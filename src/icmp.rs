// Copyright 2020 Jeremy Wall
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::time::{Duration, Instant};
use std::{convert::TryFrom, ops::Sub};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
};

use crate::util;

use gflags;
use icmp_socket::{
    packet::{Icmpv4Message, Icmpv6Message, WithEchoRequest},
    IcmpSocket, IcmpSocket4, IcmpSocket6, Icmpv4Packet, Icmpv6Packet,
};
use log::{error, info};
use prometheus::{CounterVec, GaugeVec};
use socket2::{self, SockAddr};

gflags::define! {
    /// The payload to use for the ping requests.
    --pingPayload = "durnitisp"
}

gflags::define! {
    /// The timeout for ping requests.
    --pingTimeout: u64 = 2048
}

gflags::define! {
    /// The size in bytes of the ping requests.
    --maxHops: u8 = 50
}

fn resolve_host_address(host: &str) -> String {
    format!(
        "{}",
        util::resolve_hosts(&vec![host])
            .unwrap()
            .first()
            .unwrap()
            .unwrap()
    )
}

fn loop_impl<Sock, PH, EH>(
    mut socket: Sock,
    dest: Sock::AddrType,
    packet_handler: PH,
    err_handler: EH,
    stop_signal: Arc<RwLock<bool>>,
) where
    PH: Fn(Sock::PacketType, socket2::SockAddr, Instant, u16) -> Option<()>,
    EH: Fn(std::io::Error, bool) -> (),
    Sock: IcmpSocket,
    Sock::AddrType: std::fmt::Display + Copy,
    Sock::PacketType: WithEchoRequest<Packet = Sock::PacketType>,
{
    let mut sequence: u16 = 0;
    loop {
        {
            // Limit the scope of this lock
            if *stop_signal.read().unwrap() {
                info!("Stopping ping thread for {}", dest);
                return;
            }
        }
        let packet = Sock::PacketType::with_echo_request(
            42,
            sequence,
            PINGPAYLOAD.flag.as_bytes().to_owned(),
        )
        .unwrap();
        let send_time = Instant::now();
        if let Err(e) = socket.send_to(dest, packet) {
            err_handler(e, true);
        } else {
            loop {
                // Keep going until we get the packet we are looking for.
                match socket.rcv_with_timeout(Duration::from_secs(1)) {
                    Err(e) => {
                        err_handler(e, false);
                    }
                    Ok((resp, sock_addr)) => {
                        if packet_handler(resp, sock_addr, send_time, sequence).is_some() {
                            sequence = sequence.wrapping_add(1);
                            break;
                        }
                    }
                }
                // Give up after 3 seconds and send another packet.
                if Instant::now() - send_time > Duration::from_secs(3) {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn start_echo_loop(
    domain_name: &str,
    stop_signal: Arc<RwLock<bool>>,
    ping_latency_guage: GaugeVec,
    ping_counter: CounterVec,
) {
    let resolved = resolve_host_address(domain_name);
    info!(
        "Attempting to ping domain {} at address: {}",
        domain_name, resolved
    );
    let dest = resolved
        .parse::<IpAddr>()
        .expect(&format!("Invalid IP Address {}", resolved));

    let err_handler = |e: std::io::Error, send: bool| {
        if send {
            error!(
                "ICMP: error sending to domain: {} and address: {} failed: {:?}, Trying again later",
                domain_name, &dest, e
            );
        } else {
            error!(
                "ICMP: error receiving for domain: {} and address: {} failed: {:?}, Trying again later",
                domain_name, &dest, e
            );
        }
    };
    match dest {
        IpAddr::V4(dest) => {
            let mut socket = IcmpSocket4::try_from(Ipv4Addr::new(0, 0, 0, 0)).unwrap();
            socket.set_max_hops(MAXHOPS.flag as u32);
            let packet_handler = |p: Icmpv4Packet,
                                  _s: SockAddr,
                                  send_time: Instant,
                                  seq: u16|
             -> Option<()> {
                // We only want to handle replies for the address we are pinging.
                match p.message {
                    Icmpv4Message::ParameterProblem {
                        pointer: _,
                        padding: _,
                        header: _,
                    } => {
                        ping_counter
                            .with(&prometheus::labels! {"result" => "parameter_problem", "domain" => domain_name})
                            .inc();
                    }
                    Icmpv4Message::Unreachable {
                        padding: _,
                        header: _,
                    } => {
                        info!(
                            "ICMP: Destination Unreachable {} from {}",
                            dest,
                            _s.as_inet().unwrap().ip()
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "unreachable", "domain" => domain_name})
                            .inc();
                    }
                    Icmpv4Message::TimeExceeded {
                        padding: _,
                        header: _,
                    } => {
                        info!("ICMP: Timeout for {}", dest);
                        ping_counter
                            .with(&prometheus::labels! {"result" => "timeout", "domain" => domain_name})
                            .inc();
                    }
                    Icmpv4Message::EchoReply {
                        identifier,
                        sequence,
                        payload: _,
                    } => {
                        if identifier != 42 {
                            info!("ICMP: Discarding wrong identifier {}", identifier);
                            return None;
                        }
                        if sequence != seq {
                            info!("ICMP: Discarding sequence {}", sequence);
                            return None;
                        }
                        let elapsed =
                            Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00;
                        info!(
                            "ICMP: Reply from {}: time={}ms, seq={}",
                            dest, elapsed, sequence,
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                            .inc();
                        if elapsed as i32 != 0 {
                            ping_latency_guage
                                .with(&prometheus::labels! {"domain" => domain_name})
                                .set(elapsed);
                        }
                    }
                    p => {
                        // We ignore the rest.
                        info!("ICMP Unhandled packet {:?}", p);
                    }
                }
                Some(())
            };
            loop_impl(socket, dest, packet_handler, err_handler, stop_signal);
        }
        IpAddr::V6(dest) => {
            let mut socket = IcmpSocket6::try_from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)).unwrap();
            socket.set_max_hops(MAXHOPS.flag as u32);
            let packet_handler = |p: Icmpv6Packet,
                                  _s: SockAddr,
                                  send_time: Instant,
                                  seq: u16|
             -> Option<()> {
                match p.message {
                    Icmpv6Message::Unreachable {
                        _unused,
                        invoking_packet: _,
                    } => {
                        ping_counter
                        .with(&prometheus::labels! {"result" => "unreachable", "domain" => domain_name})
                        .inc();
                    }
                    Icmpv6Message::ParameterProblem {
                        pointer: _,
                        invoking_packet: _,
                    } => {
                        ping_counter
                        .with(&prometheus::labels! {"result" => "parameter_problem", "domain" => domain_name})
                        .inc();
                    }
                    Icmpv6Message::EchoReply {
                        identifier,
                        sequence,
                        payload: _,
                    } => {
                        if identifier != 42 {
                            info!("ICMP: Discarding wrong identifier {}", identifier);
                            return None;
                        }
                        if sequence != seq {
                            info!("ICMP: Discarding sequence {}", sequence);
                            return None;
                        }
                        let elapsed =
                            Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00;
                        info!(
                            "ICMP: Reply from {}: time={}ms, seq={}",
                            dest, elapsed, sequence,
                        );
                        info!(
                            "ICMP: Reply from {}: time={}ms, seq={}",
                            dest, elapsed, sequence,
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                            .inc();
                        if elapsed as i32 != 0 {
                            ping_latency_guage
                                .with(&prometheus::labels! {"domain" => domain_name})
                                .set(elapsed);
                        }
                    }
                    _ => {
                        // We ignore the rest.
                    }
                }
                Some(())
            };
            loop_impl(socket, dest, packet_handler, err_handler, stop_signal);
        }
    };
}
