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
use prometheus::{CounterVec, IntGaugeVec};
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
    PH: Fn(Sock::PacketType, socket2::SockAddr, Instant) -> (),
    EH: Fn(std::io::Error) -> (),
    Sock: IcmpSocket,
    Sock::AddrType: std::fmt::Display + Copy,
    Sock::PacketType: WithEchoRequest<Packet = Sock::PacketType>,
{
    loop {
        {
            // Limit the scope of this lock
            if *stop_signal.read().unwrap() {
                info!("Stopping ping thread for {}", dest);
                return;
            }
        }
        let sequence = 0;
        let packet = Sock::PacketType::with_echo_request(
            42,
            sequence,
            PINGPAYLOAD.flag.as_bytes().to_owned(),
        )
        .unwrap();
        let send_time = Instant::now();
        if let Err(e) = socket.send_to(dest, packet) {
            err_handler(e);
        }
        match socket.rcv_from() {
            Err(e) => {
                err_handler(e);
            }
            Ok((resp, sock_addr)) => {
                packet_handler(resp, sock_addr, send_time);
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn start_echo_loop(
    domain_name: &str,
    stop_signal: Arc<RwLock<bool>>,
    ping_latency_guage: IntGaugeVec,
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

    let err_handler = |e: std::io::Error| {
        ping_counter
            .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
            .inc();
        error!(
            "Ping send to domain: {} and address: {} failed: {:?}, Trying again later",
            domain_name, &dest, e
        );
    };
    match dest {
        IpAddr::V4(dest) => {
            let mut socket = IcmpSocket4::try_from(Ipv4Addr::new(0, 0, 0, 0)).unwrap();
            socket.set_max_hops(MAXHOPS.flag as u32);
            let packet_handler = |p: Icmpv4Packet, s: SockAddr, send_time: Instant| {
                // We only want to handle replies for the address we are pinging.
                if let Some(addr) = s.as_inet() {
                    if &dest != addr.ip() {
                        return;
                    }
                } else {
                    return;
                };
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
                        // // If we got unreachable we need to set up a new sender.
                        // error!("{:?}", r);
                        // info!("Restarting our sender");
                        ping_counter
                                    .with(&prometheus::labels! {"result" => "unreachable", "domain" => domain_name})
                                    .inc();
                        // let resolved = resolve_host_address(domain_name);
                        // let mut new_sender = Ekko::with_target(&resolved).unwrap();
                        //            std::mem::swap(&mut sender, &mut new_sender);
                    }
                    Icmpv4Message::TimeExceeded {
                        padding: _,
                        header: _,
                    } => {
                        ping_counter
                                .with(&prometheus::labels! {"result" => "timeout", "domain" => domain_name})
                                .inc();
                    }
                    Icmpv4Message::EchoReply {
                        identifier: _,
                        sequence,
                        payload: _,
                    } => {
                        let elapsed = Instant::now().sub(send_time.clone()).as_millis();
                        info!(
                            "ICMP: Reply from {}: time={}ms, seq={}",
                            dest, elapsed, sequence,
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                            .inc();
                        if elapsed != 0 {
                            ping_latency_guage
                                .with(&prometheus::labels! {"domain" => domain_name})
                                .set(elapsed as i64);
                        }
                    }
                    _ => {
                        // We ignore the rest.
                    }
                }
            };
            loop_impl(socket, dest, packet_handler, err_handler, stop_signal);
        }
        IpAddr::V6(dest) => {
            let mut socket = IcmpSocket6::try_from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)).unwrap();
            socket.set_max_hops(MAXHOPS.flag as u32);
            let packet_handler = |p: Icmpv6Packet, s: SockAddr, send_time: Instant| {
                // We only want to handle replies for the addres we are pinging.
                if let Some(addr) = s.as_inet6() {
                    if &dest != addr.ip() {
                        return;
                    }
                } else {
                    return;
                };
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
                        identifier: _,
                        sequence,
                        payload: _,
                    } => {
                        let elapsed = Instant::now().sub(send_time.clone()).as_millis();
                        info!(
                            "ICMP: Reply from {}: time={}ms, seq={}",
                            dest, elapsed, sequence,
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                            .inc();
                        if elapsed != 0 {
                            ping_latency_guage
                                .with(&prometheus::labels! {"domain" => domain_name})
                                .set(elapsed as i64);
                        }
                    }
                    _ => {
                        // We ignore the rest.
                    }
                }
            };
            loop_impl(socket, dest, packet_handler, err_handler, stop_signal);
        }
    };
}
