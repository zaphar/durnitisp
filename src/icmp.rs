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
use std::ops::Sub;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
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
use log::{debug, error, info};
use prometheus::{CounterVec, GaugeVec};

gflags::define! {
    /// The payload to use for the ping requests.
    --pingPayload = "durnitisp"
}

gflags::define! {
    /// The timeout for ping requests.
    --pingTimeout: u64 = 2048
}

gflags::define! {
    /// The delay between ping requests.
    --pingDelay: u64 = 5
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

struct State<AddrType> {
    sequence: u16,
    destinations: HashMap<u16, (String, AddrType)>, // domain, address
    time_tracker: HashMap<u16, Instant>,
    latency_guage: GaugeVec,
    ping_counter: CounterVec,
    stop_signal: Arc<RwLock<bool>>,
}

struct PingerImpl<Sock: IcmpSocket> {
    sock: Sock,
    timeout: Duration,
}

trait PacketHandler<PacketType, AddrType>
where
    AddrType: std::fmt::Display + Copy,
    PacketType: WithEchoRequest<Packet = PacketType>,
{
    fn get_mut_state(&mut self) -> &mut State<AddrType>;
    fn handle_pkt(&mut self, pkt: PacketType) -> bool;
}

impl<'a> PacketHandler<Icmpv6Packet, Ipv6Addr> for &'a mut State<Ipv6Addr> {
    fn get_mut_state(&mut self) -> &mut State<Ipv6Addr> {
        return self;
    }

    fn handle_pkt(&mut self, pkt: Icmpv6Packet) -> bool {
        match pkt.message {
            Icmpv6Message::Unreachable {
                _unused,
                invoking_packet,
            } => {
                match Icmpv6Packet::parse(&invoking_packet) {
                    Ok(Icmpv6Packet {
                        typ: _,
                        code: _,
                        checksum: _,
                        message:
                            Icmpv6Message::EchoRequest {
                                identifier,
                                sequence: _,
                                payload: _,
                            },
                    }) => {
                        if let Some((domain_name, _addr)) = self.destinations.get(&identifier) {
                            self.ping_counter
                                    .with(&prometheus::labels! {"result" => "unreachable", "domain" => domain_name})
                                    .inc();
                            return true;
                        }
                    }
                    Err(e) => {
                        // We ignore these as well but log it.
                        error!("ICMP: Error parsing Unreachable invoking packet {:?}", e);
                    }
                    _ => {
                        // We ignore these
                    }
                };
            }
            Icmpv6Message::ParameterProblem {
                pointer: _,
                invoking_packet,
            } => {
                match Icmpv6Packet::parse(&invoking_packet) {
                    Ok(Icmpv6Packet {
                        typ: _,
                        code: _,
                        checksum: _,
                        message:
                            Icmpv6Message::EchoRequest {
                                identifier,
                                sequence: _,
                                payload: _,
                            },
                    }) => {
                        if let Some((domain_name, _addr)) = self.destinations.get(&identifier) {
                            self.ping_counter
                                    .with(&prometheus::labels! {"result" => "parameter_problem", "domain" => domain_name})
                                    .inc();
                            return true;
                        }
                    }
                    Err(e) => {
                        // We ignore these as well but log it.
                        error!("ICMP: Error parsing Unreachable invoking packet {:?}", e);
                    }
                    _ => {
                        // We ignore these
                    }
                }
            }
            Icmpv6Message::EchoReply {
                identifier,
                sequence,
                payload: _,
            } => {
                if let Some((domain_name, dest)) = self.destinations.get(&identifier) {
                    if self.sequence != sequence {
                        error!("ICMP: Discarding sequence {}", sequence);
                        return false;
                    }
                    let elapsed = if let Some(send_time) = self.time_tracker.get(&identifier) {
                        Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00
                    } else {
                        return false;
                    };
                    info!(
                        "ICMP: Reply from {}({}): time={}ms, seq={}",
                        domain_name, dest, elapsed, sequence,
                    );
                    self.ping_counter
                        .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                        .inc();
                    if elapsed as i32 != 0 {
                        self.latency_guage
                            .with(&prometheus::labels! {"domain" => domain_name.as_str()})
                            .set(elapsed);
                    }
                    return true;
                } else {
                    info!("ICMP: Discarding wrong identifier {}", identifier);
                }
            }
            _ => {
                // We ignore the rest.
            }
        }
        return false;
    }
}

impl<'a> PacketHandler<Icmpv4Packet, Ipv4Addr> for &'a mut State<Ipv4Addr> {
    fn get_mut_state(&mut self) -> &mut State<Ipv4Addr> {
        return self;
    }

    fn handle_pkt(&mut self, pkt: Icmpv4Packet) -> bool {
        match pkt.message {
            Icmpv4Message::ParameterProblem {
                pointer: _,
                padding: _,
                header: _,
            } => {
                self.ping_counter
                    .with(&prometheus::labels! {"result" => "parameter_problem", "domain" => "unknown"})
                    .inc();
            }
            Icmpv4Message::Unreachable { padding: _, header } => {
                let dest_addr = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
                info!("ICMP: Destination Unreachable response from {}", dest_addr,);
                self.ping_counter
                    .with(&prometheus::labels! {"result" => "unreachable", "domain" => "unknown"})
                    .inc();
            }
            Icmpv4Message::TimeExceeded { padding: _, header } => {
                let dest_addr = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
                info!("ICMP: Timeout for {}", dest_addr);
                self.ping_counter
                    .with(&prometheus::labels! {"result" => "timeout", "domain" => "unknown"})
                    .inc();
            }
            Icmpv4Message::EchoReply {
                identifier,
                sequence,
                payload: _,
            } => {
                if let Some((domain_name, dest)) = self.destinations.get(&identifier) {
                    let elapsed = if let Some(send_time) = self.time_tracker.get(&identifier) {
                        Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00
                    } else {
                        return false;
                    };
                    if self.sequence != sequence {
                        error!(
                            "ICMP: Discarding sequence {}, expected sequence {}",
                            sequence, self.sequence
                        );
                        return false;
                    }
                    info!(
                        "ICMP: Reply from {}({}): time={}ms, seq={}",
                        domain_name, dest, elapsed, sequence,
                    );
                    self.ping_counter
                        .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                        .inc();
                    self.latency_guage
                        .with(&prometheus::labels! {"domain" => domain_name.as_str()})
                        .set(elapsed);
                    return true;
                } else {
                    info!("ICMP: Discarding wrong identifier {}", identifier);
                }
            }
            p => {
                // We ignore the rest.
                info!("ICMP Unhandled packet {:?}", p);
            }
        }
        return false;
    }
}

trait Pinger<AddrType, PacketType>
where
    AddrType: std::fmt::Display + Copy,
    PacketType: WithEchoRequest<Packet = PacketType>,
{
    fn send_all(&mut self, state: &mut State<AddrType>) -> std::io::Result<()>;
    fn send_to_destination(
        &mut self,
        dest: AddrType,
        identifier: u16,
        sequence: u16,
    ) -> std::io::Result<Instant>;

    fn recv_pkt(&mut self) -> std::io::Result<PacketType>;
    fn recv_all<H: PacketHandler<PacketType, AddrType>>(&mut self, handler: H);
}

impl<Sock> Pinger<Sock::AddrType, Sock::PacketType> for PingerImpl<Sock>
where
    Sock: IcmpSocket,
    Sock::AddrType: std::fmt::Display + Copy,
    Sock::PacketType: WithEchoRequest<Packet = Sock::PacketType>,
{
    fn send_all(&mut self, state: &mut State<Sock::AddrType>) -> std::io::Result<()> {
        self.sock.set_timeout(self.timeout)?;
        let destinations = state.destinations.clone();
        for (identifier, (domain_name, dest)) in destinations.into_iter() {
            debug!("ICMP: sending echo request to {}({})", domain_name, dest);
            match self.send_to_destination(dest, identifier, state.sequence) {
                Err(e) => {
                    state
                        .ping_counter
                        .with(&prometheus::labels! {"result" => "err", "type" => "send"})
                        .inc();
                    error!(
                            "ICMP: error sending to domain: {} and address: {} failed: {:?}, Trying again later",
                            domain_name, &dest, e
                        );
                }
                Ok(send_time) => {
                    state.time_tracker.insert(identifier, send_time);
                }
            }
            {
                // Scope the lock really tightly
                if *state.stop_signal.read().unwrap() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn send_to_destination(
        &mut self,
        dest: Sock::AddrType,
        identifier: u16,
        sequence: u16,
    ) -> std::io::Result<Instant> {
        let packet = Sock::PacketType::with_echo_request(
            identifier,
            sequence,
            PINGPAYLOAD.flag.as_bytes().to_owned(),
        )
        .unwrap();
        let send_time = Instant::now();
        self.sock.send_to(dest, packet)?;
        Ok(send_time)
    }

    fn recv_pkt(&mut self) -> std::io::Result<Sock::PacketType> {
        let (response, _addr) = self.sock.rcv_from()?;
        Ok(response)
    }

    fn recv_all<H: PacketHandler<Sock::PacketType, Sock::AddrType>>(&mut self, mut handler: H) {
        let expected_len = handler.get_mut_state().time_tracker.len();
        for _ in 0..expected_len {
            loop {
                // Receive loop
                match self.recv_pkt() {
                    Ok(pkt) => {
                        if handler.handle_pkt(pkt) {
                            // break out of the recv loop
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error receiving packet: {:?}", e);
                        handler
                            .get_mut_state()
                            .ping_counter
                            .with(&prometheus::labels! {"result" => "err", "domain" => "unknown"})
                            .inc();
                    }
                }
                {
                    // Scope the lock really tightly.
                    if *handler.get_mut_state().stop_signal.read().unwrap() {
                        return;
                    }
                }
            }
        }
        let mut state = handler.get_mut_state();
        state.sequence = state.sequence.wrapping_add(1);
    }
}

pub fn start_echo_loop(
    domain_names: &Vec<&str>,
    stop_signal: Arc<RwLock<bool>>,
    ping_latency_guage: GaugeVec,
    ping_counter: CounterVec,
) {
    let resolved: Vec<(String, IpAddr)> = domain_names
        .iter()
        .map(|domain_name| {
            let resolved = resolve_host_address(domain_name);
            let dest = resolved
                .parse::<IpAddr>()
                .expect(&format!("Invalid IP Address {}", resolved));
            (domain_name.to_string(), dest)
        })
        .collect();
    let mut v4_targets: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut v6_targets: Vec<(String, Ipv6Addr)> = Vec::new();
    for (name, addr) in resolved {
        match addr {
            IpAddr::V6(addr) => {
                v6_targets.push((name, addr));
            }
            IpAddr::V4(addr) => {
                v4_targets.push((name, addr));
            }
        }
    }

    let mut v4_destinations = HashMap::new();
    let mut v4_id_counter = 42;
    for target in v4_targets {
        info!("ICMP: Attempting ping to {}({})", target.0, target.1);
        v4_destinations.insert(v4_id_counter, target.clone());
        v4_id_counter += 1;
    }
    let mut v4_state = State {
        sequence: 0,
        destinations: v4_destinations,
        time_tracker: HashMap::new(),
        latency_guage: ping_latency_guage.clone(),
        ping_counter: ping_counter.clone(),
        stop_signal: stop_signal.clone(),
    };
    let mut v6_destinations = HashMap::new();
    let mut v6_id_counter = 42;
    for target in v6_targets {
        info!("ICMP: Attempting ping to {}({})", target.0, target.1);
        v6_destinations.insert(v6_id_counter, target.clone());
        v6_id_counter += 1;
    }
    let mut v4_pinger = PingerImpl {
        sock: IcmpSocket4::new().expect("Failed to open Icmpv4 Socket"),
        timeout: Duration::from_secs(1),
    };
    let mut v6_state = State {
        sequence: 0,
        destinations: v6_destinations,
        time_tracker: HashMap::new(),
        latency_guage: ping_latency_guage,
        ping_counter,
        stop_signal: stop_signal.clone(),
    };
    let mut v6_pinger = PingerImpl {
        sock: IcmpSocket6::new().expect("Failed to open Icmpv6 Socket"),
        timeout: Duration::from_secs(1),
    };
    loop {
        v4_pinger
            .send_all(&mut v4_state)
            .expect("Error sending packets on socket");
        v6_pinger
            .send_all(&mut v6_state)
            .expect("Error sending packets on socket");
        v4_pinger.recv_all(&mut v4_state);
        v6_pinger.recv_all(&mut v6_state);
        {
            // Scope the lock really tightly
            if *stop_signal.read().unwrap() {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(PINGDELAY.flag))
    }
}
