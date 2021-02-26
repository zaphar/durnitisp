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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Sub;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::util;

use gflags;
use icmp_socket::{
    packet::{Icmpv4Message, Icmpv6Message, WithEchoRequest},
    IcmpSocket, IcmpSocket4, IcmpSocket6, Icmpv4Packet, Icmpv6Packet,
};
use log::{debug, error, info};
use nursery::{thread, Nursery};
use prometheus::{CounterVec, GaugeVec};

gflags::define! {
    /// The payload to use for the ping requests.
    --pingPayload = "durnitisp"
}

gflags::define! {
    /// The timeout for ping requests in seconds.
    --pingTimeout: u64 = 3
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
    destinations: HashMap<u16, (String, AddrType)>, // domain, address
    // TODO(jwall): This should be a time tracker by both identifier and sequence
    time_tracker: HashMap<u16, (Option<Instant>, u16)>,
    latency_guage: GaugeVec,
    ping_counter: CounterVec,
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
        debug!("ICMP: handling packet {:?}", pkt);
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
                    if let Some((Some(send_time), expected_sequence)) =
                        self.time_tracker.get(&identifier)
                    {
                        let elapsed =
                            Instant::now().sub(send_time.clone()).as_millis() as f64 / 1000.00;
                        // We make a copy here to avoid the borrow above sticking around for too long.
                        let expected_sequence = *expected_sequence;
                        if sequence != expected_sequence {
                            error!(
                                "ICMP: Discarding unexpected sequence sequence={} expected={}",
                                sequence, expected_sequence
                            );
                            self.time_tracker
                                .insert(identifier, (None, expected_sequence.wrapping_add(1)));
                            return false;
                        }
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
                        self.time_tracker
                            .insert(identifier, (None, expected_sequence.wrapping_add(1)));
                        return true;
                    } else {
                        return false;
                    };
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
        debug!("ICMP: handling packet {:?}", pkt);
        match pkt.message {
            Icmpv4Message::EchoReply {
                identifier,
                sequence,
                payload: _,
            } => {
                if let Some((domain_name, dest)) = self.destinations.get(&identifier) {
                    if let Some((Some(send_time), expected_sequence)) =
                        self.time_tracker.get(&identifier)
                    {
                        let elapsed =
                            Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00;
                        let expected_sequence = *expected_sequence;
                        if expected_sequence != sequence {
                            error!(
                                "ICMP: Discarding unexpected sequence sequence={} expected={}",
                                sequence, expected_sequence
                            );
                            self.time_tracker
                                .insert(identifier, (None, expected_sequence.wrapping_add(1)));
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
                        self.time_tracker
                            .insert(identifier, (None, expected_sequence.wrapping_add(1)));
                        return true;
                    } else {
                        return false;
                    };
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
        let destinations = state.destinations.clone();
        info!("ICMP: Attempting to send packets for all domains");
        for (identifier, (domain_name, dest)) in destinations.into_iter() {
            let previous_tracker = state.time_tracker.get(&identifier);
            let sequence = if previous_tracker.is_some() {
                let (send_status, sequence) = previous_tracker.unwrap();
                if let Some(send_time) = send_status {
                    // We haven't recieved the previous packet response yet so don't send unless we've waited
                    // for timeout length of time.
                    let elapsed = Instant::now() - *send_time;
                    if elapsed > Duration::from_secs(PINGTIMEOUT.flag) {
                        info!(
                            "ICMP: Dropped packet detected for domain_name={} send_time={:?} elapsed={:?} sequence={}",
                            domain_name, send_time, elapsed, sequence
                        );
                        state.ping_counter
                            .with(&prometheus::labels! {"result" => "dropped", "domain" => &domain_name})
                            .inc();
                        sequence.wrapping_add(1)
                    } else {
                        debug!(
                            "ICMP: Waiting for timeout before sending next packet domain_name={} sequence={}",
                            domain_name, sequence
                        );
                        continue;
                    }
                } else {
                    *sequence
                }
            } else {
                debug!(
                    "ICMP: Initializing sequence for first send domain_name={} sequence=0",
                    domain_name
                );
                0
            };
            info!(
                "ICMP: sending echo request to {}({}) sequence={}",
                domain_name, dest, sequence
            );
            match self.send_to_destination(dest, identifier, sequence) {
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
                    state
                        .time_tracker
                        .insert(identifier, (Some(send_time), sequence));
                }
            }
        }
        debug!("ICMP: finished sending for domains");
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
        if handler.get_mut_state().destinations.is_empty() {
            debug!("Nothing to send to so skipping for this socket");
            return;
        };
        if handler
            .get_mut_state()
            .time_tracker
            .values()
            .find(|item| item.0.is_some())
            .is_none()
        {
            // nothing has been sent yet so no need to try to recv packets
            debug!("Nothing to recieve for so skipping for this socket");
            return;
        }
        self.sock
            .set_timeout(self.timeout)
            .expect("Unable to set timout for recieves on socket.");
        let loop_start_time = Instant::now();
        loop {
            // Receive loop
            debug!("ICMP: Attempting to recieve packets on socket");
            match self.recv_pkt() {
                Ok(pkt) => {
                    if handler.handle_pkt(pkt) {
                        // break out of the recv loop
                        debug!("ICMP: Recieved Packet");
                        return;
                    }
                }
                Err(e) => {
                    error!("ICMP: Error receiving packet: {:?}", e);
                    handler
                        .get_mut_state()
                        .ping_counter
                        .with(&prometheus::labels! {"result" => "err", "domain" => "unknown"})
                        .inc();
                    return;
                }
            }
            if (Instant::now() - loop_start_time) > Duration::from_secs(PINGTIMEOUT.flag) {
                info!("ICMP: Timing out on recieve loop");
                return;
            }
        }
    }
}

struct Multi {
    v4_state: State<Ipv4Addr>,
    v6_state: State<Ipv6Addr>,
    v4_pinger: PingerImpl<IcmpSocket4>,
    v6_pinger: PingerImpl<IcmpSocket6>,
}

impl Multi {
    fn send_all(&mut self) {
        self.v4_pinger
            .send_all(&mut self.v4_state)
            .expect("Error sending packets on socket");
        self.v6_pinger
            .send_all(&mut self.v6_state)
            .expect("Error sending packets on socket");
    }

    fn recv_all(&mut self) {
        self.v4_pinger.recv_all(&mut self.v4_state);
        self.v6_pinger.recv_all(&mut self.v6_state);
    }
}

pub fn schedule_echo_server(
    domain_names: &Vec<&str>,
    ping_latency_guage: GaugeVec,
    ping_counter: CounterVec,
    parent: &mut Nursery,
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
    let v4_state = State {
        destinations: v4_destinations,
        time_tracker: HashMap::new(),
        latency_guage: ping_latency_guage.clone(),
        ping_counter: ping_counter.clone(),
    };
    let mut v6_destinations = HashMap::new();
    let mut v6_id_counter = 42;
    for target in v6_targets {
        info!("ICMP: Attempting ping to {}({})", target.0, target.1);
        v6_destinations.insert(v6_id_counter, target.clone());
        v6_id_counter += 1;
    }
    let v4_pinger = PingerImpl {
        sock: IcmpSocket4::new().expect("Failed to open Icmpv4 Socket"),
        timeout: Duration::from_millis(10),
    };
    let v6_state = State {
        destinations: v6_destinations,
        time_tracker: HashMap::new(),
        latency_guage: ping_latency_guage,
        ping_counter,
    };
    let v6_pinger = PingerImpl {
        sock: IcmpSocket6::new().expect("Failed to open Icmpv6 Socket"),
        timeout: Duration::from_millis(10),
    };
    let multi = std::sync::Arc::new(std::sync::Mutex::new(Multi {
        v4_pinger,
        v6_pinger,
        v4_state,
        v6_state,
    }));
    let send_multi = multi.clone();
    let send_thread = thread::Pending::new(move || {
        info!("ICMP: Starrting send thread");
        loop {
            {
                send_multi.lock().unwrap().send_all();
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    let recv_thread = thread::Pending::new(move || {
        info!("ICMP: Starrting recv thread");
        loop {
            {
                multi.lock().unwrap().recv_all();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    parent.schedule(Box::new(send_thread));
    parent.schedule(Box::new(recv_thread));
}
