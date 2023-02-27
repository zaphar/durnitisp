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
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use crate::util;

use gflags;
use icmp_socket::{
    packet::{Icmpv4Message, Icmpv6Message, WithEchoRequest},
    IcmpSocket, IcmpSocket4, IcmpSocket6, Icmpv4Packet, Icmpv6Packet,
};
use nursery::{thread, Nursery};
use prometheus::{CounterVec, GaugeVec};
use tracing::{debug, error, info, instrument, warn};

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
    time_tracker: BTreeMap<u16, BTreeMap<u16, Instant>>,
    destination_counter: BTreeMap<u16, u16>,
    latency_guage: GaugeVec,
    ping_counter: CounterVec,
}

impl<AddrType: std::fmt::Display> State<AddrType> {
    fn handle_echo_reply(&mut self, identifier: u16, sequence: u16) -> bool {
        if let Some((domain_name, dest)) = self.destinations.get(&identifier) {
            let time_tracker = self.time_tracker.get_mut(&identifier);
            if let Some(Some(send_time)) = time_tracker.as_ref().map(|m| m.get(&sequence)) {
                let elapsed = Instant::now().sub(send_time.clone()).as_micros() as f64 / 1000.00;
                // We make a copy here to avoid the borrow above sticking around for too long.
                info!(
                    domain=domain_name,
                    %dest,
                    time = elapsed,
                    seq = sequence,
                    "Reply",
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
                    .get_mut(&identifier)
                    .and_then(|m| m.remove(&sequence));
                return true;
            } else {
                error!(sequence, "Discarding unexpected sequence",);
            };
            // Check all the other sequences to see if they have expired timeouts yet.
            // Record timeout for the expired sequences.
            // Remove the timeouts for the expired sequences.
            let expired_sequences = self.time_tracker.get(&identifier).map(|m| {
                let mut for_delete = Vec::with_capacity(m.len());
                let m = m.clone();
                {
                    for (k, send_time) in m.iter() {
                        if Instant::now().sub(*send_time) >= Duration::from_secs(PINGTIMEOUT.flag) {
                            info!(
                                domain=domain_name,
                                %dest,
                                seq = sequence,
                                "Dropped"
                            );
                            self.ping_counter
                                .with(&prometheus::labels! {"result" => "timeout", "domain" => domain_name})
                                .inc();
                            for_delete.push(*k);
                        }
                    }
                }
                for_delete
            });
            for k in expired_sequences.unwrap_or_default() {
                self.time_tracker
                    .get_mut(&identifier)
                    .and_then(|m| m.remove(&k));
            }
        } else {
            warn!(identifier, "Discarding wrong identifier");
        }
        return false;
    }
}

struct PingerImpl<Sock: IcmpSocket> {
    sock: Sock,
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

    #[instrument(level = "debug", skip(self))]
    fn handle_pkt(&mut self, pkt: Icmpv6Packet) -> bool {
        debug!("handling packet");
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
                        error!(err = ?e, "Error parsing Unreachable");
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
                        error!(err = ?e, "Error parsing ParameterProblem");
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
                return self.handle_echo_reply(identifier, sequence);
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

    #[instrument(level = "debug", skip(self))]
    fn handle_pkt(&mut self, pkt: Icmpv4Packet) -> bool {
        debug!("handling packet");
        match pkt.message {
            Icmpv4Message::EchoReply {
                identifier,
                sequence,
                payload: _,
            } => {
                return self.handle_echo_reply(identifier, sequence);
            }
            _ => {
                // We ignore the rest.
                info!("Unhandled packet");
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

    fn send_pkt(
        &mut self,
        state: &mut State<AddrType>,
        identifier: u16,
        dest: AddrType,
        domain_name: &String,
    ) -> std::io::Result<()> {
        let sequence = *state.destination_counter.entry(identifier).or_insert(0);
        debug!(
            domain=domain_name, %dest, sequence,
            "Sending echo request",
        );
        match self.send_to_destination(dest, identifier, sequence) {
            Err(e) => {
                state
                    .ping_counter
                    .with(&prometheus::labels! {"result" => "err", "type" => "send"})
                    .inc();
                error!(
                    domain=domain_name, %dest, err=?e,
                    "Error sending. Trying again later",
                );
            }
            Ok(send_time) => {
                state
                    .time_tracker
                    .entry(identifier)
                    .or_insert_with(|| BTreeMap::new())
                    .insert(sequence, send_time);
            }
        }
        state
            .destination_counter
            .get_mut(&identifier)
            .map(|v| *v = v.wrapping_add(1));
        Ok(())
    }
}

impl<Sock> Pinger<Sock::AddrType, Sock::PacketType> for PingerImpl<Sock>
where
    Sock: IcmpSocket,
    Sock::AddrType: std::fmt::Display + Copy,
    Sock::PacketType: WithEchoRequest<Packet = Sock::PacketType>,
{
    #[instrument(skip_all)]
    fn send_all(&mut self, state: &mut State<Sock::AddrType>) -> std::io::Result<()> {
        let destinations = state.destinations.clone();
        debug!("Attempting to send packets for all domains");
        for (identifier, (domain_name, dest)) in destinations.into_iter() {
            self.send_pkt(state, identifier, dest, &domain_name)?;
        }
        debug!("Finished sending for domains");
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

    #[instrument(skip(self, handler))]
    fn recv_all<H: PacketHandler<Sock::PacketType, Sock::AddrType>>(&mut self, mut handler: H) {
        if handler.get_mut_state().destinations.is_empty() {
            debug!("Nothing to send to so skipping for this socket");
            return;
        };
        if handler
            .get_mut_state()
            .time_tracker
            .values()
            .find(|item| !item.is_empty())
            .is_none()
        {
            // nothing has been sent yet so no need to try to recv packets
            debug!("Nothing to recieve so skipping for this socket");
            return;
        }
        self.sock.set_timeout(None);
        let loop_start_time = Instant::now();
        loop {
            // Receive loop
            debug!("Attempting to recieve packets on socket");
            match self.recv_pkt() {
                Ok(pkt) => {
                    if handler.handle_pkt(pkt) {
                        // break out of the recv loop
                        debug!("Recieved Packet");
                        return;
                    }
                }
                Err(e) => {
                    error!(err = ?e, "Error receiving packet");
                    handler
                        .get_mut_state()
                        .ping_counter
                        .with(&prometheus::labels! {"result" => "err", "domain" => "unknown"})
                        .inc();
                    return;
                }
            }
            if (Instant::now() - loop_start_time) > Duration::from_secs(PINGTIMEOUT.flag) {
                info!("Timing out on recieve loop");
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

#[instrument(name = "ICMP", skip_all)]
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
        info!(
            domain_name = target.0,
            address = %target.1,
            "Attempting ping"
        );
        v4_destinations.insert(v4_id_counter, target.clone());
        v4_id_counter += 1;
    }
    let v4_state = State {
        destinations: v4_destinations,
        time_tracker: BTreeMap::new(),
        destination_counter: BTreeMap::new(),
        latency_guage: ping_latency_guage.clone(),
        ping_counter: ping_counter.clone(),
    };
    let mut v6_destinations = HashMap::new();
    let mut v6_id_counter = 42;
    for target in v6_targets {
        info!(
            domain_name = target.0,
            address = %target.1,
            "Attempting ping"
        );
        v6_destinations.insert(v6_id_counter, target.clone());
        v6_id_counter += 1;
    }
    let v4_pinger = PingerImpl {
        sock: IcmpSocket4::new().expect("Failed to open Icmpv4 Socket"),
    };
    let v6_state = State {
        destinations: v6_destinations,
        time_tracker: BTreeMap::new(),
        destination_counter: BTreeMap::new(),
        latency_guage: ping_latency_guage,
        ping_counter,
    };
    let v6_pinger = PingerImpl {
        sock: IcmpSocket6::new().expect("Failed to open Icmpv6 Socket"),
    };
    let multi = std::sync::Arc::new(std::sync::Mutex::new(Multi {
        v4_pinger,
        v6_pinger,
        v4_state,
        v6_state,
    }));
    let send_multi = multi.clone();
    let send_thread = thread::Pending::new(move || {
        info!("Starting send thread");
        loop {
            {
                send_multi.lock().unwrap().send_all();
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    let recv_thread = thread::Pending::new(move || {
        info!("Starting recv thread");
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
