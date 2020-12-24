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
use std::convert::Into;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use gflags;
use log::{debug, error, info};
use packet::icmp::echo::{Builder, Packet};
use packet::Builder as PBuilder;
use socket2::Domain;
use socket2::Protocol;
use socket2::SockAddr;
use socket2::Socket;

gflags::define! {
    // The size in bytes of the ping requests.
    --pingPayload = "durnitisp ping test"
}

fn make_echo_packet(ident: u16) -> Packet<Vec<u8>> {
    let buffer = Builder::default()
        .request()
        .unwrap()
        .identifier(ident)
        .unwrap()
        .sequence(0)
        .unwrap()
        .payload(PINGPAYLOAD.flag.as_bytes())
        .unwrap()
        .build()
        .unwrap();
    Packet::unchecked(buffer)
}

pub fn start_echo_loop(
    domain_name: &str,
    stop_signal: Arc<RwLock<bool>>,
    addr: IpAddr,
    ident: u16,
) {
    info!("Starting ping of {}", domain_name);
    // First we construct our icmp transport
    // TODO(jwall): Timeouts.
    // TODO(jwall): Handle out of order packets.
    let (domain, protocol) = match addr {
        IpAddr::V4(_) => (Domain::ipv4(), Protocol::icmpv4()),
        IpAddr::V6(_) => (Domain::ipv6(), Protocol::icmpv6()),
    };
    // Construct a socket to send the ICMP request on.
    // socket type: Ip, Datagram, ICMP
    let addr: SocketAddr = (addr, 0).into();
    let addr: SockAddr = addr.into();
    let socket = match Socket::new(domain, socket2::Type::raw(), Some(protocol)) {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to create socket for icmp request:\n {}", e);
            return;
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_millis(2048)))
        .unwrap();
    // then we start our loop
    let mut n = 0;
    let mut pkt = make_echo_packet(ident);
    loop {
        {
            // Limit the scope of this lock
            if *stop_signal.read().unwrap() {
                info!("Stopping ping thread for {}", domain_name);
                return;
            }
        }
        pkt.set_sequence(n).unwrap();
        // TODO(jwall): Count the errors?
        // construct echo packet
        let time_of_send = Instant::now();
        // send echo packet
        let pkt_buf: &[u8] = pkt.as_ref();
        debug!("Sending echo request for {}", domain_name);
        let sent = socket.send_to(pkt_buf, &addr).unwrap();
        if pkt_buf.len() != sent {
            error!("Failed to send a complete icmp packet!");
            continue;
        }
        //    // Wait for echo response
        debug!("Waiting for echo reply from {}", domain_name);
        let mut buf = vec![0; sent];
        let _rcv_size = match socket.recv(&mut buf) {
            Ok(sz) => sz,
            Err(e) => {
                if let std::io::ErrorKind::TimedOut = e.kind() {
                    error!("icmp echo request timed out to {}", domain_name);
                    continue;
                }
                error!("Error recieving on icmp socket! {:?}", e);
                return;
            }
        };
        let echo = Packet::new(&buf).unwrap();
        if echo.sequence() == n {
            let round_trip_time = Instant::now().checked_duration_since(time_of_send).unwrap();
            // record this time
            info!("Sequence # {} {}ms", n, round_trip_time.as_millis());
        } else {
            error!("Got the wrong sequence number {}", echo.sequence());
        }
        // Increment our sequence number
        n += 1;
    }
}
