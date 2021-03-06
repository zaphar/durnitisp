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

use gflags;
use log::{debug, error, info};
use prometheus::{CounterVec, IntGaugeVec};
use std::convert::From;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::SystemTime;

gflags::define! {
    /// Read timeout for the stun server udp receive
    --stunRecvTimeoutSecs: u64 = 5
}

gflags::define! {
    /// Delay between lookup attempts in seconds
    --delaySecs: u64 = 60
}

const STUN_PAYLOAD: [u8; 20] = [
    0, 1, // Binding request
    0, 0, // Message length
    0x21, 0x12, 0xa4, 0x42, // magic
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

enum ConnectError {
    Timeout(SystemTime),
    Err(io::Error),
    Incomplete,
}

impl From<io::Error> for ConnectError {
    fn from(e: io::Error) -> ConnectError {
        if let io::ErrorKind::TimedOut = e.kind() {
            return ConnectError::Timeout(SystemTime::now());
        } else {
            return ConnectError::Err(e);
        }
    }
}

fn attempt_stun_connect(addr: SocketAddr) -> Result<SystemTime, ConnectError> {
    // We let the OS choose the port by specifying 0
    let local_socket = UdpSocket::bind("0.0.0.0:0")?;
    local_socket.connect(addr)?;
    local_socket.set_read_timeout(Some(std::time::Duration::from_secs(
        STUNRECVTIMEOUTSECS.flag,
    )))?;
    let _sent = local_socket.send(&STUN_PAYLOAD)?;
    // TODO what if we didn't send the whole packet?
    let mut buf = [0 as u8; 1024];
    let rcvd = local_socket.recv(&mut buf)?;
    if rcvd == 0 {
        return Err(ConnectError::Incomplete);
    }
    Ok(SystemTime::now())
}

pub fn start_listen_thread(
    domain_name: &str,
    s: SocketAddr,
    stun_counter_vec_copy: CounterVec,
    stun_latency_vec_copy: IntGaugeVec,
    stun_success_vec_copy: IntGaugeVec,
) {
    debug!("started thread for {}", domain_name);
    loop {
        let now = SystemTime::now();
        info!("Attempting to connect to {}", domain_name);
        match attempt_stun_connect(s) {
            Ok(finish_time) => {
                info!("Success! connecting to {}", domain_name);
                stun_counter_vec_copy
                    .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                    .inc();
                stun_latency_vec_copy
                    .with(&prometheus::labels! {"domain" => domain_name})
                    // Technically this could be lossy but we'll chance it anyway.
                    .set(finish_time.duration_since(now).unwrap().as_millis() as i64);
                stun_success_vec_copy
                    .with(&prometheus::labels! {"domain" => domain_name})
                    .set(1);
            }
            Err(ConnectError::Timeout(finish_time)) => {
                info!(
                    "Stun connection to {} timedout after {} millis",
                    domain_name,
                    finish_time.duration_since(now).unwrap().as_millis()
                );
                stun_counter_vec_copy
                    .with(&prometheus::labels! {"result" => "timeout", "domain" => domain_name})
                    .inc();
                stun_success_vec_copy
                    .with(&prometheus::labels! {"domain" => domain_name})
                    .set(0);
            }
            Err(ConnectError::Err(e)) => {
                error!("Error connecting to {}: {}", domain_name, e);
                stun_counter_vec_copy
                    .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
                    .inc();
                stun_success_vec_copy
                    .with(&prometheus::labels! {"domain" => domain_name})
                    .set(0);
            }
            Err(ConnectError::Incomplete) => {
                error!("Connection to {} was incomplete", domain_name);
                stun_counter_vec_copy
                    .with(&prometheus::labels! {"result" => "incomplete", "domain" => domain_name})
                    .inc();
                stun_success_vec_copy
                    .with(&prometheus::labels! {"domain" => domain_name})
                    .set(0);
            }
        }

        // Then we wait for some period of time.
        std::thread::sleep(std::time::Duration::from_secs(DELAYSECS.flag))
    }
}

pub fn delay_secs() -> u64 {
    DELAYSECS.flag
}
