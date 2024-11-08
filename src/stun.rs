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
use metrics::{counter, gauge};
use std::convert::From;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::SystemTime;
use tracing::{debug, error, info, instrument};

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

fn make_count_labels(domain_name: &str, result: &str) -> [(&'static str, String); 2] {
    [
        ("domain", domain_name.to_owned()),
        ("result", result.to_owned()),
    ]
}

#[instrument(
    name = "STUN",
    fields(domain=domain_name, socket=%s),
)]
pub fn start_listen_thread(domain_name: &str, s: SocketAddr) {
    let labels: [(&str, String); 1] = [("domain", domain_name.to_owned())];
    let success = gauge!("stun_success", &labels);

    debug!("starting thread");
    loop {
        let now = SystemTime::now();
        info!("Attempting to connect");
        match attempt_stun_connect(s) {
            Ok(finish_time) => {
                info!(
                    timeout = false,
                    success = true,
                    millis = finish_time.duration_since(now).unwrap().as_millis(),
                    conn_type = "Stun connection",
                );
                counter!(
                    "stun_attempt_counter",
                    &make_count_labels(domain_name, "ok")
                )
                .increment(1);
                gauge!("stun_attempt_latency_ms", &labels)
                    .increment(finish_time.duration_since(now).unwrap().as_millis() as f64);
                success.set(1);
            }
            Err(ConnectError::Timeout(finish_time)) => {
                info!(
                    timeout = true,
                    success = false,
                    millis = finish_time.duration_since(now).unwrap().as_millis(),
                    conn_type = "Stun connection",
                );
                counter!(
                    "stun_attempt_counter",
                    &make_count_labels(domain_name, "timeout")
                )
                .increment(1);
                success.set(0);
            }
            Err(ConnectError::Err(e)) => {
                error!(
                    timeout=true, success=false, err = ?e,
                    conn_type="Stun connection",
                );
                counter!(
                    "stun_attempt_counter",
                    &make_count_labels(domain_name, "err")
                )
                .increment(1);
                success.set(0);
            }
            Err(ConnectError::Incomplete) => {
                error!(
                    timeout = true,
                    success = false,
                    err = "Incomplete",
                    conn_type = "Stun connection",
                );
                counter!(
                    "stun_attempt_counter",
                    &make_count_labels(domain_name, "incomplete")
                )
                .increment(1);
                success.set(0);
            }
        }

        // Then we wait for some period of time.
        std::thread::sleep(std::time::Duration::from_secs(DELAYSECS.flag))
    }
}

pub fn delay_secs() -> u64 {
    DELAYSECS.flag
}
