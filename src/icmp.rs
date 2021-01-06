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
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::util;

use ekko::{Ekko, EkkoResponse};
use gflags;
use log::{error, info};
use prometheus::{CounterVec, IntGaugeVec};

gflags::define! {
    /// The size in bytes of the ping requests.
    --pingPayload = "durnitisp"
}

gflags::define! {
    /// The size in bytes of the ping requests.
    --pingTTL: u32 = 113
}

gflags::define! {
    /// The size in bytes of the ping requests.
    --pingTimeout: u64 = 2048
}

gflags::define! {
    /// The size in bytes of the ping requests.
    --maxHops: u8 = 50
}

fn resolve_host_address(host: &str) -> String {
    format!("{}", util::resolve_hosts(&vec![host]).unwrap().first().unwrap().unwrap())
}

pub fn start_echo_loop(
    domain_name: &str,
    stop_signal: Arc<RwLock<bool>>,
    ping_latency_guage: IntGaugeVec,
    ping_counter: CounterVec,
) {
    let resolved = resolve_host_address(domain_name);
    info!("Attempting to ping domain {} at address: {}", domain_name, resolved);
    let mut sender = Ekko::with_target(&resolved).unwrap();
    loop {
        {
            // Limit the scope of this lock
            if *stop_signal.read().unwrap() {
                info!("Stopping ping thread for {}", domain_name);
                return;
            }
        }
        match sender
            .send_with_timeout(MAXHOPS.flag, Some(Duration::from_millis(PINGTIMEOUT.flag))) {
                Ok(r) => match r {
                    EkkoResponse::DestinationResponse(r) => {
                        info!(
                            "ICMP: Reply from {}: time={}ms",
                            r.address.unwrap(),
                            r.elapsed.as_millis(),
                        );
                        ping_counter
                            .with(&prometheus::labels! {"result" => "ok", "domain" => domain_name})
                            .inc();
                        ping_latency_guage
                            .with(&prometheus::labels! {"domain" => domain_name})
                            .set(r.elapsed.as_millis() as i64);
                    }
                    EkkoResponse::UnreachableResponse((_, ref _code)) => {
                        // If we got unreachable we need to set up a new sender.
                        error!("{:?}", r);
                        info!("Restarting our sender");
                        ping_counter
                            .with(&prometheus::labels! {"result" => "unreachable", "domain" => domain_name})
                            .inc();
                        let resolved = resolve_host_address(domain_name);
                        let mut new_sender = Ekko::with_target(&resolved).unwrap();
                        std::mem::swap(&mut sender, &mut new_sender);

                    }
                    EkkoResponse::ExceededResponse(_) => {
                        ping_counter
                            .with(&prometheus::labels! {"result" => "timeout", "domain" => domain_name})
                            .inc();
                    }
                    _ => {
                        ping_counter
                            .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
                            .inc();
                        error!("{:?}", r);
                    }
                },
                Err(e) => {
                    ping_counter
                        .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
                        .inc();
                    error!("Ping send to domain: {} address: {} failed: {:?}, Trying again later", domain_name, &resolved, e);
                }
            };
        std::thread::sleep(Duration::from_secs(3));
    }
}
