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
use ekko::{Ekko, EkkoResponse};
use gflags;
use log::{error, info};
use prometheus::{CounterVec, IntGaugeVec};
use std::sync::{Arc, RwLock};
use std::time::Duration;

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

pub fn start_echo_loop(
    domain_name: &str,
    stop_signal: Arc<RwLock<bool>>,
    ping_latency_guage: IntGaugeVec,
    ping_counter: CounterVec,
) {
    info!("Pinging {}", domain_name);
    let mut sender = Ekko::with_target(domain_name).unwrap();
    loop {
        {
            // Limit the scope of this lock
            if *stop_signal.read().unwrap() {
                info!("Stopping ping thread for {}", domain_name);
                return;
            }
        }
        let response = sender
            .send_with_timeout(MAXHOPS.flag, Some(Duration::from_millis(PINGTIMEOUT.flag)))
            .unwrap();
        match response {
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
            EkkoResponse::ExceededResponse(r) => {
                ping_counter
                    .with(&prometheus::labels! {"result" => "timedout", "domain" => domain_name})
                    .inc();
            }
            _ => {
                ping_counter
                    .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
                    .inc();
                error!("{:?}", response);
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}
