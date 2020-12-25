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

use std::sync::Arc;
use std::sync::RwLock;

use gflags;
use log::{debug, error, info};
use nursery::thread;
use nursery::{Nursery, Waitable};
use prometheus;
use prometheus::{CounterVec, Encoder, IntGaugeVec, Opts, Registry, TextEncoder};
use stderrlog;
use tiny_http;

mod icmp;
mod stun;
mod util;

gflags::define! {
    /// Print this help text
    -h, --help = false
}

gflags::define! {
    /// Port to listen on for exporting variables prometheus style
    --listenHost = "0.0.0.0:8080"
}

gflags::define! {
    /// Enable debug logging
    --debug = false
}

gflags::define! {
    /// Comma separated list of hosts to ping
    --pingHosts = "google.com"
}

fn main() -> anyhow::Result<()> {
    let default_stun_servers: Vec<&'static str> = vec![
        "stun.l.google.com:19302",
        "stun.ekiga.net:3478",
        "stun.xten.com:3478",
        "stun.ideasip.com:3478",
        "stun.rixtelecom.se:3478",
        "stun.schlund.de:3478",
        "stun.softjoys.com:3478",
        "stun.stunprotocol.org:3478",
        "stun.voiparound.com:3478",
        "stun.voipbuster.com:3478",
        "stun.voipstunt.com:3478",
        "stun1.noc.ams-ix.net:3478",
    ];
    let mut stun_servers = gflags::parse();

    if HELP.flag {
        println!("durnitisp <options> <list of hostname:port>");
        println!("");
        println!("The hostname and port are expected to be for a valid stun server.");
        println!("You can put as many of them as you want after the options.");
        println!("");
        println!("FLAGS:");
        gflags::print_help_and_exit(0);
    }

    let level = if DEBUG.flag || cfg!(debug_assertions) {
        3
    } else {
        2
    };

    stderrlog::new()
        .verbosity(level)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()?;

    if stun_servers.is_empty() {
        stun_servers = default_stun_servers;
    }
    // FIXME(jwall): allow them to override ping hosts
    let ping_hosts: Vec<&str> = PINGHOSTS.flag.split(",").collect();
    let stop_signal = Arc::new(RwLock::new(false));

    // Create a Registry and register metrics.
    let r = Registry::new();
    let stun_counter_vec = CounterVec::new(
        Opts::new(
            "stun_attempt_counter",
            "Counter for the good, bad, and total attempts to connect to stun server.",
        ),
        &["result", "domain"],
    )
    .unwrap();
    let stun_success_vec = IntGaugeVec::new(
        Opts::new("stun_success", "Stun probe successes"),
        &["domain"],
    )
    .unwrap();
    let stun_latency_vec = IntGaugeVec::new(
        Opts::new(
            "stun_attempt_latency_ms",
            "Latency guage in millis per stun domain.",
        ),
        &["domain"],
    )
    .unwrap();
    let ping_latency_vec =
        IntGaugeVec::new(Opts::new("ping_latency", "ICMP Ping latency"), &["domain"]).unwrap();
    let ping_counter_vec = CounterVec::new(
        Opts::new("ping_counter", "Ping Request Counter"),
        &["result", "domain"],
    )
    .unwrap();
    r.register(Box::new(stun_counter_vec.clone()))
        .expect("Failed to register stun connection counter");
    r.register(Box::new(stun_latency_vec.clone()))
        .expect("Failed to register stun latency guage");
    r.register(Box::new(stun_success_vec.clone()))
        .expect("Failed to register stun success gauge");
    r.register(Box::new(ping_latency_vec.clone()))
        .expect("Failed to register ping latency guage");
    r.register(Box::new(ping_counter_vec.clone()))
        .expect("Failed to register ping counter");
    let stun_socket_addrs = util::resolve_addrs(&stun_servers).unwrap();
    let stun_servers = Arc::new(stun_servers);
    let ping_hosts = Arc::new(ping_hosts);

    let mut parent = Nursery::new();
    // First we start the render thread.
    {
        // Introduce a new scope for our Arc to clone before moving it into the thread.
        let stop_signal = stop_signal.clone();
        // thread::Handle starts the thread immediately so the render thread will usually start first.
        let render_thread = thread::Handle::new(move || {
            debug!("attempting to start server on {}", LISTENHOST.flag);
            let server = match tiny_http::Server::http(LISTENHOST.flag) {
                Ok(server) => server,
                Err(err) => {
                    let mut signal = stop_signal.write().unwrap();
                    *signal = true;
                    error!("Error starting render thread {}", err);
                    error!("Shutting down all threads...");
                    std::process::exit(1);
                }
            };
            info!("Listening for metrics request on {}", LISTENHOST.flag);
            loop {
                info!("Waiting for request");
                match server.recv() {
                    Ok(req) => {
                        let mut buffer = vec![];
                        // Gather the metrics.
                        let encoder = TextEncoder::new();
                        let metric_families = r.gather();
                        encoder.encode(&metric_families, &mut buffer).unwrap();

                        let response = tiny_http::Response::from_data(buffer).with_status_code(200);
                        if let Err(e) = req.respond(response) {
                            error!("Error responding to request {}", e);
                        }
                    }
                    Err(e) => {
                        info!("Invalid http request! {}", e);
                    }
                }
            }
        });
        parent.adopt(Box::new(render_thread));
    }
    for (i, domain_name) in ping_hosts.iter().cloned().enumerate() {
        // TODO(Prometheus stats)
        let stop_signal = stop_signal.clone();
        let ping_latency_vec = ping_latency_vec.clone();
        let ping_counter_vec = ping_counter_vec.clone();
        let ping_thread = thread::Pending::new(move || {
            icmp::start_echo_loop(domain_name, stop_signal, ping_latency_vec, ping_counter_vec);
        });
        parent.schedule(Box::new(ping_thread));
    }
    // Then we attempt to start connections to each stun server.
    for (i, s) in stun_socket_addrs.iter().enumerate() {
        let stun_servers_copy = stun_servers.clone();
        let stun_counter_vec_copy = stun_counter_vec.clone();
        let stun_latency_vec_copy = stun_latency_vec.clone();
        let stun_success_vec_copy = stun_success_vec.clone();
        if let Some(s) = s.clone() {
            let domain_name = *stun_servers_copy.get(i).unwrap();
            let stop_signal = stop_signal.clone();
            let connect_thread = thread::Pending::new(move || {
                stun::start_listen_thread(
                    domain_name,
                    stop_signal,
                    s,
                    stun_counter_vec_copy,
                    stun_latency_vec_copy,
                    stun_success_vec_copy,
                )
            });
            parent.schedule(Box::new(connect_thread));
            // Spread the probe threads out so they're somewhat uniformly distributed.
            std::thread::sleep(std::time::Duration::from_micros(
                stun::delay_secs() * 1000000 / (stun_socket_addrs.len() as u64),
            ))
        };
    }
    // Blocks forever
    parent.wait();
    Ok(())
}
