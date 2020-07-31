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

use std::convert::From;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;

use gflags;
use nursery::thread;
use nursery::{Nursery, Waitable};
use prometheus;
use prometheus::{CounterVec, Encoder, IntGaugeVec, Opts, Registry, TextEncoder};
use tiny_http;

use log::{debug, error, info};

gflags::define! {
    /// Print this help text.
    -h, --help = false
}

gflags::define! {
    /// Delay between lookup attempts in seconds.
    --delaySecs: u64 = 60
}

gflags::define! {
    /// Port to listen on for exporting variables prometheus style.
    --listenHost = "0.0.0.0:8080"
}

gflags::define! {
    /// Read timeout for the stun server udp receive
    --stunRecvTimeoutSecs: u64 = 5
}

gflags::define! {
    /// Enable debug logging
    --debug = false
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

fn resolve_addrs(servers: &Vec<&str>) -> io::Result<Vec<SocketAddr>> {
    let mut results = Vec::new();
    for name in servers.iter().cloned() {
        // TODO for resolution errors return a more valid error with the domain name.
        match name.to_socket_addrs() {
            Ok(addr) => results.extend(addr),
            Err(e) => info!("Failed to resolve {} with error {}", name, e),
        }
    }
    return Ok(results);
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

fn main() -> anyhow::Result<()> {
    let default_stun_servers: Vec<&'static str> = vec![
        "stun.l.google.com:19302",
        "stun.ekiga.net:3478",
        "stun.xten.com:3478",
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

    let level = if DEBUG.flag { 3 } else { 2 };
    stderrlog::new()
        .verbosity(level)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()?;

    if stun_servers.is_empty() {
        stun_servers = default_stun_servers;
    }
    let counter_opts = Opts::new(
        "stun_attempt_counter",
        "Counter for the good, bad, and total attempts to connect to stun server.",
    );
    let gauge_opts = Opts::new(
        "stun_attempt_latency_ms",
        "Latency guage in millis per stun domain.",
    );

    let stop_signal = Arc::new(RwLock::new(false));

    // Create a Registry and register metrics.
    let r = Registry::new();
    let stun_counter_vec = CounterVec::new(counter_opts, &["result", "domain"]).unwrap();
    r.register(Box::new(stun_counter_vec.clone()))
        .expect("Failed to register stun connection counter");
    let stun_latency_vec = IntGaugeVec::new(gauge_opts, &["domain"]).unwrap();
    r.register(Box::new(stun_latency_vec.clone()))
        .expect("Failed to register stun latency guage");
    let socket_addrs = resolve_addrs(&stun_servers).unwrap();
    let stun_servers = Arc::new(stun_servers);

    // first we attempt connections to each server.
    let mut parent = Nursery::new();
    for (i, s) in socket_addrs.iter().enumerate() {
        let stun_servers_copy = stun_servers.clone();
        let stun_counter_vec_copy = stun_counter_vec.clone();
        let stun_latency_vec_copy = stun_latency_vec.clone();
        let s = s.clone();
        let domain_name = *stun_servers_copy.get(i).unwrap();
        let stop_signal = stop_signal.clone();
        let connect_thread = thread::Pending::new(move || {
            debug!("started thread for {}", domain_name);
            loop {
                {
                    // Limit the scope of this lock
                    if *stop_signal.read().unwrap() {
                        info!("Stopping thread for {}", domain_name);
                        return;
                    }
                }
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
                    }
                    Err(ConnectError::Err(e)) => {
                        error!("Error connecting to {}: {}", domain_name, e);
                        stun_counter_vec_copy
                            .with(&prometheus::labels! {"result" => "err", "domain" => domain_name})
                            .inc();
                    }
                    Err(ConnectError::Incomplete) => {
                        error!("Connection to {} was incomplete", domain_name);
                        stun_counter_vec_copy
                            .with(&prometheus::labels! {"result" => "incomplete", "domain" => domain_name})
                            .inc();
                    }
                }

                // Then we wait for some period of time.
                std::thread::sleep(std::time::Duration::from_secs(DELAYSECS.flag))
            }
        });
        parent.schedule(Box::new(connect_thread));
    }
    let stop_signal = stop_signal.clone();
    let render_thread = thread::Pending::new(move || {
        debug!("attempting to start server on {}", LISTENHOST.flag);
        let server = match tiny_http::Server::http(LISTENHOST.flag) {
            Ok(server) => server,
            Err(err) => {
                let mut signal = stop_signal.write().unwrap();
                *signal = true;
                error!("Error starting render thread {}", err);
                error!("Shutting down all threads...");
                return;
            }
        };
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
                        info!("Error responding to request {}", e);
                    }
                }
                Err(e) => {
                    info!("Invalid http request! {}", e);
                }
            }
        }
    });
    parent.schedule(Box::new(render_thread));
    // Blocks forever
    parent.wait();
    Ok(())
}
