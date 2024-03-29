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
use std::sync::Arc;

use gflags;
use metrics_exporter_prometheus;
use nursery::thread;
use nursery::{Nursery, Waitable};
use tiny_http;
use tracing::{debug, error, info, instrument, Level};
use tracing_subscriber::FmtSubscriber;

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
    /// Enable trace logging
    --trace = false
}

gflags::define! {
    /// Comma separated list of hosts to ping
    --pingHosts = "google.com"
}

gflags::define! {
    /// Comma separated list of hosts to ping
    --stunHosts = "stun.l.google.com:19302,stun.ekiga.net:3478,stun.xten.com:3478,stun.ideasip.com:3478,stun.rixtelecom.se:3478,stun.schlund.de:3478,stun.softjoys.com:3478,stun.stunprotocol.org:3478,stun.voiparound.com:3478,stun.voipbuster.com:3478,stun.voipstunt.com:3478,stun1.noc.ams-ix.net:3478"
}

#[instrument]
fn main() -> anyhow::Result<()> {
    gflags::parse();
    let stun_servers: Vec<&str> = STUNHOSTS.flag.split(",").collect();

    if HELP.flag {
        println!("durnitisp <options> <list of hostname:port>");
        println!("");
        println!("The hostname and port are expected to be for a valid stun server.");
        println!("You can put as many of them as you want after the options.");
        println!("");
        println!("FLAGS:");
        gflags::print_help_and_exit(0);
    }

    let subscriber_builder = if DEBUG.flag {
        FmtSubscriber::builder()
            // all spans/events with a level higher than debug
            // will be written to stdout.
            .with_max_level(Level::DEBUG)
    } else if TRACE.flag {
        FmtSubscriber::builder()
            // all spans/events with a level will be written to stdout.
            .with_max_level(Level::TRACE)
    } else {
        FmtSubscriber::builder()
            // all spans/events with a level higher than info (e.g, error, info, warn, etc.)
            // will be written to stdout.
            .with_max_level(Level::INFO)
    };

    tracing::subscriber::set_global_default(subscriber_builder.finish())
        .expect("setting default subscriber failed");

    let ping_hosts: Vec<&str> = PINGHOSTS.flag.split(",").collect();

    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let prom_handle = builder
        .install_recorder()
        .expect("Failed to install prometheus exporter");
    // Create a Registry and register metrics.
    let stun_socket_addrs = util::resolve_socket_addrs(&stun_servers).unwrap();
    let stun_servers = Arc::new(stun_servers);
    let ping_hosts = Arc::new(ping_hosts);

    let mut parent = Nursery::new();
    // First we start the render thread.
    {
        // Introduce a new scope for our Arc to clone before moving it into the thread.
        // thread::Handle starts the thread immediately so the render thread will usually start first.
        let render_thread = thread::Handle::new(move || {
            debug!(listenhost = LISTENHOST.flag, "attempting to start server");
            let server = match tiny_http::Server::http(LISTENHOST.flag) {
                Ok(server) => server,
                Err(err) => {
                    error!(
                        ?err,
                        "Error starting render thread. Shutting down all thread.",
                    );
                    std::process::exit(1);
                }
            };
            info!(
                listenthost = LISTENHOST.flag,
                "Listening for metrics request on"
            );
            loop {
                info!("Waiting for request");
                match server.recv() {
                    Ok(req) => {
                        let response = tiny_http::Response::from_data(prom_handle.render())
                            .with_status_code(200);
                        if let Err(e) = req.respond(response) {
                            error!(err = ?e, "Error responding to request");
                        }
                    }
                    Err(e) => {
                        error!(err = ?e, "Invalid http request!");
                    }
                }
            }
        });
        parent.adopt(Box::new(render_thread));
    }
    {
        icmp::schedule_echo_server(&ping_hosts, &mut parent);
    }
    // Then we attempt to start connections to each stun server.
    for (i, s) in stun_socket_addrs.iter().enumerate() {
        let stun_servers_copy = stun_servers.clone();
        if let Some(s) = s.clone() {
            let domain_name = *stun_servers_copy.get(i).unwrap();
            let connect_thread =
                thread::Pending::new(move || stun::start_listen_thread(domain_name, s.into()));
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
