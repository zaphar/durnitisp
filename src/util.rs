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

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use log::info;

pub fn resolve_addrs<'a>(servers: &'a Vec<&str>) -> io::Result<Vec<Option<SocketAddr>>> {
    let mut results = Vec::new();
    for name in servers.iter().cloned() {
        // TODO for resolution errors return a more valid error with the domain name.
        match name.to_socket_addrs() {
            Ok(addr) => results.push(addr.into_iter().next()),
            Err(e) => {
                info!("Failed to resolve {} with error {}", name, e);
                results.push(None);
            }
        }
    }
    return Ok(results);
}

pub fn resolve_ip_addrs(hosts: &Vec<&str>) -> io::Result<Vec<Option<IpAddr>>> {
    let mut results = Vec::with_capacity(hosts.len());
    // NOTE(jwall): This is a silly hack due to the fact that the proper way
    // to do host lookups in the Rust stdlib has not settled yet.
    // TODO(jwall): Do this in a less hacky method once host lookups
    // are settled properly.
    for host in hosts.iter().cloned() {
        match format!("{}:8080", host).to_socket_addrs() {
            Ok(addr) => results.push(addr.into_iter().next().map(|a| a.ip())),
            Err(e) => {
                info!("Failed to resolve {} with error {}", host, e);
                results.push(None);
            }
        }
    }
    Ok(results)
}
