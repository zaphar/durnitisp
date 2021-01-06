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
use std::net::IpAddr;
use std::net::{SocketAddr, ToSocketAddrs};

use log::info;
use resolve::config::DnsConfig;
use resolve::resolver::{DnsResolver};
use gflags;

gflags::define! {
    /// Allow IPv6 addresses for domain name lookups.
    --allowIpv6: bool = false
}

pub fn resolve_hosts<'a>(servers: &'a Vec<&str>) -> io::Result<Vec<Option<IpAddr>>> {
    let mut results = Vec::new();
    let mut config = DnsConfig::load_default()?;
    config.use_inet6 = ALLOWIPV6.flag;
    let resolver = DnsResolver::new(config)?;
    for name in servers.iter().cloned() {
        // TODO for resolution errors return a more valid error with the domain name.
        let mut iter = resolver.resolve_host(name)?;
        results.push(iter.next());
    }
    return Ok(results);
}

pub fn resolve_socket_addrs<'a>(servers: &'a Vec<&str>) -> io::Result<Vec<Option<SocketAddr>>> {
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