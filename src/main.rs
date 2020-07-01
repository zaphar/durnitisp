use gflags;

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

gflags::define! {
    /// Print this help text.
    -h, --help = false
}

gflags::define! {
    /// Delay between lookup attempts in seconds.
    --delaySec: i32 = 60
}

gflags::define! {
    /// Port to listen on for exporting variables prometheus style.
    --listenPort: i32 = 0
}

gflags::define! {
    /// Retry dns infinitenly until we resolve.
    --dnsRetryInfinite = false
}

fn resolveAddrs(servers: Vec<&str>) -> io::Result<Vec<SocketAddr>> {
    let mut results = Vec::new();
    for name in servers {
        eprintln!("Resolving {}", name);
        results.extend(name.to_socket_addrs()?);
    }
    return Ok(results);
}

fn main() {
    let default_stun_servers: Vec<&'static str> = vec![
        "stun.l.google.com:19302",
        "stun.ekiga.net:3478",
        "stunserver.org:3478",
        "stun.xten.com:3478",
        "stun.softjoys.com:3478",
        "stun1.noc.ams-ix.net:3478",
    ];
    let mut stun_servers = gflags::parse();

    if HELP.flag {
        // TODO print better help than this.
        gflags::print_help_and_exit(0);
    }
    if stun_servers.is_empty() {
        stun_servers = default_stun_servers;
    }
    let socketAddrs = resolveAddrs(stun_servers).unwrap();
}
