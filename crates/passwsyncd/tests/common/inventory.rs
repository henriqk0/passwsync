//! Socket inventory of this test process: `/proc/self/fd` socket inodes matched against
//! `/proc/self/net/{tcp,tcp6,udp,udp6}` (SC-002).

use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    /// `0A` = TCP LISTEN.
    pub state: String,
}

impl Sock {
    pub fn is_listener(&self) -> bool {
        self.proto == "tcp" && self.state == "0A"
    }

    pub fn local_port(&self) -> u16 {
        self.local.rsplit(':').next().unwrap().parse().unwrap()
    }
}

fn own_inodes() -> HashSet<String> {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
        .filter_map(|link| {
            let text = link.to_string_lossy().into_owned();
            Some(
                text.strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .to_string(),
            )
        })
        .collect()
}

fn decode_v4(field: &str) -> String {
    let (ip, port) = field.split_once(':').unwrap();
    if ip.len() != 8 {
        return format!("[v6 {ip}]:{}", u16::from_str_radix(port, 16).unwrap());
    }
    let raw = u32::from_str_radix(ip, 16).unwrap();
    let ip = Ipv4Addr::from(raw.swap_bytes());
    SocketAddrV4::new(ip, u16::from_str_radix(port, 16).unwrap()).to_string()
}

/// Every TCP/UDP (v4 and v6) socket held by this process.
pub fn sockets() -> Vec<Sock> {
    let inodes = own_inodes();
    let mut out = Vec::new();
    for (file, proto) in [
        ("tcp", "tcp"),
        ("tcp6", "tcp6"),
        ("udp", "udp"),
        ("udp6", "udp6"),
    ] {
        let table = fs::read_to_string(format!("/proc/self/net/{file}")).unwrap_or_default();
        for line in table.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() > 9 && inodes.contains(cols[9]) {
                out.push(Sock {
                    proto,
                    local: decode_v4(cols[1]),
                    remote: decode_v4(cols[2]),
                    state: cols[3].to_string(),
                });
            }
        }
    }
    out
}
