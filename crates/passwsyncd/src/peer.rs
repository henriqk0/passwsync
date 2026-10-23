//! Which local user owns the client end of a loopback connection (FR-007a, research R5).
//! Reads `/proc/net/tcp`; any lookup failure means "unknown", which callers reject.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// UID owning the socket whose local address is `client` and remote address is `server`
/// (both IPv4, client on loopback) in a `/proc/net/tcp` table.
pub fn find_uid(table: &str, client: SocketAddr, server: SocketAddr) -> Option<u32> {
    let (SocketAddr::V4(client), SocketAddr::V4(server)) = (client, server) else {
        return None;
    };
    if !client.ip().is_loopback() {
        return None;
    }
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let local = parse_addr(fields.nth(1)?)?;
        let remote = parse_addr(fields.next()?)?;
        if local != client || remote != server {
            return None;
        }
        // Remaining fields: st tx:rx tr:when retrnsmt uid
        fields.nth(4)?.parse().ok()
    })
}

/// `0100007F:6B5F`: the address as the kernel's native-endian u32, then the port.
fn parse_addr(text: &str) -> Option<SocketAddrV4> {
    let (ip, port) = text.split_once(':')?;
    if ip.len() != 8 || port.len() != 4 {
        return None;
    }
    let ip = u32::from_str_radix(ip, 16).ok()?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(SocketAddrV4::new(Ipv4Addr::from(ip.to_ne_bytes()), port))
}

/// Looks up the UID of the connection from `client` to our `server` address.
pub fn peer_uid(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    let table = fs::read_to_string("/proc/net/tcp").ok()?;
    find_uid(&table, client, server)
}
