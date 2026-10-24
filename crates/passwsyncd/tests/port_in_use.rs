//! 003 edge case: a busy peer or discovery port keeps networking off with `port_in_use`,
//! leaves no network socket open, and the loopback UI keeps working. One test per file:
//! the inventory covers the whole test process.

mod common;

use std::net::{TcpListener, UdpSocket};

use common::inventory::sockets;
use common::server::{TestServer, free_net_port};

#[test]
fn busy_ports_keep_networking_off_and_the_ui_working() {
    // Busy peer port.
    let (peer, disc) = (free_net_port(), free_net_port());
    let busy = TcpListener::bind(("0.0.0.0", peer)).unwrap();
    let a = TestServer::start_with(&format!(
        "network = on\npeer_port = {peer}\ndiscovery_port = {disc}\n"
    ));
    assert_eq!(a.running().network_status(), "port_in_use");
    assert!(
        a.log_text()
            .contains(&format!("network unavailable (port-in-use {peer})"))
    );
    let s = a.login();
    let v = a.api(&s, "GET", "/api/network", None).json();
    assert_eq!(v["status"]["state"], "port_in_use");
    assert_eq!(v["status"]["port"], peer);
    assert!(!a.running().device_key_held(), "key wiped");
    let socks = sockets();
    assert!(
        !socks.iter().any(|x| x.local.ends_with(&format!(":{disc}"))),
        "the discovery socket is not left open: {socks:?}"
    );
    drop(a);
    drop(busy);

    // Busy discovery port: the TCP listener opened first is closed again.
    let (peer, disc) = (free_net_port(), free_net_port());
    let busy = UdpSocket::bind(("0.0.0.0", disc)).unwrap();
    let b = TestServer::start_with(&format!(
        "network = on\npeer_port = {peer}\ndiscovery_port = {disc}\n"
    ));
    assert_eq!(b.running().network_status(), "port_in_use");
    assert!(
        b.log_text()
            .contains(&format!("network unavailable (port-in-use {disc})"))
    );
    let socks = sockets();
    assert!(
        !socks.iter().any(|x| x.local == format!("0.0.0.0:{peer}")),
        "the peer listener was closed again: {socks:?}"
    );
    let s = b.login();
    assert_eq!(b.api(&s, "GET", "/api/network", None).status, 200);
    drop(busy);
}
