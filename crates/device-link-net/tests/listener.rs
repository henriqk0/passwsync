//! Bounded listener (FR-030): at most 16 unauthenticated connections, policy check on the
//! peer address, Hello timeout.

mod support;

use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use device_link::error::DropReason;
use device_link::policy::AddressPolicy;
use support::{Options, start, wait_for};

fn closed_quickly(stream: &mut TcpStream, within: Duration) -> bool {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0u8; 8];
    matches!(stream.read(&mut buf), Ok(0))
        || matches!(stream.read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
}

#[test]
fn listener_binds_the_wildcard_address_on_the_peer_port() {
    let n = start(1, "A", Options::default());
    let table = std::fs::read_to_string("/proc/self/net/tcp").unwrap();
    let wanted = format!("00000000:{:04X}", n.peer_port);
    assert!(
        table.lines().any(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.get(1) == Some(&wanted.as_str()) && cols.get(3) == Some(&"0A")
        }),
        "no 0.0.0.0:{} listener",
        n.peer_port
    );
    n.node.stop();
}

#[test]
fn the_seventeenth_unauthenticated_connection_is_closed_and_counted() {
    let mut options = Options::default();
    options.timing.step_timeout = Duration::from_secs(5);
    let n = start(1, "A", options);
    let mut idle = Vec::new();
    for _ in 0..16 {
        idle.push(TcpStream::connect(n.addr()).unwrap());
    }
    assert!(wait_for(Duration::from_secs(2), || n
        .node
        .unauthenticated()
        == 16));
    let mut extra = TcpStream::connect(n.addr()).unwrap();
    assert!(closed_quickly(&mut extra, Duration::from_secs(1)));
    assert!(wait_for(Duration::from_secs(1), || n
        .node
        .counters()
        .get(DropReason::Overflow)
        == 1));
    // The first 16 are still open.
    idle[0]
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut buf = [0u8; 1];
    assert!(
        idle[0].read(&mut buf).is_err(),
        "still open (read times out)"
    );
    drop(idle);
    assert!(wait_for(Duration::from_secs(3), || n
        .node
        .unauthenticated()
        == 0));
    n.node.stop();
}

#[test]
fn connections_from_addresses_failing_the_policy_are_closed() {
    let n = start(
        1,
        "A",
        Options {
            policy: AddressPolicy::lan(),
            ..Options::default()
        },
    );
    let mut stream = TcpStream::connect(n.addr()).unwrap();
    assert!(closed_quickly(&mut stream, Duration::from_secs(1)));
    assert!(wait_for(Duration::from_secs(1), || n
        .node
        .counters()
        .get(DropReason::Public)
        >= 1));
    n.node.stop();
}

#[test]
fn a_silent_connection_is_closed_after_the_hello_timeout() {
    let mut options = Options::default();
    options.timing.step_timeout = Duration::from_millis(300);
    let n = start(1, "A", options);
    let mut stream = TcpStream::connect(n.addr()).unwrap();
    let start = Instant::now();
    assert!(closed_quickly(&mut stream, Duration::from_secs(2)));
    assert!(start.elapsed() >= Duration::from_millis(250));
    assert!(wait_for(Duration::from_secs(1), || n
        .node
        .counters()
        .get(DropReason::Timeout)
        == 1));
    n.node.stop();
}

#[test]
fn a_bad_hello_closes_and_counts_malformed_and_an_oversized_frame_counts_oversized() {
    let n = start(1, "A", Options::default());
    let mut stream = TcpStream::connect(n.addr()).unwrap();
    std::io::Write::write_all(&mut stream, b"\x00\x06PWSX\x01\x01").unwrap();
    assert!(closed_quickly(&mut stream, Duration::from_secs(1)));
    let mut stream = TcpStream::connect(n.addr()).unwrap();
    std::io::Write::write_all(&mut stream, b"\x04\x01").unwrap();
    assert!(closed_quickly(&mut stream, Duration::from_secs(1)));
    assert!(wait_for(Duration::from_secs(1), || {
        let c = n.node.counters();
        c.get(DropReason::Malformed) == 1 && c.get(DropReason::Oversized) == 1
    }));
    n.node.stop();
}

#[test]
fn a_pairing_hello_without_a_code_is_refused_at_once() {
    let n = start(1, "A", Options::default());
    let mut stream = TcpStream::connect(n.addr()).unwrap();
    std::io::Write::write_all(&mut stream, b"\x00\x06PWSC\x01\x02").unwrap();
    assert!(closed_quickly(&mut stream, Duration::from_secs(1)));
    n.node.stop();
}

/// Non-listening TCP sockets in this network namespace that touch `port` (local or remote).
fn tcp_sockets_on(port: u16) -> Vec<String> {
    let suffix = format!(":{port:04X}");
    std::fs::read_to_string("/proc/self/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let touches = cols.get(1).is_some_and(|c| c.ends_with(&suffix))
                || cols.get(2).is_some_and(|c| c.ends_with(&suffix));
            touches && cols.get(3) != Some(&"0A")
        })
        .map(str::to_owned)
        .collect()
}

/// `Udp: InDatagrams` for this network namespace.
fn udp_in_datagrams() -> u64 {
    let snmp = std::fs::read_to_string("/proc/self/net/snmp").unwrap();
    let mut udp = snmp.lines().filter(|l| l.starts_with("Udp: "));
    let names: Vec<&str> = udp.next().unwrap().split_whitespace().collect();
    let values: Vec<&str> = udp.next().unwrap().split_whitespace().collect();
    let at = names.iter().position(|n| *n == "InDatagrams").unwrap();
    values[at].parse().unwrap()
}

#[test]
fn stop_sends_nothing_outside_the_policy_and_returns_within_the_step_timeout() {
    // The LAN policy forbids 127.0.0.1; long timers so only stop itself can wake the threads.
    let mut options = Options {
        policy: AddressPolicy::lan(),
        ..Options::default()
    };
    options.timing.rescan = Duration::from_secs(60);
    options.timing.announce = Duration::from_secs(60);
    let n = start(1, "A", options);
    std::thread::sleep(Duration::from_millis(100));
    let peer_port = n.peer_port;
    assert!(tcp_sockets_on(peer_port).is_empty());
    let datagrams = udp_in_datagrams();
    let begun = Instant::now();
    n.node.stop();
    let took = begun.elapsed();
    let sent = udp_in_datagrams() - datagrams;
    assert!(
        tcp_sockets_on(peer_port).is_empty(),
        "stop opened a TCP connection to 127.0.0.1: {:?}",
        tcp_sockets_on(peer_port)
    );
    assert_eq!(sent, 0, "stop sent a datagram (to 127.0.0.1)");
    assert!(took < Duration::from_millis(1500), "stop took {took:?}");
}
