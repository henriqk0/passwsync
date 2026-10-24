//! 003: networking does not weaken the 002 protections (FR-012, FR-025a obligations).

mod common;

use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use common::server::{Fixture, TestServer, free_net_port, net_config};
use serde_json::json;

fn net_threads() -> Vec<String> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .map(|c| c.trim().to_string())
        .filter(|c| c.starts_with("net-"))
        .collect()
}

/// One test so the thread and socket inventory of this process is not disturbed.
#[test]
fn network_threads_and_sockets_exist_only_when_enabled_and_never_resolve_names() {
    let off = TestServer::start();
    std::thread::sleep(Duration::from_millis(100));
    assert!(net_threads().is_empty(), "no network thread when off");
    assert!(
        common::inventory::sockets()
            .iter()
            .all(|s| s.proto == "tcp" && s.local.starts_with("127.0.0.1:")),
        "no network socket when off"
    );
    drop(off);

    let on = TestServer::start_with(&net_config());
    let threads = net_threads();
    assert!(threads.iter().any(|t| t == "net-accept"), "{threads:?}");
    assert!(threads.iter().any(|t| t == "net-discovery"), "{threads:?}");
    let socks = common::inventory::sockets();
    assert!(
        !socks.iter().any(|s| s.proto.ends_with('6')),
        "never an IPv6 socket: {socks:?}"
    );
    // Host names are refused before any lookup: the answer is immediate and the resolver is
    // never reached (the address parser accepts IPv4 literals only).
    let s = on.login();
    for address in [
        "printer.local:27472",
        "example.com:27472",
        "localhost:27472",
    ] {
        let body = json!({"address": address, "code": "12345678", "device_id": null});
        let started = Instant::now();
        let resp = on.api(&s, "POST", "/api/pairing/join", Some(&body.to_string()));
        assert_eq!(resp.status, 400);
        assert_eq!(resp.error_code(), "invalid_address");
        assert!(started.elapsed() < Duration::from_millis(500));
    }
    drop(on);
    std::thread::sleep(Duration::from_millis(200));
    assert!(net_threads().is_empty(), "network threads end on stop");
}

/// Runs the real binary with networking on, only where the hard memlock limit allows the
/// required 256 MiB (the 002 start-up test has the same guard).
#[test]
fn real_binary_with_networking_on_keeps_memory_locked_and_dumps_off() {
    let hard = rustix::process::getrlimit(rustix::process::Resource::Memlock).maximum;
    if hard.is_some_and(|h| h < 256 * 1024 * 1024) {
        eprintln!("skipped: hard RLIMIT_MEMLOCK below 256 MiB");
        return;
    }
    let fx = Fixture::new(&format!(
        "network = on\npeer_port = {}\ndiscovery_port = {}\n",
        free_net_port(),
        free_net_port()
    ));
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("ulimit -l 262144 && exec \"$0\"")
        .arg(env!("CARGO_BIN_EXE_passwsyncd"))
        .env_clear()
        .env("HOME", &fx.home)
        .env("XDG_RUNTIME_DIR", fx.root.path().join("run"))
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if fx.launch_file.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let pid = child.id();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let limits = fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let environ = fs::read(format!("/proc/{pid}/environ"));
    let tasks: Vec<String> = fs::read_dir(format!("/proc/{pid}/task"))
        .map(|dir| {
            dir.filter_map(|t| fs::read_to_string(t.ok()?.path().join("comm")).ok())
                .map(|c| c.trim().to_string())
                .collect()
        })
        .unwrap_or_default();
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    let exit = child.wait().unwrap();
    assert_eq!(exit.code(), Some(0));
    let locked = status.lines().find(|l| l.starts_with("VmLck:")).unwrap();
    assert_ne!(locked.split_whitespace().nth(1), Some("0"), "{locked}");
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max core file size") && l.contains(" 0 "))
    );
    assert!(
        environ.is_err(),
        "non-dumpable: /proc/<pid>/environ is not readable"
    );
    // Thread names can only be read while dumpable; when readable, the network runs.
    if !tasks.is_empty() {
        assert!(tasks.iter().any(|t| t == "net-accept"), "{tasks:?}");
    }
}
