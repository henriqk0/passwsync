mod common;

use std::fs;
use std::net::TcpListener;
use std::process::Command;

use common::mode;
use common::server::{Fixture, TestServer};
use passwsyncd::app::start;
use passwsyncd::hardening::FakeHardening;

fn binary(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_passwsyncd"))
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

#[test]
fn help_and_version_exit_0_before_anything_else() {
    let help = binary(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: passwsyncd"));
    let version = binary(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&version.stdout),
        format!("passwsyncd {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn invalid_arguments_print_usage_and_exit_2() {
    for args in [
        &["--port=1"][..],
        &["x"],
        &["--help", "--version"],
        &["--no-mlock"],
    ] {
        let out = binary(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage: passwsyncd"));
    }
}

#[test]
fn second_instance_exits_4() {
    let server = TestServer::start();
    let fx2 = Fixture {
        root: common::TempDir::new("unused"),
        port: server.fx.port,
        home: server.fx.home.clone(),
        config_dir: server.fx.config_dir.clone(),
        wallets_dir: server.fx.wallets_dir.clone(),
        runtime_dir: server.fx.runtime_dir.clone(),
        launch_file: server.fx.launch_file.clone(),
    };
    let mut env = fx2.env();
    env.xdg_runtime_dir = server.fx.env().xdg_runtime_dir;
    let (mut deps, log, _) = fx2.deps(FakeHardening::ok());
    deps.env = env;
    let error = start(deps).err().expect("second instance must fail");
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("already running"), "{error}");
    drop(log);
    // The first instance is unaffected.
    assert!(server.launch_url().starts_with("http://127.0.0.1:"));
}

#[test]
fn busy_port_exits_4() {
    let fx = Fixture::new("");
    let _busy = TcpListener::bind(("127.0.0.1", fx.port)).unwrap();
    let (deps, _, _) = fx.deps(FakeHardening::ok());
    let error = start(deps).err().expect("busy port must fail");
    assert_eq!(error.exit_code(), 4);
    assert!(!fx.launch_file.exists());
}

#[test]
fn config_errors_exit_2() {
    let fx = Fixture::new("auto_lock_minutes = 0\n");
    let (deps, _, _) = fx.deps(FakeHardening::ok());
    let error = start(deps).err().expect("bad config must fail");
    assert_eq!(error.exit_code(), 2);
    assert_eq!(
        error.to_string(),
        "config: auto_lock_minutes: must be 1..=240"
    );
}

#[test]
fn missing_runtime_dir_exits_2() {
    let fx = Fixture::new("");
    let (mut deps, _, _) = fx.deps(FakeHardening::ok());
    deps.env.xdg_runtime_dir = None;
    let error = start(deps).err().expect("must fail");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn listener_is_bound_to_ipv4_loopback_only() {
    let server = TestServer::start();
    assert_eq!(server.running().addr().ip().to_string(), "127.0.0.1");
    let port = format!("{:04X}", server.port);
    let table = fs::read_to_string("/proc/net/tcp").unwrap();
    let listening: Vec<&str> = table
        .lines()
        .filter(|l| l.split_whitespace().nth(3) == Some("0A"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter(|a| a.ends_with(&format!(":{port}")))
        .collect();
    assert_eq!(listening, [format!("0100007F:{port}")]);
    let table6 = fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    assert!(!table6.lines().any(|l| {
        l.split_whitespace().nth(3) == Some("0A")
            && l.split_whitespace()
                .nth(1)
                .is_some_and(|a| a.ends_with(&format!(":{port}")))
    }));
}

#[test]
fn launch_file_is_private_holds_only_the_url_and_is_deleted_on_stop() {
    let mut server = TestServer::start();
    let file = server.fx.launch_file.clone();
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&server.fx.runtime_dir), 0o700);
    let text = fs::read_to_string(&file).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with(&format!("http://127.0.0.1:{}/launch/", server.port)));
    assert_eq!(
        text.len(),
        format!("http://127.0.0.1:{}/launch/", server.port).len() + 65
    );
    assert!(
        server
            .log_text()
            .contains(&format!("launch file {}", file.display()))
    );
    assert!(
        !server.log_text().contains(text.trim_end()),
        "token never logged"
    );
    assert_eq!(server.stop(), 0);
    assert!(!file.exists());
    assert!(server.log_text().contains("stopping"));
}

#[test]
fn device_id_is_created_on_first_run_and_reused() {
    let mut server = TestServer::start();
    let path = server.fx.config_dir.join("device-id");
    let first = fs::read_to_string(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    let fx = std::mem::replace(&mut server.fx, Fixture::new(""));
    server.stop();
    let again = TestServer::start_in(fx);
    assert_eq!(fs::read_to_string(&path).unwrap(), first);
    drop(again);
}

/// Runs the real binary end to end only where the hard memlock limit allows the required
/// 256 MiB (it does not in every CI or desktop session; the in-process tests cover the rest).
#[test]
fn real_binary_starts_when_the_memlock_limit_allows() {
    let hard = rustix::process::getrlimit(rustix::process::Resource::Memlock).maximum;
    if hard.is_some_and(|h| h < 256 * 1024 * 1024) {
        eprintln!("skipped: hard RLIMIT_MEMLOCK below 256 MiB");
        return;
    }
    let fx = Fixture::new("");
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
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let status_text = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    let limits = fs::read_to_string(format!("/proc/{}/limits", child.id())).unwrap();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(!fx.launch_file.exists());
    let locked = status_text
        .lines()
        .find(|l| l.starts_with("VmLck:"))
        .unwrap();
    assert_ne!(locked.split_whitespace().nth(1), Some("0"), "{locked}");
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max core file size") && l.contains(" 0 "))
    );
}
