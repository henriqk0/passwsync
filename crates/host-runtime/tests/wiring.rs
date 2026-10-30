//! Identity seam of `NetRuntime::start` (contract section 3.1) and the `HostCore` golden test
//! (X5, contract section 3.4).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use device_link::identity::DeviceKey;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::FakeInterfaces;
use host_runtime::config::NetworkSettings;
use host_runtime::log::Log;
use host_runtime::net_runtime::{NetDeps, NetRuntime, NetState};

// --- part 1: identity seam ---

#[test]
fn net_deps_keeps_exactly_its_five_public_fields() {
    let _deps = NetDeps {
        policy: AddressPolicy::testkit(),
        interfaces: Some(Arc::new(FakeInterfaces::loopback())),
        timing: fast_timing(),
        announce_ports: Vec::new(),
        sync: fast_sync_timing(),
    };
    let _ = NetDeps::production();
}

#[test]
fn start_with_a_memory_identity_runs_the_node_on_its_key_and_store() {
    let identity = MemoryIdentity::new(7);
    let (log, buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert_eq!(net.state(), NetState::On);
    let expected = DeviceKey::from_private([7; 32]).id();
    assert_eq!(net.this_device.as_ref().unwrap().id, expected);
    assert!(net.key_held());
    // The registry was loaded from the fake's store.
    assert_eq!(net.paired_count(), 0);
    net.stop();
    let text = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(text.contains("passwsyncd: network on"), "{text}");
}

#[test]
fn networking_off_reads_the_identity_but_starts_nothing() {
    let identity = MemoryIdentity::new(8);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(NetworkSettings::default(), &identity, loopback_deps(), &log);
    assert_eq!(net.state(), NetState::Off);
    assert!(net.this_device.is_some());
    assert!(!net.key_held());
}

#[test]
fn an_unusable_identity_gives_identity_unusable() {
    let mut identity = MemoryIdentity::new(9);
    identity.key = None;
    let (log, buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert_eq!(net.state(), NetState::IdentityUnusable);
    assert!(net.this_device.is_none());
    let text = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(text.contains("identity"), "{text}");
}

#[test]
fn unusable_pins_give_peers_unusable() {
    let mut identity = MemoryIdentity::new(10);
    identity.peers_ok = false;
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert_eq!(net.state(), NetState::PeersUnusable);
    assert!(!net.key_held());
}

#[test]
fn ticking_a_running_runtime_is_harmless() {
    let identity = MemoryIdentity::new(11);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    net.tick(Duration::from_secs(1));
    assert_eq!(net.state(), NetState::On);
    net.stop();
    assert_eq!(net.state(), NetState::Off);
}

// --- part 2: HostCore golden test (X5) ---

use host_runtime::config::Settings;
use host_runtime::wiring::{HostCore, HostDirs, sweep_locks};
use vault_core::{DeviceId, KdfConfig};
use wallet_service::ServiceConfig;
use wallet_service::testkit::FakeElapsedClock;
use zeroize::Zeroizing;

const PW: &str = "correct horse battery";

struct Host {
    _root: TempDir,
    dirs: HostDirs,
}

fn host() -> Host {
    let root = TempDir::new("wiring");
    let dirs = HostDirs {
        wallets: root.path().join("wallets"),
        sync: root.path().join("sync"),
        received: root.path().join("received"),
    };
    for dir in [&dirs.wallets, &dirs.sync, &dirs.received] {
        std::fs::create_dir(dir).unwrap();
        set_mode(dir, 0o700);
    }
    Host { _root: root, dirs }
}

fn service_config(auto_lock: Duration) -> ServiceConfig {
    ServiceConfig {
        device: DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
        wallet_kdf: KdfConfig::MINIMUM,
        auto_lock,
    }
}

fn lines(buffer: &std::sync::Mutex<Vec<u8>>) -> Vec<String> {
    String::from_utf8(buffer.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn networking_off_logs_exactly_network_off_and_creates_nothing() {
    let h = host();
    let (log, buffer) = Log::to_buffer();
    let clock = Arc::new(FakeElapsedClock::new());
    let core = HostCore::assemble(
        &h.dirs,
        &Settings::default(),
        &MemoryIdentity::new(1),
        loopback_deps(),
        service_config(Duration::from_secs(900)),
        clock,
        &log,
    );
    // Golden line copied from passwsyncd 006 (tests/network_off.rs: "network off").
    assert_eq!(lines(&buffer), vec!["passwsyncd: network off".to_string()]);
    assert!(!core.net.key_held());
    for dir in [&h.dirs.wallets, &h.dirs.sync, &h.dirs.received] {
        assert!(
            entries(dir).is_empty(),
            "{}: {:?}",
            dir.display(),
            entries(dir)
        );
    }
    core.share.shutdown();
    core.sync.stop();
    core.net.stop();
}

#[test]
fn networking_on_starts_the_node_then_sync_and_the_service_saves_through_the_journal() {
    let h = host();
    let (log, buffer) = Log::to_buffer();
    let settings = Settings {
        network: net_on(),
        ..Settings::default()
    };
    let (peer, discovery) = (settings.network.peer_port, settings.network.discovery_port);
    let clock = Arc::new(FakeElapsedClock::new());
    let core = HostCore::assemble(
        &h.dirs,
        &settings,
        &MemoryIdentity::new(2),
        loopback_deps(),
        service_config(Duration::from_secs(900)),
        clock,
        &log,
    );
    assert_eq!(
        lines(&buffer).first().map(String::as_str),
        Some(
            format!("passwsyncd: network on peer={peer} discovery={discovery} interfaces=lo")
                .as_str()
        )
    );
    assert!(core.net.key_held());
    // The service saves through JournalingDirectory over FsWalletDirectory.
    core.service
        .create(
            "Personal",
            Zeroizing::new(PW.into()),
            Zeroizing::new(PW.into()),
        )
        .unwrap();
    assert!(!entries(&h.dirs.wallets).is_empty());
    core.tick(Duration::from_secs(15));
    core.share.shutdown();
    core.sync.stop();
    core.net.stop();
}

#[test]
fn sweep_locks_logs_idle_and_suspend_locks() {
    let h = host();
    let (log, buffer) = Log::to_buffer();
    let clock = Arc::new(FakeElapsedClock::new());
    let core = HostCore::assemble(
        &h.dirs,
        &Settings::default(),
        &MemoryIdentity::new(3),
        loopback_deps(),
        service_config(Duration::from_secs(60)),
        Arc::clone(&clock) as Arc<dyn wallet_service::ElapsedClock>,
        &log,
    );
    let name = core
        .service
        .create(
            "Personal",
            Zeroizing::new(PW.into()),
            Zeroizing::new(PW.into()),
        )
        .unwrap();
    core.service
        .unlock(&name, Zeroizing::new(PW.into()))
        .unwrap();
    clock.advance(Duration::from_secs(61));
    sweep_locks(&core.service, &log);
    assert!(
        lines(&buffer).contains(&"passwsyncd: locked Personal (idle)".to_string()),
        "{:?}",
        lines(&buffer)
    );
    core.service
        .unlock(&name, Zeroizing::new(PW.into()))
        .unwrap();
    clock.suspend(Duration::from_secs(60));
    sweep_locks(&core.service, &log);
    let all = lines(&buffer);
    let at = all
        .iter()
        .position(|l| l == "passwsyncd: suspend detected")
        .expect("suspend line");
    assert_eq!(all[at + 1], "passwsyncd: locked Personal (suspend)");
    core.share.shutdown();
    core.sync.stop();
    core.net.stop();
}
