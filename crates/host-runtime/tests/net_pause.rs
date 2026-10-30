//! X6: `NetRuntime::pause`/`resume`/`is_paused`/`set_interfaces` (additive, used only by the
//! Android app). Socket counts come from `/proc/self/fd`, so the tests of this file run one at
//! a time.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use device_link_net::interfaces::FakeInterfaces;
use host_runtime::log::Log;
use host_runtime::net_runtime::{NetRuntime, NetState};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn pause_closes_every_socket_and_resume_restores_the_node() {
    let _guard = serial();
    let before = socket_fds();
    let identity = MemoryIdentity::new(21);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert_eq!(net.state(), NetState::On);
    assert!(socket_fds() > before, "node opened sockets");
    assert!(!net.is_paused());

    net.pause();
    assert!(net.is_paused());
    assert!(
        wait_for(Duration::from_secs(1), || socket_fds() == before),
        "sockets still open: {} vs {before}",
        socket_fds()
    );
    // Identity stays in memory.
    assert!(net.this_device.is_some());
    assert!(net.snapshot().is_none());

    // A tick while paused never restarts the node.
    net.tick(Duration::from_secs(30));
    assert_eq!(socket_fds(), before);

    net.resume();
    assert!(!net.is_paused());
    assert_eq!(net.state(), NetState::On);
    assert!(net.snapshot().is_some());
    assert!(socket_fds() > before);
    net.stop();
    assert!(wait_for(Duration::from_secs(1), || socket_fds() == before));
}

#[test]
fn pins_survive_a_pause() {
    let _guard = serial();
    let identity = MemoryIdentity::new(22);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    let pins_before = identity.store.pins().len();
    net.pause();
    net.resume();
    assert_eq!(net.paired_count(), pins_before);
    assert_eq!(identity.store.pins().len(), pins_before);
    net.stop();
}

#[test]
fn set_interfaces_swaps_the_source_before_resume() {
    let _guard = serial();
    let identity = MemoryIdentity::new(23);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    net.pause();
    net.set_interfaces(Arc::new(FakeInterfaces::new(Vec::new())));
    net.resume();
    assert_eq!(net.state(), NetState::NoLocalNetwork);
    assert!(net.snapshot().is_none());
    // The key is still held, waiting for a network.
    assert!(net.key_held());
    net.set_interfaces(Arc::new(FakeInterfaces::loopback()));
    net.tick(Duration::from_secs(15));
    assert_eq!(net.state(), NetState::On);
    net.stop();
}

#[test]
fn a_runtime_that_is_never_paused_behaves_as_before() {
    let _guard = serial();
    let before = socket_fds();
    let identity = MemoryIdentity::new(24);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert!(!net.is_paused());
    assert_eq!(net.state(), NetState::On);
    net.stop();
    assert_eq!(net.state(), NetState::Off);
    assert!(!net.key_held());
    assert!(wait_for(Duration::from_secs(1), || socket_fds() == before));
    // pause/resume after stop do nothing.
    net.pause();
    net.resume();
    assert_eq!(net.state(), NetState::Off);
    assert!(!net.key_held());
}

#[test]
fn pin_count_reads_the_pins_while_paused() {
    let _guard = serial();
    let identity = MemoryIdentity::new(25);
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &identity, loopback_deps(), &log);
    assert_eq!(net.pin_count(), 0);
    let other = device_link::identity::DeviceKey::from_private([26; 32]);
    let pin = device_link::registry::PeerPin {
        public: *other.public(),
        name: device_link::name::DeviceName::parse("laptop").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    };
    // Saved while paused (a running node saves its own registry when it stops).
    net.pause();
    device_link::ports::PeerStore::save(identity.store.as_ref(), &[pin]).unwrap();
    assert_eq!(net.pin_count(), 1, "read from the store while paused");
    net.resume();
    assert_eq!(net.pin_count(), 1);
    net.stop();
    assert_eq!(net.pin_count(), 0, "nothing held after stop");
}
