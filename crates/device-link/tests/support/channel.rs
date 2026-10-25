//! Runs channel handshakes in memory.

use device_link::channel::{Channel, ChannelDialer, ChannelResponder};
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::wire::{HelloKind, parse_hello};

pub struct Ends {
    pub dialer: Channel,
    pub responder: Channel,
    /// Every frame on the wire, in order.
    pub wire: Vec<Vec<u8>>,
}

pub fn key(seed: u8) -> DeviceKey {
    DeviceKey::from_private([seed; 32])
}

pub fn name(text: &str) -> DeviceName {
    DeviceName::parse(text).unwrap()
}

/// Runs a full handshake between `a` (dialer) and `b` (responder, which pins `a`).
pub fn connect(a: &DeviceKey, b: &DeviceKey) -> Ends {
    let mut wire = Vec::new();
    let mut dialer = ChannelDialer::start(a, *b.public(), name("Laptop")).unwrap();
    let out = dialer.outgoing();
    assert_eq!(out.len(), 2, "Hello and msg1");
    assert_eq!(parse_hello(&out[0]).unwrap(), HelloKind::Channel);
    wire.extend(out.clone());
    let mut responder = ChannelResponder::new(b, name("Phone"), &out[0]);
    let pinned = *a.public();
    let is_pinned = move |k: &[u8; 32]| *k == pinned;
    assert!(responder.on_frame(&out[1], &is_pinned).unwrap().is_none());
    let msg2 = responder.outgoing();
    assert_eq!(msg2.len(), 1);
    wire.extend(msg2.clone());
    assert!(dialer.on_frame(&msg2[0]).unwrap().is_none());
    let msg3 = dialer.outgoing();
    wire.extend(msg3.clone());
    let responder_channel = responder.on_frame(&msg3[0], &is_pinned).unwrap().unwrap();
    let welcome = responder.outgoing();
    wire.extend(welcome.clone());
    let dialer_channel = dialer.on_frame(&welcome[0]).unwrap().unwrap();
    Ends {
        dialer: dialer_channel,
        responder: responder_channel,
        wire,
    }
}

/// 004: a full channel handshake with Hello version 2 (sync-enabled channel).
pub fn connect_v2(a: &DeviceKey, b: &DeviceKey) -> Ends {
    use device_link::wire::{HelloVersion, parse_hello_versioned};
    let mut wire = Vec::new();
    let mut dialer =
        ChannelDialer::start_version(a, *b.public(), name("Laptop"), HelloVersion::V2).unwrap();
    let out = dialer.outgoing();
    assert_eq!(out.len(), 2, "Hello and msg1");
    assert_eq!(
        parse_hello_versioned(&out[0]).unwrap(),
        (HelloKind::Channel, HelloVersion::V2)
    );
    wire.extend(out.clone());
    let mut responder = ChannelResponder::new(b, name("Phone"), &out[0]);
    let pinned = *a.public();
    let is_pinned = move |k: &[u8; 32]| *k == pinned;
    assert!(responder.on_frame(&out[1], &is_pinned).unwrap().is_none());
    let msg2 = responder.outgoing();
    wire.extend(msg2.clone());
    assert!(dialer.on_frame(&msg2[0]).unwrap().is_none());
    let msg3 = dialer.outgoing();
    wire.extend(msg3.clone());
    let responder_channel = responder.on_frame(&msg3[0], &is_pinned).unwrap().unwrap();
    let welcome = responder.outgoing();
    wire.extend(welcome.clone());
    let dialer_channel = dialer.on_frame(&welcome[0]).unwrap().unwrap();
    Ends {
        dialer: dialer_channel,
        responder: responder_channel,
        wire,
    }
}
