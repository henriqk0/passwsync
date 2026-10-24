//! Discovery datagram codec and the bounded nearby list (contracts/peer-protocol.md,
//! FR-014..FR-016).

use std::net::SocketAddrV4;
use std::time::Duration;

use device_link::discovery::{
    ANNOUNCE_LEN, MAX_NEARBY, NearbyList, decode_announce, encode_announce,
};
use device_link::error::DropReason;
use device_link::identity::DeviceId;
use device_link::policy::AddressPolicy;

const S: fn(u64) -> Duration = Duration::from_secs;

fn id(byte: u8) -> DeviceId {
    DeviceId::from_bytes([byte; 32])
}

fn src(last: u8) -> SocketAddrV4 {
    SocketAddrV4::new([192, 168, 1, last].into(), 40000)
}

#[test]
fn announcements_are_exactly_39_bytes_with_magic_version_id_port() {
    assert_eq!(ANNOUNCE_LEN, 39);
    let packet = encode_announce(&id(7), 27472);
    assert_eq!(&packet[..5], b"PWSD\x01");
    assert_eq!(&packet[5..37], &[7u8; 32]);
    assert_eq!(&packet[37..], &27472u16.to_be_bytes());
    assert_eq!(decode_announce(&packet, &id(1)), Ok((id(7), 27472)));
}

#[test]
fn malformed_datagrams_are_ignored_and_counted() {
    let good = encode_announce(&id(7), 27472);
    let mut cases: Vec<Vec<u8>> = vec![good[..38].to_vec(), [&good[..], &[0]].concat()];
    let mut magic = good;
    magic[0] = b'X';
    cases.push(magic.to_vec());
    let mut version = good;
    version[4] = 2;
    cases.push(version.to_vec());
    cases.push(encode_announce(&id(7), 1023).to_vec());
    cases.push(encode_announce(&id(7), 0).to_vec());
    cases.push(Vec::new());
    for bytes in cases {
        assert_eq!(
            decode_announce(&bytes, &id(1)),
            Err(DropReason::Malformed),
            "{bytes:?}"
        );
    }
    // Our own announcement is ignored too.
    assert_eq!(
        decode_announce(&encode_announce(&id(1), 27472), &id(1)),
        Err(DropReason::Malformed)
    );
}

#[test]
fn nearby_list_is_bounded_expires_and_updates() {
    let mut list = NearbyList::new(S(90), AddressPolicy::lan());
    assert_eq!(MAX_NEARBY, 64);
    for i in 0..64u8 {
        list.observe(id(i), src(1), 27472, S(0), false).unwrap();
    }
    assert_eq!(
        list.observe(id(200), src(2), 27472, S(0), false),
        Err(DropReason::Overflow),
        "the 65th is dropped"
    );
    assert_eq!(list.len(), 64);
    // A re-announcement updates address and time without growing the list.
    list.observe(id(3), src(9), 30000, S(60), false).unwrap();
    assert_eq!(list.len(), 64);
    let entry = list
        .views(S(60), |_| false)
        .into_iter()
        .find(|v| v.id == id(3))
        .unwrap();
    assert_eq!(
        entry.addr,
        SocketAddrV4::new([192, 168, 1, 9].into(), 30000)
    );
    // Entries expire 90 s after they were last heard.
    list.expire(S(89));
    assert_eq!(list.len(), 64);
    list.expire(S(90));
    assert_eq!(list.len(), 1, "only the refreshed entry remains");
    list.expire(S(150));
    assert_eq!(list.len(), 0);
}

#[test]
fn paired_flag_comes_from_the_registry_and_paired_peers_do_not_use_the_64_slots() {
    let mut list = NearbyList::new(S(90), AddressPolicy::lan());
    for i in 0..64u8 {
        list.observe(id(i), src(1), 27472, S(0), false).unwrap();
    }
    // A paired peer is still recorded although the list is full.
    list.observe(id(250), src(5), 27472, S(0), true).unwrap();
    let views = list.views(S(0), |candidate| {
        *candidate == id(250) || *candidate == id(1)
    });
    assert_eq!(views.len(), 65);
    assert!(views.iter().find(|v| v.id == id(250)).unwrap().paired);
    assert!(views.iter().find(|v| v.id == id(1)).unwrap().paired);
    assert!(!views.iter().find(|v| v.id == id(2)).unwrap().paired);
}

#[test]
fn sources_failing_the_policy_are_dropped_as_public() {
    let mut list = NearbyList::new(S(90), AddressPolicy::lan());
    let public = SocketAddrV4::new([8, 8, 8, 8].into(), 40000);
    assert_eq!(
        list.observe(id(1), public, 27472, S(0), false),
        Err(DropReason::Public)
    );
    let loopback = SocketAddrV4::new([127, 0, 0, 1].into(), 40000);
    assert_eq!(
        list.observe(id(1), loopback, 27472, S(0), false),
        Err(DropReason::Public)
    );
    assert_eq!(list.len(), 0);
}
