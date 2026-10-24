//! Interface selection (research R8/R9).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use device_link::policy::AddressPolicy;
use device_link_net::interfaces::{
    FakeInterfaces, Interface, InterfaceSource, OsInterfaces, RawInterface, select,
};

fn raw(name: &str, addr: &str, mask: &str) -> RawInterface {
    RawInterface {
        name: name.to_string(),
        addr: addr.parse().unwrap(),
        netmask: mask.parse().unwrap(),
    }
}

fn sample() -> Vec<RawInterface> {
    vec![
        raw("lo", "127.0.0.1", "255.0.0.0"),
        raw("wlan0", "192.168.1.5", "255.255.255.0"),
        raw("eth0", "8.8.4.4", "255.255.255.0"),
        raw("eth1", "169.254.10.20", "255.255.0.0"),
        raw("docker0", "172.17.0.1", "255.255.0.0"),
        RawInterface {
            name: "wlan0".into(),
            addr: IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
            netmask: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        raw("bad name!", "10.0.0.2", "255.0.0.0"),
    ]
}

#[test]
fn keeps_ipv4_private_and_link_local_drops_loopback_public_ipv6() {
    let selected = select(&sample(), AddressPolicy::lan(), None);
    let names: Vec<&str> = selected.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["wlan0", "eth1", "docker0"]);
    let wlan = &selected[0];
    assert_eq!(wlan.addr, Ipv4Addr::new(192, 168, 1, 5));
    assert_eq!(wlan.prefix, 24);
    assert_eq!(wlan.broadcast, Ipv4Addr::new(192, 168, 1, 255));
    assert_eq!(selected[1].broadcast, Ipv4Addr::new(169, 254, 255, 255));
    assert_eq!(selected[1].prefix, 16);
}

#[test]
fn testkit_policy_keeps_loopback() {
    let selected = select(&sample(), AddressPolicy::testkit(), None);
    assert_eq!(selected[0].name.as_str(), "lo");
    assert_eq!(selected[0].broadcast, Ipv4Addr::new(127, 255, 255, 255));
    assert_eq!(selected[0].prefix, 8);
}

#[test]
fn network_interface_setting_filters_to_one_name() {
    let selected = select(&sample(), AddressPolicy::lan(), Some("docker0"));
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].name.as_str(), "docker0");
    assert!(select(&sample(), AddressPolicy::lan(), Some("nothere")).is_empty());
}

#[test]
fn subnet_membership_and_special_addresses() {
    let wlan = &select(&sample(), AddressPolicy::lan(), Some("wlan0"))[0];
    assert!(wlan.contains(Ipv4Addr::new(192, 168, 1, 7)));
    assert!(!wlan.contains(Ipv4Addr::new(192, 168, 2, 7)));
    assert!(wlan.is_network_or_broadcast(Ipv4Addr::new(192, 168, 1, 0)));
    assert!(wlan.is_network_or_broadcast(Ipv4Addr::new(192, 168, 1, 255)));
    assert!(!wlan.is_network_or_broadcast(Ipv4Addr::new(192, 168, 1, 7)));
}

#[test]
fn empty_selection_means_no_local_network() {
    let only_public = vec![
        raw("lo", "127.0.0.1", "255.0.0.0"),
        raw("eth0", "8.8.4.4", "255.255.255.0"),
    ];
    assert!(select(&only_public, AddressPolicy::lan(), None).is_empty());
}

#[test]
fn os_source_returns_only_policy_passing_ipv4() {
    let source = OsInterfaces::new(AddressPolicy::lan(), None);
    for interface in source.scan() {
        assert!(
            AddressPolicy::lan().allows_v4(interface.addr),
            "{interface:?}"
        );
        assert!(!interface.addr.is_loopback());
    }
}

#[test]
fn fake_source_can_change() {
    let fake = FakeInterfaces::loopback();
    assert_eq!(fake.scan().len(), 1);
    fake.set(vec![]);
    assert!(fake.scan().is_empty());
    let one: Vec<Interface> = select(&sample(), AddressPolicy::lan(), Some("wlan0"));
    fake.set(one.clone());
    assert_eq!(fake.scan(), one);
}
