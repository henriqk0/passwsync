use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use device_link::policy::AddressPolicy;

fn v4(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

#[test]
fn lan_policy_accepts_private_and_link_local() {
    let policy = AddressPolicy::lan();
    for ip in [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.5",
        "169.254.10.20",
    ] {
        assert!(policy.allows_v4(v4(ip)), "{ip}");
        assert!(policy.allows(IpAddr::V4(v4(ip))), "{ip}");
    }
}

#[test]
fn lan_policy_rejects_everything_else() {
    let policy = AddressPolicy::lan();
    for ip in [
        "127.0.0.1",
        "127.1.2.3",
        "8.8.8.8",
        "172.15.255.255",
        "172.32.0.1",
        "192.169.0.1",
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "0.0.0.0",
        "100.64.0.1",
    ] {
        assert!(!policy.allows_v4(v4(ip)), "{ip}");
    }
    for ip in [
        Ipv6Addr::LOCALHOST,
        "fe80::1".parse().unwrap(),
        "fd00::1".parse().unwrap(),
    ] {
        assert!(!policy.allows(IpAddr::V6(ip)), "{ip}");
    }
    let mapped: Ipv6Addr = "::ffff:192.168.1.5".parse().unwrap();
    assert!(!policy.allows(IpAddr::V6(mapped)), "IPv6 of any kind");
}

#[test]
fn testkit_policy_adds_only_loopback() {
    let policy = AddressPolicy::testkit();
    assert!(policy.allows_v4(v4("127.0.0.1")));
    assert!(policy.allows_v4(v4("127.0.0.2")));
    assert!(policy.allows_v4(v4("192.168.1.5")));
    assert!(!policy.allows_v4(v4("8.8.8.8")));
    assert!(!policy.allows_v4(v4("0.0.0.0")));
    assert!(!policy.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!AddressPolicy::lan().allows_v4(v4("127.0.0.1")));
}
