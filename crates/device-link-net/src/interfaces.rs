//! Which interfaces are in use (research R8): IPv4 addresses passing the address policy,
//! optionally only the configured one.

use std::net::{IpAddr, Ipv4Addr};
#[cfg(feature = "testkit")]
use std::sync::{Mutex, PoisonError};

use device_link::name::InterfaceName;
use device_link::policy::AddressPolicy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: InterfaceName,
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub broadcast: Ipv4Addr,
}

impl Interface {
    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr) & self.mask()
    }

    pub fn is_network_or_broadcast(&self, ip: Ipv4Addr) -> bool {
        let network = u32::from(self.addr) & self.mask();
        let raw = u32::from(ip);
        self.prefix < 31 && (raw == network || raw == network | !self.mask())
    }
}

/// An address as reported by the OS.
#[derive(Clone, Debug)]
pub struct RawInterface {
    pub name: String,
    pub addr: IpAddr,
    pub netmask: IpAddr,
}

pub fn select(raw: &[RawInterface], policy: AddressPolicy, only: Option<&str>) -> Vec<Interface> {
    let mut out = Vec::new();
    for entry in raw {
        let (IpAddr::V4(addr), IpAddr::V4(mask)) = (entry.addr, entry.netmask) else {
            continue;
        };
        if !policy.allows_v4(addr) || only.is_some_and(|name| name != entry.name) {
            continue;
        }
        let Ok(name) = InterfaceName::parse(&entry.name) else {
            continue;
        };
        let mask = u32::from(mask);
        let prefix = mask.leading_ones() as u8;
        if mask.count_ones() != u32::from(prefix) {
            continue; // non-contiguous netmask
        }
        let broadcast = Ipv4Addr::from(u32::from(addr) | !mask);
        out.push(Interface {
            name,
            addr,
            prefix,
            broadcast,
        });
    }
    out
}

pub trait InterfaceSource: Send + Sync {
    fn scan(&self) -> Vec<Interface>;
}

/// `getifaddrs` through `if-addrs`.
pub struct OsInterfaces {
    policy: AddressPolicy,
    only: Option<String>,
}

impl OsInterfaces {
    pub fn new(policy: AddressPolicy, only: Option<String>) -> Self {
        Self { policy, only }
    }
}

impl InterfaceSource for OsInterfaces {
    fn scan(&self) -> Vec<Interface> {
        let Ok(list) = if_addrs::get_if_addrs() else {
            return Vec::new();
        };
        let raw: Vec<RawInterface> = list
            .into_iter()
            .filter_map(|i| match i.addr {
                if_addrs::IfAddr::V4(v4) => Some(RawInterface {
                    name: i.name,
                    addr: IpAddr::V4(v4.ip),
                    netmask: IpAddr::V4(v4.netmask),
                }),
                if_addrs::IfAddr::V6(_) => None,
            })
            .collect();
        select(&raw, self.policy, self.only.as_deref())
    }
}

/// Settable interface list for tests (feature `testkit`).
#[cfg(feature = "testkit")]
pub struct FakeInterfaces(Mutex<Vec<Interface>>);

#[cfg(feature = "testkit")]
impl FakeInterfaces {
    pub fn new(list: Vec<Interface>) -> Self {
        Self(Mutex::new(list))
    }

    /// `lo 127.0.0.1/8`, broadcast `127.255.255.255`.
    pub fn loopback() -> Self {
        Self::new(vec![Interface {
            name: InterfaceName::parse("lo").unwrap_or_else(|_| unreachable!()),
            addr: Ipv4Addr::LOCALHOST,
            prefix: 8,
            broadcast: Ipv4Addr::new(127, 255, 255, 255),
        }])
    }

    pub fn set(&self, list: Vec<Interface>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = list;
    }
}

#[cfg(feature = "testkit")]
impl InterfaceSource for FakeInterfaces {
    fn scan(&self) -> Vec<Interface> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
