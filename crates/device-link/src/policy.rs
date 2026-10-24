//! Which peer addresses may be talked to (research R9): IPv4 private and link-local only.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressPolicy {
    loopback: bool,
}

impl AddressPolicy {
    /// 10/8, 172.16/12, 192.168/16, 169.254/16.
    pub const fn lan() -> Self {
        Self { loopback: false }
    }

    /// Automated tests only: the LAN ranges plus 127.0.0.0/8. Not compiled without the
    /// `testkit` feature.
    #[cfg(feature = "testkit")]
    pub const fn testkit() -> Self {
        Self { loopback: true }
    }

    pub fn allows_loopback(&self) -> bool {
        self.loopback
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.allows_v4(v4),
            IpAddr::V6(_) => false,
        }
    }

    pub fn allows_v4(&self, ip: Ipv4Addr) -> bool {
        (ip.is_private() || ip.is_link_local()) || (self.loopback && ip.is_loopback())
    }
}
