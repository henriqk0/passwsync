#![forbid(unsafe_code)]
//! Eligible interfaces (data-model.md section 8, FR-039): the OS scan, already restricted by
//! the 003 private/link-local policy, filtered by the names Kotlin's `NetworkClassifier`
//! marked as local Wi-Fi or Ethernet. An empty set is "no local network".

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError, RwLock};

use device_link::name::InterfaceName;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::{Interface, InterfaceSource, OsInterfaces};

/// The interface source handed to `NetRuntime::set_interfaces`.
pub struct EligibleInterfaces {
    names: RwLock<BTreeSet<InterfaceName>>,
    inner: Arc<dyn InterfaceSource>,
    /// Addresses outside this policy are never used (003 FR-011), whatever the source says.
    policy: Option<AddressPolicy>,
    /// The optional `network_interface` setting.
    only: Option<InterfaceName>,
}

impl EligibleInterfaces {
    /// Over the OS interfaces under `policy` (003 private/link-local rules).
    pub fn new(policy: AddressPolicy, only: Option<InterfaceName>) -> Self {
        let os = OsInterfaces::new(policy, only.as_ref().map(|n| n.as_str().to_owned()));
        Self::over(Arc::new(os), policy, only)
    }

    /// Over any source, restricted by `policy`.
    pub fn over(
        inner: Arc<dyn InterfaceSource>,
        policy: AddressPolicy,
        only: Option<InterfaceName>,
    ) -> Self {
        Self {
            names: RwLock::new(BTreeSet::new()),
            inner,
            policy: Some(policy),
            only,
        }
    }

    /// Over any source (tests); starts with no eligible name.
    pub fn with_inner(inner: Box<dyn InterfaceSource>, only: Option<InterfaceName>) -> Self {
        Self {
            names: RwLock::new(BTreeSet::new()),
            inner: Arc::from(inner),
            policy: None,
            only,
        }
    }

    /// Replaces the eligible set; names that are not valid interface names are ignored.
    pub fn set_names(&self, names: &[String]) {
        let set = names
            .iter()
            .filter_map(|n| InterfaceName::parse(n).ok())
            .collect();
        *self.names.write().unwrap_or_else(PoisonError::into_inner) = set;
    }

    /// No eligible name at all ("no local network").
    pub fn is_empty(&self) -> bool {
        self.names
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }
}

impl InterfaceSource for EligibleInterfaces {
    fn scan(&self) -> Vec<Interface> {
        let names = self.names.read().unwrap_or_else(PoisonError::into_inner);
        if names.is_empty() {
            return Vec::new();
        }
        self.inner
            .scan()
            .into_iter()
            .filter(|i| names.contains(&i.name))
            .filter(|i| self.only.as_ref().is_none_or(|only| *only == i.name))
            .filter(|i| self.policy.is_none_or(|policy| policy.allows_v4(i.addr)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use device_link::name::InterfaceName;
    use device_link_net::interfaces::{Interface, InterfaceSource};

    use super::EligibleInterfaces;

    struct Fixed(Vec<Interface>);

    impl InterfaceSource for Fixed {
        fn scan(&self) -> Vec<Interface> {
            self.0.clone()
        }
    }

    fn iface(name: &str, last: u8) -> Interface {
        Interface {
            name: InterfaceName::parse(name).unwrap(),
            addr: Ipv4Addr::new(192, 168, last, 10),
            prefix: 24,
            broadcast: Ipv4Addr::new(192, 168, last, 255),
        }
    }

    fn inner() -> Box<dyn InterfaceSource> {
        Box::new(Fixed(vec![
            iface("wlan0", 1),
            iface("eth0", 2),
            iface("rmnet0", 3),
        ]))
    }

    fn names(scan: &[Interface]) -> Vec<&str> {
        scan.iter().map(|i| i.name.as_str()).collect()
    }

    fn set(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scan_is_the_inner_scan_filtered_by_the_names() {
        let eligible = EligibleInterfaces::with_inner(inner(), None);
        eligible.set_names(&set(&["wlan0", "eth0"]));
        assert_eq!(names(&eligible.scan()), ["wlan0", "eth0"]);
    }

    #[test]
    fn an_empty_set_is_no_local_network() {
        let eligible = EligibleInterfaces::with_inner(inner(), None);
        assert!(eligible.scan().is_empty(), "starts empty");
        eligible.set_names(&set(&["wlan0"]));
        eligible.set_names(&[]);
        assert!(eligible.scan().is_empty());
    }

    #[test]
    fn the_network_interface_setting_narrows_further() {
        let only = InterfaceName::parse("eth0").unwrap();
        let eligible = EligibleInterfaces::with_inner(inner(), Some(only));
        eligible.set_names(&set(&["wlan0", "eth0"]));
        assert_eq!(names(&eligible.scan()), ["eth0"]);
        eligible.set_names(&set(&["wlan0"]));
        assert!(
            eligible.scan().is_empty(),
            "setting names an ineligible one"
        );
    }

    #[test]
    fn a_swap_is_visible_to_the_next_scan_through_a_shared_source() {
        let eligible = Arc::new(EligibleInterfaces::with_inner(inner(), None));
        let source: Arc<dyn InterfaceSource> = eligible.clone();
        eligible.set_names(&set(&["wlan0"]));
        assert_eq!(names(&source.scan()), ["wlan0"]);
        eligible.set_names(&set(&["eth0"]));
        assert_eq!(names(&source.scan()), ["eth0"]);
    }

    #[test]
    fn invalid_names_are_ignored() {
        let eligible = EligibleInterfaces::with_inner(inner(), None);
        eligible.set_names(&set(&[
            "",
            "way-too-long-interface-name",
            "wlan0",
            "bad name",
        ]));
        assert_eq!(names(&eligible.scan()), ["wlan0"]);
        assert!(!eligible.is_empty());
    }
}
