//! 004 T006: the wallet-level state vector (data-model.md "StateVector").

use vault_core::{DeviceId, StateVector, VaultError, VersionOrdering};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(pairs.iter().map(|(n, c)| (d(n), *c)).collect()).unwrap()
}

#[test]
fn empty_vector_reads_zero_everywhere() {
    let empty = StateVector::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.get(&d("a")), 0);
    assert_eq!(empty.iter().count(), 0);
}

#[test]
fn bump_adds_one_and_inserts_new_devices() {
    let mut v = StateVector::new();
    v.bump(&d("b")).unwrap();
    v.bump(&d("a")).unwrap();
    v.bump(&d("b")).unwrap();
    assert_eq!(v.get(&d("b")), 2);
    assert_eq!(v.get(&d("a")), 1);
    let order: Vec<_> = v.iter().map(|(k, c)| (k.as_str().to_string(), c)).collect();
    assert_eq!(order, [("a".to_string(), 1), ("b".to_string(), 2)]);
}

#[test]
fn bump_overflow_is_an_error_and_changes_nothing() {
    let mut v = sv(&[("a", u64::MAX)]);
    assert!(matches!(v.bump(&d("a")), Err(VaultError::CounterOverflow)));
    assert_eq!(v.get(&d("a")), u64::MAX);
}

#[test]
fn bump_refuses_a_257th_device() {
    let pairs: Vec<(DeviceId, u64)> = (0..256).map(|i| (d(&format!("{i:03}")), 1)).collect();
    let mut v = StateVector::from_pairs(pairs).unwrap();
    assert_eq!(v.len(), StateVector::MAX_DEVICES);
    assert!(matches!(v.bump(&d("zzz")), Err(VaultError::TooManyDevices)));
    assert_eq!(v.len(), 256);
    v.bump(&d("000")).unwrap(); // an existing device still counts
    assert_eq!(v.get(&d("000")), 2);
}

#[test]
fn join_is_component_wise_max() {
    let a = sv(&[("a", 3), ("b", 1)]);
    let b = sv(&[("b", 4), ("c", 2)]);
    assert_eq!(a.join(&b), sv(&[("a", 3), ("b", 4), ("c", 2)]));
    assert_eq!(a.join(&b), b.join(&a));
    assert_eq!(a.join(&a), a);
}

#[test]
fn dominates_treats_missing_as_zero() {
    let a = sv(&[("a", 2), ("b", 1)]);
    assert!(a.dominates(&sv(&[("a", 2)])));
    assert!(a.dominates(&StateVector::new()));
    assert!(a.dominates(&a));
    assert!(!sv(&[("a", 2)]).dominates(&a));
    assert!(!a.dominates(&sv(&[("c", 1)])));
}

#[test]
fn compare_classifies_states() {
    use VersionOrdering::*;
    let cases = [
        (sv(&[("a", 1)]), sv(&[("a", 1)]), Equal),
        (sv(&[("a", 2)]), sv(&[("a", 1)]), Newer),
        (sv(&[("a", 1)]), sv(&[("a", 1), ("b", 1)]), Older),
        (
            sv(&[("a", 2), ("b", 1)]),
            sv(&[("a", 1), ("b", 2)]),
            Concurrent,
        ),
        (StateVector::new(), StateVector::new(), Equal),
        (StateVector::new(), sv(&[("a", 1)]), Older),
    ];
    for (left, right, expected) in cases {
        assert_eq!(left.compare(&right), expected, "{left:?} vs {right:?}");
    }
}

#[test]
fn canonical_encoding_is_sorted_pairs() {
    let v = sv(&[("a", 1), ("b", 300)]);
    let bytes = postcard::to_allocvec(&v).unwrap();
    let pairs: Vec<(String, u64)> = vec![("a".into(), 1), ("b".into(), 300)];
    assert_eq!(bytes, postcard::to_allocvec(&pairs).unwrap());
    let back: StateVector = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, v);
}

#[test]
fn decode_rejects_unsorted_duplicate_zero_and_too_many() {
    let enc = |pairs: Vec<(String, u64)>| postcard::to_allocvec(&pairs).unwrap();
    let too_many: Vec<(String, u64)> = (0..257).map(|i| (format!("{i:03}"), 1)).collect();
    for bytes in [
        enc(vec![("b".into(), 1), ("a".into(), 1)]),
        enc(vec![("a".into(), 1), ("a".into(), 2)]),
        enc(vec![("a".into(), 0)]),
        enc(vec![(String::new(), 1)]),
        enc(too_many),
    ] {
        assert!(postcard::from_bytes::<StateVector>(&bytes).is_err());
    }
}

#[test]
fn from_pairs_applies_the_same_rules() {
    assert!(StateVector::from_pairs(vec![(d("b"), 1), (d("a"), 1)]).is_err());
    assert!(StateVector::from_pairs(vec![(d("a"), 1), (d("a"), 1)]).is_err());
    assert!(StateVector::from_pairs(vec![(d("a"), 0)]).is_err());
    assert!(StateVector::from_pairs(vec![]).unwrap().is_empty());
}
