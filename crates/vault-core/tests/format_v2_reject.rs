//! 004 T011: authenticated v2 payloads that break a rule are rejected with the generic
//! error; damaged files never panic.

mod support;

use support::*;
use vault_core::VaultError;

fn assert_corrupt(payload: &RawPayloadV2, case: &str) {
    assert!(
        matches!(
            unlock(&seal(2, payload)),
            Err(VaultError::InvalidPasswordOrCorrupted)
        ),
        "{case}"
    );
}

fn valid() -> RawPayloadV2 {
    one_entry(
        &[("a", 1), ("b", 1)],
        vec![
            rv("newer", 20, "b", &[("b", 1)]),
            rv("older", 10, "a", &[("a", 1)]),
        ],
    )
}

#[test]
fn the_reference_payload_is_valid() {
    assert!(unlock(&seal(2, &valid())).is_ok());
}

#[test]
fn state_vector_rules() {
    let mut p = valid();
    p.state = (0..257).map(|i| (format!("{i:03}"), 1)).collect();
    assert_corrupt(&p, "> 256 devices");
    let mut p = valid();
    p.state = pairs(&[("b", 1), ("a", 1)]);
    assert_corrupt(&p, "unsorted");
    let mut p = valid();
    p.state = pairs(&[("a", 1), ("a", 1), ("b", 1)]);
    assert_corrupt(&p, "duplicate");
    let mut p = valid();
    p.state = pairs(&[("a", 0), ("b", 1)]);
    assert_corrupt(&p, "zero counter");
}

#[test]
fn more_than_15_conflicts() {
    let names: Vec<String> = (0..17).map(|i| format!("d{i:02}")).collect();
    let mut versions: Vec<RawVersion> = names
        .iter()
        .enumerate()
        .map(|(i, n)| rv("x", 100 - i as i64, n, &[(n.as_str(), 1)]))
        .collect();
    let state: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), 1)).collect();
    assert_corrupt(&one_entry(&state, versions.clone()), "17 versions");
    versions.pop();
    assert!(
        unlock(&seal(2, &one_entry(&state, versions))).is_ok(),
        "16 versions"
    );
}

#[test]
fn equal_content_hash() {
    let v = rv("same", 10, "a", &[("a", 1)]);
    assert_corrupt(
        &one_entry(&[("a", 1)], vec![v.clone(), v]),
        "duplicate version",
    );
}

#[test]
fn dominated_sibling() {
    let p = one_entry(
        &[("a", 2)],
        vec![
            rv("new", 20, "a", &[("a", 2)]),
            rv("old", 10, "a", &[("a", 1)]),
        ],
    );
    assert_corrupt(&p, "dominated version");
}

#[test]
fn non_canonical_order() {
    let p = one_entry(
        &[("a", 1), ("b", 1)],
        vec![
            rv("older", 10, "a", &[("a", 1)]),
            rv("newer", 20, "b", &[("b", 1)]),
        ],
    );
    assert_corrupt(&p, "older first");
    let mut tomb_first = valid();
    tomb_first.entries[0].current.state = RawState::Deleted { deleted_at: 20 };
    assert_corrupt(&tomb_first, "tombstone before live");
}

#[test]
fn version_component_above_state() {
    let mut p = valid();
    p.state = pairs(&[("a", 1)]);
    assert_corrupt(&p, "b missing from state");
    let mut p = valid();
    p.entries[0].current.version = pairs(&[("b", 2)]);
    assert_corrupt(&p, "b above state");
}

#[test]
fn duplicate_entry_ids_and_invalid_fields() {
    let mut p = valid();
    let copy = p.entries[0].clone();
    p.entries.push(copy);
    assert_corrupt(&p, "duplicate id");
    let mut p = valid();
    p.entries[0].conflicts[0].state = live_state(" ");
    assert_corrupt(&p, "blank title in a conflict version");
}

#[test]
fn trailing_bytes() {
    let mut plain = postcard::to_allocvec(&valid()).unwrap();
    plain.push(0);
    let bytes =
        vault_core::testkit::seal_payload(PASSWORD, vault_core::KdfConfig::MINIMUM, 2, &plain);
    assert!(matches!(
        unlock(&bytes),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}

#[test]
fn damaged_files_never_panic() {
    let bytes = seal(2, &valid());
    // Deterministic sample of positions (every position would run Argon2 per case).
    for index in (0..bytes.len()).step_by(7) {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1 << (index % 8);
        assert!(unlock(&damaged).is_err(), "flip at {index} accepted");
    }
    for length in (0..bytes.len()).step_by(11) {
        assert!(unlock(&bytes[..length]).is_err(), "truncation to {length}");
    }
}
