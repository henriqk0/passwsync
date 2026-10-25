//! 004 T022: merge properties over random edit histories on 2-5 devices (FR-015, FR-018,
//! FR-020, SC-002, SC-003). Seeded xorshift generator, no extra dependency; each case checks
//! every property, 1000+ cases.

use std::collections::{BTreeMap, BTreeSet};

use vault_core::testkit::{copy_of, fork};
use vault_core::{
    DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, StateVector, Vault,
    VersionOrdering,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn fields(title: String) -> EntryFields {
    let mut f = EntryFields::default();
    f.title = title;
    f
}

/// Entry id -> ordered version hashes, plus the state: everything a merge result is.
type Fingerprint = (BTreeMap<EntryId, Vec<[u8; 32]>>, StateVector);

fn fingerprint(v: &Vault) -> Fingerprint {
    let entries = v
        .all_records()
        .map(|e| {
            (
                e.id(),
                e.versions().iter().map(|x| x.content_hash()).collect(),
            )
        })
        .collect();
    (entries, v.state().clone())
}

fn merged(a: &Vault, b: &Vault) -> Vault {
    let mut out = fork(a, "merger", 0);
    let report = out.merge(copy_of(b)).expect("merge");
    assert!(!report.merge_change, "no counter reuse in honest histories");
    out
}

/// Random history: devices start from one base wallet and edit, delete, add and merge.
fn history(rng: &mut Rng, base: &Vault) -> Vec<Vault> {
    let devices = 2 + rng.below(4);
    let mut vaults: Vec<Vault> = (0..devices)
        .map(|i| fork(base, &format!("dev{i}"), 0))
        .collect();
    let steps = 4 + rng.below(20);
    for now in (11i64..).take(steps) {
        let i = rng.below(devices);
        let pick = rng.below(10);
        let v = &mut vaults[i];
        // Keep each device's clock moving so timestamps differ.
        *v = fork(v, &format!("dev{i}"), now);
        let ids: Vec<EntryId> = v
            .all_records()
            .filter(|e| !e.is_deleted() && !e.is_conflicted())
            .map(|e| e.id())
            .collect();
        match pick {
            0..=1 => {
                v.add_entry(fields(format!("new {now}"))).unwrap();
            }
            2..=4 if !ids.is_empty() => {
                let id = ids[rng.below(ids.len())];
                v.update_entry(id, fields(format!("edit {now} on {i}")))
                    .unwrap();
            }
            5 if !ids.is_empty() => {
                let id = ids[rng.below(ids.len())];
                v.delete_entry(id).unwrap();
            }
            _ => {
                let j = rng.below(devices);
                if j != i {
                    let other = copy_of(&vaults[j]);
                    vaults[i].merge(other).unwrap();
                }
            }
        }
    }
    vaults
}

fn base_wallet() -> Vault {
    let mut v = Vault::create(
        MasterPassword::new("correct horse battery".into()),
        KdfConfig::MINIMUM,
        DeviceId::new("origin").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    for t in ["alpha", "beta", "gamma"] {
        v.add_entry(fields(t.into())).unwrap();
    }
    v
}

fn all_input_versions(
    inputs: &[&Vault],
) -> BTreeMap<EntryId, Vec<(VersionVectorKey, [u8; 32], bool)>> {
    let mut map: BTreeMap<EntryId, Vec<(VersionVectorKey, [u8; 32], bool)>> = BTreeMap::new();
    for v in inputs {
        for e in v.all_records() {
            for version in e.versions() {
                map.entry(e.id()).or_default().push((
                    VersionVectorKey(version.version().clone()),
                    version.content_hash(),
                    version.is_deleted(),
                ));
            }
        }
    }
    map
}

#[derive(Clone)]
struct VersionVectorKey(vault_core::VersionVector);

fn check_lossless(inputs: &[&Vault], result: &Vault) {
    let result_versions: BTreeMap<EntryId, Vec<(vault_core::VersionVector, [u8; 32])>> = result
        .all_records()
        .map(|e| {
            (
                e.id(),
                e.versions()
                    .iter()
                    .map(|v| (v.version().clone(), v.content_hash()))
                    .collect(),
            )
        })
        .collect();
    for (id, versions) in all_input_versions(inputs) {
        let out = result_versions
            .get(&id)
            .expect("entry ids are never dropped");
        for (vv, hash, _deleted) in &versions {
            // Never backwards: some result version is >= every input version.
            assert!(
                out.iter().any(|(w, _)| matches!(
                    w.compare(&vv.0),
                    VersionOrdering::Newer | VersionOrdering::Equal
                )),
                "an entry moved backwards"
            );
            // No silent overwrite: a version not dominated by another input is kept.
            let dominated = versions
                .iter()
                .any(|(other, _, _)| other.0.compare(&vv.0) == VersionOrdering::Newer);
            if !dominated {
                assert!(
                    out.iter().any(|(_, h)| h == hash),
                    "a non-dominated version (live or tombstone) was dropped"
                );
            }
        }
    }
    let mut join = StateVector::new();
    for v in inputs {
        join = join.join(v.state());
    }
    assert_eq!(result.state(), &join, "state is the join of the inputs");
}

#[test]
fn merge_is_convergent_idempotent_commutative_associative_and_lossless() {
    let base = base_wallet();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut cases = 0;
    let mut conflicts_seen = 0;
    while cases < 1000 {
        let vaults = history(&mut rng, &base);
        let (a, b) = (&vaults[0], &vaults[1]);
        let c = &vaults[vaults.len() - 1];

        // Idempotence.
        assert_eq!(fingerprint(&merged(a, a)), fingerprint(a));
        let ab = merged(a, b);
        assert_eq!(fingerprint(&merged(&ab, b)), fingerprint(&ab));
        assert_eq!(fingerprint(&merged(&ab, a)), fingerprint(&ab));
        // Commutativity.
        assert_eq!(fingerprint(&ab), fingerprint(&merged(b, a)));
        // Associativity.
        let left = merged(&ab, c);
        let right = merged(a, &merged(b, c));
        assert_eq!(fingerprint(&left), fingerprint(&right));
        // Convergence: every merge order of all devices gives the same result.
        let mut forward = fork(&vaults[0], "f", 0);
        for v in &vaults[1..] {
            forward.merge(copy_of(v)).unwrap();
        }
        let mut backward = fork(&vaults[vaults.len() - 1], "g", 0);
        for v in vaults.iter().rev().skip(1) {
            backward.merge(copy_of(v)).unwrap();
        }
        assert_eq!(fingerprint(&forward), fingerprint(&backward));
        // Lossless, never backwards, state = join, tombstones kept.
        let inputs: Vec<&Vault> = vaults.iter().collect();
        check_lossless(&inputs, &forward);
        check_lossless(&[a, b], &ab);
        conflicts_seen += forward.conflicted().len();
        cases += 1;
    }
    assert!(
        conflicts_seen > 50,
        "the generator produces conflicts ({conflicts_seen})"
    );
}

#[test]
fn tombstones_are_never_dropped_by_any_merge_order() {
    // Without resolutions nothing can dominate a tombstone (a deleted entry cannot be
    // edited), so every tombstone version of every device survives every merge order.
    let base = base_wallet();
    let mut rng = Rng(42);
    for _ in 0..1000 {
        let vaults = history(&mut rng, &base);
        let tombstones: BTreeSet<[u8; 32]> = vaults
            .iter()
            .flat_map(|v| {
                v.all_records()
                    .flat_map(|e| e.versions().iter())
                    .filter(|x| x.is_deleted())
                    .map(|x| x.content_hash())
                    .collect::<Vec<_>>()
            })
            .collect();
        for order in [false, true] {
            let mut list: Vec<&Vault> = vaults.iter().collect();
            if order {
                list.reverse();
            }
            let mut all = fork(list[0], "m", 0);
            for v in &list[1..] {
                all.merge(copy_of(v)).unwrap();
            }
            let kept: BTreeSet<[u8; 32]> = all
                .all_records()
                .flat_map(|e| e.versions().iter().map(|x| x.content_hash()))
                .collect();
            assert!(tombstones.is_subset(&kept), "a tombstone was dropped");
        }
    }
}
