//! 004 T128 (US6, SC-002): randomized 5-device simulations: random edits, deletes and
//! resolutions, partitions healing, lost connections, restarts at journal points, lock and
//! unlock. 200+ seeded scenarios; the seed is printed on failure.

mod support;

use std::collections::BTreeMap;

use rand_core::RngCore;
use support::sim::*;
use vault_core::{EntryId, Resolution, VersionOrdering, VersionVector};
use wallet_sync::journal::{Recovery, recover};
use wallet_sync::ports::SyncStore;
use wallet_sync::record::sha256;

type Seen = BTreeMap<EntryId, Vec<VersionVector>>;

fn versions(sim: &Sim, d: usize) -> Seen {
    let mut out = Seen::new();
    for e in sim.devices[d].vault.all_records() {
        out.insert(
            e.id(),
            e.versions().iter().map(|v| v.version().clone()).collect(),
        );
    }
    out
}

fn covered(by: &[VersionVector], v: &VersionVector) -> bool {
    by.iter().any(|w| {
        matches!(
            w.compare(v),
            VersionOrdering::Newer | VersionOrdering::Equal
        )
    })
}

fn step(sim: &mut Sim, rng: &mut support::TestRng) {
    let n = sim.devices.len();
    let d = (rng.next_u64() % n as u64) as usize;
    let t = sim.tick();
    match rng.next_u64() % 12 {
        0 | 1 => {
            sim.devices[d].edit(t, |v| v.add_entry(fields(&format!("new {t}"))).is_ok());
        }
        2..=4 => {
            let ids: Vec<EntryId> = sim.devices[d]
                .vault
                .list()
                .iter()
                .filter(|e| !e.is_conflicted())
                .map(|e| e.id())
                .collect();
            if !ids.is_empty() {
                let id = ids[(rng.next_u64() % ids.len() as u64) as usize];
                sim.devices[d].edit(t, |v| {
                    v.update_entry(id, fields(&format!("edit {t}"))).is_ok()
                });
            }
        }
        5 => {
            let ids: Vec<EntryId> = sim.devices[d]
                .vault
                .list()
                .iter()
                .filter(|e| !e.is_conflicted())
                .map(|e| e.id())
                .collect();
            if !ids.is_empty() {
                let id = ids[(rng.next_u64() % ids.len() as u64) as usize];
                sim.devices[d].edit(t, |v| v.delete_entry(id).is_ok());
            }
        }
        6 => {
            let conflicted: Vec<EntryId> = sim.devices[d]
                .vault
                .conflicted()
                .iter()
                .map(|e| e.id())
                .collect();
            if let Some(id) = conflicted.first().copied() {
                let how = if rng.next_u64() % 2 == 0 {
                    Resolution::Keep(0)
                } else {
                    Resolution::KeepBoth
                };
                sim.devices[d].edit(t, |v| v.resolve(id, how).is_ok());
            }
        }
        7 | 8 => {
            let e = (rng.next_u64() % n as u64) as usize;
            if e != d {
                if sim.links.contains(&(d.min(e), d.max(e))) {
                    sim.disconnect(d, e);
                } else {
                    sim.connect(d, e);
                    sim.start_round(d, e);
                }
            }
        }
        9 => {
            if sim.devices[d].locked {
                if sim.devices[d].unlock() {
                    sim.rounds_from(d);
                }
            } else {
                sim.devices[d].locked = true;
            }
        }
        10 => {
            // A restart: channels drop, the journal is recovered against the file.
            let peers: Vec<usize> = (0..n)
                .filter(|e| sim.links.contains(&(d.min(*e), d.max(*e))))
                .collect();
            for e in peers {
                sim.disconnect(d, e);
            }
            let wallet = sim.devices[d].wallet();
            let digest = sim.devices[d].source.get(NAME).map(|b| sha256(&b));
            sim.devices[d]
                .store
                .update(&wallet, &mut |r| {
                    let mut r = r?;
                    let outcome = recover(&mut r, digest);
                    assert!(matches!(
                        outcome,
                        Recovery::Clean | Recovery::Committed(_) | Recovery::Discarded
                    ));
                    Some(r)
                })
                .unwrap();
        }
        _ => sim.rounds_from(d),
    }
    sim.settle();
}

fn run(seed: u64) -> (usize, usize) {
    let mut sim = Sim::new(5, seed);
    sim.loss = 3;
    let mut rng = support::TestRng(seed.wrapping_mul(6364136223846793005).max(1));
    let mut ever: Seen = Seen::new();
    let mut marks: Vec<vault_core::StateVector> =
        sim.devices.iter().map(|d| d.record().mark).collect();
    let mut last: Vec<Seen> = (0..5).map(|d| versions(&sim, d)).collect();
    for _ in 0..(10 + rng.next_u64() % 30) {
        step(&mut sim, &mut rng);
        for d in 0..5 {
            let now = versions(&sim, d);
            // No entry ever moves backwards on any device.
            for (id, old) in &last[d] {
                let new = now.get(id).expect("entries are never dropped");
                for v in old {
                    assert!(
                        covered(new, v),
                        "seed {seed}: an entry moved backwards on device {d}"
                    );
                }
            }
            for (id, vs) in &now {
                ever.entry(*id).or_default().extend(vs.iter().cloned());
            }
            last[d] = now;
            // Marks never decrease.
            let mark = sim.devices[d].record().mark;
            assert!(mark.dominates(&marks[d]), "seed {seed}: a mark decreased");
            marks[d] = mark;
        }
    }
    // Heal: everyone unlocked and connected, rounds until quiet.
    sim.loss = 0;
    for d in 0..5 {
        if sim.devices[d].locked {
            sim.devices[d].unlock();
        }
        for e in d + 1..5 {
            sim.connect(d, e);
        }
    }
    for _ in 0..4 {
        sim.all_rounds();
    }
    let conflicts_seen = sim.devices[0].vault.conflicted().len();
    let reference = fingerprint(&sim.devices[0].vault);
    for d in 1..5 {
        assert_eq!(
            fingerprint(&sim.devices[d].vault),
            reference,
            "seed {seed}: device {d} diverged"
        );
    }
    // Every version ever created is still there or superseded by a newer one.
    let final_versions = versions(&sim, 0);
    for (id, vs) in &ever {
        let now = final_versions.get(id).expect("no entry lost");
        for v in vs {
            assert!(covered(now, v), "seed {seed}: a version was lost");
        }
    }
    (sim.devices.iter().map(|d| d.merges).sum(), conflicts_seen)
}

#[test]
fn two_hundred_random_partition_scenarios_converge_without_loss() {
    let (mut merges, mut conflicts) = (0, 0);
    for seed in 1..=200u64 {
        match std::panic::catch_unwind(|| run(seed)) {
            Ok((m, c)) => {
                merges += m;
                conflicts += c;
            }
            Err(cause) => {
                eprintln!("failing seed: {seed}");
                std::panic::resume_unwind(cause);
            }
        }
    }
    eprintln!("{merges} merges, {conflicts} conflicted entries at the end");
    assert!(merges > 1000, "the scenarios exercise merges");
    assert!(conflicts > 10, "and conflicts");
}
