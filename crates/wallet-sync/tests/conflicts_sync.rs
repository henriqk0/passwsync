//! 004 T072 (US2, SC-003): concurrent edits travel between devices and are never lost.

mod support;

use support::sim::*;
use vault_core::{EntryId, Resolution};
use wallet_sync::record::PendingStatus;

fn first_id(sim: &Sim) -> EntryId {
    sim.devices[0]
        .vault
        .list()
        .iter()
        .find(|e| e.fields().unwrap().title == "alpha")
        .unwrap()
        .id()
}

fn sync_pair(sim: &mut Sim, a: usize, b: usize) {
    sim.connect(a, b);
    sim.start_round(a, b);
    sim.settle();
    sim.start_round(b, a);
    sim.settle();
}

#[test]
fn concurrent_edits_give_the_same_conflict_and_current_version_on_both() {
    let mut sim = Sim::new(2, 1);
    let id = first_id(&sim);
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
    let t = sim.tick();
    sim.devices[1].edit(t, |v| v.update_entry(id, fields("from B")).is_ok());
    sync_pair(&mut sim, 0, 1);
    for d in &sim.devices {
        let e = d.vault.all_records().find(|e| e.id() == id).unwrap();
        assert!(e.is_conflicted(), "{}", d.label);
        assert_eq!(e.fields().unwrap().title, "from B", "deterministic current");
    }
    assert_eq!(
        fingerprint(&sim.devices[0].vault),
        fingerprint(&sim.devices[1].vault)
    );
}

#[test]
fn edit_versus_delete_keeps_both_versions() {
    let mut sim = Sim::new(2, 2);
    let id = first_id(&sim);
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("kept")).is_ok());
    let t = sim.tick();
    sim.devices[1].edit(t, |v| v.delete_entry(id).is_ok());
    sync_pair(&mut sim, 0, 1);
    for d in &sim.devices {
        let e = d.vault.all_records().find(|e| e.id() == id).unwrap();
        assert!(e.is_conflicted());
        assert!(!e.is_deleted(), "live wins the current slot");
        assert!(e.conflicts()[0].is_deleted());
    }
}

#[test]
fn resolving_on_one_device_clears_the_conflict_on_the_other() {
    for how in [Resolution::Keep(1), Resolution::KeepBoth] {
        let mut sim = Sim::new(2, 3);
        let id = first_id(&sim);
        let t = sim.tick();
        sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
        let t = sim.tick();
        sim.devices[1].edit(t, |v| v.update_entry(id, fields("from B")).is_ok());
        sync_pair(&mut sim, 0, 1);
        let t = sim.tick();
        let mut created = Vec::new();
        sim.devices[0].edit(t, |v| {
            created = v.resolve(id, how).unwrap();
            true
        });
        sim.rounds_from(0);
        sim.settle();
        for d in &sim.devices {
            assert!(d.vault.conflicted().is_empty(), "{how:?} on {}", d.label);
        }
        if how == Resolution::KeepBoth {
            assert_eq!(created.len(), 1);
            assert!(
                sim.devices[1].vault.get(created[0]).is_some(),
                "extra entry on B"
            );
        }
        assert_eq!(
            fingerprint(&sim.devices[0].vault),
            fingerprint(&sim.devices[1].vault)
        );
    }
}

#[test]
fn a_concurrent_version_added_while_resolving_is_kept() {
    let mut sim = Sim::new(3, 4);
    let id = first_id(&sim);
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
    let t = sim.tick();
    sim.devices[1].edit(t, |v| v.update_entry(id, fields("from B")).is_ok());
    sync_pair(&mut sim, 0, 1);
    // C, partitioned, edits the same credential while A resolves.
    let t = sim.tick();
    sim.devices[2].edit(t, |v| v.update_entry(id, fields("from C")).is_ok());
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.resolve(id, Resolution::Keep(0)).is_ok());
    sync_pair(&mut sim, 0, 2);
    sync_pair(&mut sim, 1, 2);
    sync_pair(&mut sim, 0, 1);
    for d in &sim.devices {
        let titles: Vec<String> = d
            .vault
            .versions(id)
            .unwrap()
            .iter()
            .filter_map(|v| v.fields().map(|f| f.title.clone()))
            .collect();
        assert!(
            titles.contains(&"from C".to_string()),
            "{}: {titles:?}",
            d.label
        );
        assert_eq!(titles.len(), 2, "resolution plus C's version");
    }
}

#[test]
fn more_than_15_conflicting_versions_disable_sync_without_losing_data() {
    let n = 18;
    let mut sim = Sim::new(n, 5);
    let id = first_id(&sim);
    for i in 1..n {
        let t = sim.tick();
        sim.devices[i].edit(t, |v| v.update_entry(id, fields(&format!("v{i}"))).is_ok());
    }
    // Device 0 collects the copies one by one.
    for i in 1..n {
        sync_pair(&mut sim, i, 0);
        sim.disconnect(i, 0);
    }
    let versions = sim.devices[0].vault.versions(id).unwrap().len();
    assert_eq!(versions, 16, "at most 16 versions");
    let record = sim.devices[0].record();
    assert!(
        record.flags.too_many_conflicts,
        "sync disabled(too_many_conflicts)"
    );
    assert!(
        record
            .pending
            .values()
            .any(|p| p.status == PendingStatus::TooManyConflicts),
        "the extra copy stays pending: no data lost"
    );
}
