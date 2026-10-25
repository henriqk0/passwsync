//! 004 T127 (US6): chains, intermediaries, locked devices and revocation.

mod support;

use support::sim::*;
use wallet_sync::ports::SyncStore;

fn title(sim: &Sim, dev: usize, id: vault_core::EntryId) -> String {
    sim.devices[dev]
        .vault
        .get(id)
        .unwrap()
        .fields()
        .unwrap()
        .title
        .clone()
}

#[test]
fn a_and_c_converge_through_an_unlocked_b() {
    let mut sim = Sim::new(3, 21);
    let ids: Vec<_> = sim.devices[0].vault.list().iter().map(|e| e.id()).collect();
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(ids[0], fields("from A")).is_ok());
    let t = sim.tick();
    sim.devices[2].edit(t, |v| v.update_entry(ids[1], fields("from C")).is_ok());
    sim.connect(0, 1);
    sim.connect(1, 2); // never A-C
    sim.all_rounds();
    sim.all_rounds();
    for d in 0..3 {
        assert_eq!(title(&sim, d, ids[0]), "from A", "device {d}");
        assert_eq!(title(&sim, d, ids[1]), "from C", "device {d}");
    }
    assert_eq!(
        fingerprint(&sim.devices[0].vault),
        fingerprint(&sim.devices[2].vault)
    );
}

#[test]
fn a_locked_intermediary_stores_and_after_unlock_offers_only_its_merged_file() {
    let mut sim = Sim::new(3, 22);
    let id = sim.devices[0].vault.list()[0].id();
    sim.devices[1].locked = true;
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
    sim.connect(0, 1);
    sim.connect(1, 2);
    sim.all_rounds();
    let b_wallet = sim.devices[1].wallet();
    assert_eq!(
        sim.devices[1].store.pending_peers(&b_wallet).unwrap().len(),
        1
    );
    assert_eq!(
        title(&sim, 2, id),
        "alpha",
        "nothing forwarded while locked"
    );
    // B unlocks: merges, saves, then offers its own merged file to C.
    assert!(sim.devices[1].unlock());
    sim.rounds_from(1);
    sim.settle();
    assert_eq!(title(&sim, 1, id), "from A");
    assert_eq!(title(&sim, 2, id), "from A", "C got B's own merged file");
    assert!(
        sim.devices[1]
            .store
            .pending_peers(&b_wallet)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_revoked_device_receives_nothing_and_its_copies_are_dropped() {
    let mut sim = Sim::new(2, 23);
    let id = sim.devices[0].vault.list()[0].id();
    sim.devices[1].locked = true;
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
    sim.connect(0, 1);
    sim.all_rounds();
    let b_wallet = sim.devices[1].wallet();
    assert_eq!(
        sim.devices[1].store.pending_peers(&b_wallet).unwrap().len(),
        1
    );
    // B revokes A: A's copies go; with no channel nothing more flows.
    let a_id = sim.devices[0].id;
    sim.devices[1].engine.revoke_peer(a_id);
    // 003 shuts the socket down: A sees the channel go.
    let b_id = sim.devices[1].id;
    sim.devices[0].engine.channel_down(b_id, conn(0, 1));
    sim.links.clear();
    assert!(
        sim.devices[1]
            .store
            .pending_peers(&b_wallet)
            .unwrap()
            .is_empty()
    );
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.add_entry(fields("later")).is_ok());
    assert!(!sim.start_round(0, 1), "no channel to a revoked device");
    assert!(!sim.devices[1].record().peers.contains_key(&a_id));
}
