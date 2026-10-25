//! 004 T126: an in-process multi-device simulator: real `vault-core` wallets, real
//! `wallet-sync` engines, in-memory channels, fake clocks, a partition matrix, message loss
//! and reordering, and locked/unlocked devices. Merges and the save journal behave like the
//! host's (`passwsyncd`): records are written only from authenticated state.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use vault_core::testkit::fork;
use vault_core::{
    DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, StateVector, Vault,
    WalletId,
};
use wallet_sync::decide::jump_too_large;
use wallet_sync::ports::{MergeOutcome, MergeRequest, PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame, SyncEvent};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

use super::TestRng;

pub const NAME: &str = "Shared";

pub struct SimDevice {
    pub id: PeerId,
    pub label: String,
    pub engine: Engine,
    pub store: MemorySyncStore,
    pub source: FakeWalletSource,
    pub mono: Arc<FakeMonoClock>,
    /// The wallet as this device holds it (its file is the sealed form).
    pub vault: Vault,
    pub locked: bool,
    pub merges: usize,
    pub events: Vec<SyncEvent>,
}

/// One wallet-level snapshot of what a merge result is.
pub type Fingerprint = (BTreeMap<EntryId, Vec<[u8; 32]>>, StateVector);

pub fn fingerprint(v: &Vault) -> Fingerprint {
    (
        v.all_records()
            .map(|e| {
                (
                    e.id(),
                    e.versions().iter().map(|x| x.content_hash()).collect(),
                )
            })
            .collect(),
        v.state().clone(),
    )
}

pub fn fields(title: &str) -> EntryFields {
    let mut f = EntryFields::default();
    f.title = title.into();
    f
}

pub fn base_wallet() -> Vault {
    let mut v = Vault::create(
        MasterPassword::new("correct horse battery".into()),
        KdfConfig::MINIMUM,
        DeviceId::new("origin").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    for t in ["alpha", "beta", "gamma"] {
        v.add_entry(fields(t)).unwrap();
    }
    v
}

impl SimDevice {
    pub fn new(seed: u8, base: &Vault) -> Self {
        let label = format!("dev{seed}");
        let store = MemorySyncStore::new();
        let source = FakeWalletSource::new();
        let mono = Arc::new(FakeMonoClock::new());
        let engine = Engine::new(
            EngineDeps {
                store: Arc::new(store.clone()),
                source: Arc::new(source.clone()),
                mono: mono.clone(),
                wall: Arc::new(FakeWallClock::new(1_000)),
                rng: Box::new(TestRng(u64::from(seed) + 7)),
            },
            EngineConfig::default(),
        );
        let mut dev = Self {
            id: PeerId([seed; 32]),
            vault: fork(base, &label, 10),
            label,
            engine,
            store,
            source,
            mono,
            locked: false,
            merges: 0,
            events: Vec::new(),
        };
        dev.save(BTreeMap::new(), BTreeSet::new());
        dev
    }

    pub fn wallet(&self) -> WalletId {
        self.vault.wallet_id()
    }

    pub fn record(&self) -> SyncRecord {
        self.store.load(&self.wallet()).unwrap().unwrap()
    }

    /// Seals, writes the file and commits the record (the host's journaled save).
    pub fn save(&mut self, marks: BTreeMap<PeerId, StateVector>, consumed: BTreeSet<PeerId>) {
        let bytes = self.vault.seal().unwrap();
        let digest = sha256(&bytes);
        self.source.set(NAME, bytes);
        let (wallet, state) = (self.wallet(), self.vault.state().clone());
        self.store
            .update(&wallet, &mut |r| {
                let mut r = r
                    .unwrap_or_else(|| SyncRecord::new(wallet, NAME.into(), digest, state.clone()));
                r.committed(digest, &state);
                for (p, m) in &marks {
                    r.raise_peer_mark(*p, m);
                }
                for p in &consumed {
                    r.pending.remove(p);
                }
                Some(r)
            })
            .unwrap();
        for p in &consumed {
            let _ = self.store.delete_pending(&wallet, p);
        }
    }

    /// A local change on an unlocked device (refused while locked or conflicted).
    pub fn edit(&mut self, now: i64, change: impl FnOnce(&mut Vault) -> bool) -> bool {
        if self.locked {
            return false;
        }
        self.vault = fork(&self.vault, &self.label.clone(), now);
        if change(&mut self.vault) {
            self.save(BTreeMap::new(), BTreeSet::new());
            true
        } else {
            false
        }
    }

    /// Merges the pending copy of `peer` like the host does (checks, merge, journaled save).
    pub fn merge_pending(&mut self, peer: PeerId) -> MergeOutcome {
        if self.locked {
            return MergeOutcome::Locked;
        }
        let wallet = self.wallet();
        let Ok(bytes) = self.store.read_pending(&wallet, &peer) else {
            return MergeOutcome::Unchanged;
        };
        let record = self.record();
        let Some(pending) = record.pending.get(&peer).cloned() else {
            return MergeOutcome::Unchanged;
        };
        let Ok(copy) = self.vault.open_copy_own_key(&bytes) else {
            return MergeOutcome::CannotOpen;
        };
        let mark = record.peers.get(&peer).and_then(|p| p.peer_mark.clone());
        let ok = copy.wallet_id() == wallet
            && copy.state() == &pending.claimed
            && mark.as_ref().is_none_or(|m| copy.state().dominates(m))
            && !jump_too_large(copy.state(), &record.state, mark.as_ref());
        if !ok {
            return MergeOutcome::Invalid;
        }
        let state = copy.state().clone();
        match self.vault.merge(copy) {
            Ok(report) => {
                self.merges += 1;
                let marks = BTreeMap::from([(peer, state)]);
                let consumed = BTreeSet::from([peer]);
                self.save(marks, consumed);
                if report.changed {
                    MergeOutcome::Merged {
                        conflicts: report.conflicts_added,
                        self_rollback: report.self_rollback_recovered,
                        password_adopted: report.password_adopted,
                    }
                } else {
                    MergeOutcome::Unchanged
                }
            }
            Err(vault_core::MergeError::TooManyConflicts) => MergeOutcome::TooManyConflicts,
            Err(vault_core::MergeError::PasswordConflict) => MergeOutcome::PasswordConflict,
            Err(_) => MergeOutcome::Invalid,
        }
    }

    /// Runs queued merge requests; returns whether anything was saved.
    pub fn run_merges(&mut self) -> bool {
        let mut saved = false;
        for request in self.engine.take_merge_requests() {
            let outcome = self.merge_pending(request.peer);
            saved |= matches!(outcome, MergeOutcome::Merged { .. });
            self.engine.merge_finished(&request, outcome);
        }
        self.events.extend(self.engine.take_events());
        saved
    }

    /// Unlock: merge every pending copy (as `wallet-service` does inside `unlock`).
    pub fn unlock(&mut self) -> bool {
        self.locked = false;
        let peers: Vec<PeerId> = self.record().pending.keys().copied().collect();
        let mut saved = false;
        for peer in peers {
            let outcome = self.merge_pending(peer);
            saved |= matches!(outcome, MergeOutcome::Merged { .. });
            let request = MergeRequest {
                wallet: self.wallet(),
                wallet_name: NAME.into(),
                peer,
                claimed: StateVector::new(),
                peer_mark: None,
            };
            self.engine.merge_finished(&request, outcome);
        }
        saved
    }
}

/// Devices plus the links between them.
pub struct Sim {
    pub devices: Vec<SimDevice>,
    pub links: BTreeSet<(usize, usize)>,
    pub rng: TestRng,
    /// Probability (in percent) that a frame batch is dropped (the link then breaks).
    pub loss: u64,
    pub clock: i64,
}

impl Sim {
    pub fn new(n: usize, seed: u64) -> Self {
        let base = base_wallet();
        let devices = (0..n).map(|i| SimDevice::new(i as u8 + 1, &base)).collect();
        Self {
            devices,
            links: BTreeSet::new(),
            rng: TestRng(seed.max(1)),
            loss: 0,
            clock: 100,
        }
    }

    fn session(i: usize, j: usize, generation: u64) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = i as u8;
        s[1] = j as u8;
        s[2..10].copy_from_slice(&generation.to_be_bytes());
        s
    }

    /// Opens the channel i -> j (i dials).
    pub fn connect(&mut self, i: usize, j: usize) {
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        if !self.links.insert((a, b)) {
            return;
        }
        let generation = rand_core::RngCore::next_u64(&mut self.rng);
        let session = Self::session(a, b, generation);
        let (ida, idb) = (self.devices[a].id, self.devices[b].id);
        self.devices[a]
            .engine
            .channel_up(idb, conn(a, b), session, true);
        self.devices[b]
            .engine
            .channel_up(ida, conn(a, b), session, false);
    }

    pub fn disconnect(&mut self, i: usize, j: usize) {
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        if !self.links.remove(&(a, b)) {
            return;
        }
        let (ida, idb) = (self.devices[a].id, self.devices[b].id);
        self.devices[a].engine.channel_down(idb, conn(a, b));
        self.devices[b].engine.channel_down(ida, conn(a, b));
    }

    pub fn start_round(&mut self, i: usize, j: usize) -> bool {
        let peer = self.devices[j].id;
        self.devices[i].engine.start_round(peer)
    }

    /// Moves frames on every link until quiet, running merges and starting the rounds that
    /// saves trigger (FR-027 b, with the quiet period elided).
    pub fn settle(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            let links: Vec<(usize, usize)> = self.links.iter().copied().collect();
            for (a, b) in links {
                for (from, to) in [(a, b), (b, a)] {
                    let to_id = self.devices[to].id;
                    let from_id = self.devices[from].id;
                    let frames = self.devices[from].engine.poll_outgoing(to_id, 16);
                    if frames.is_empty() {
                        continue;
                    }
                    moved = true;
                    if self.loss > 0
                        && rand_core::RngCore::next_u64(&mut self.rng) % 100 < self.loss
                    {
                        // A lost batch breaks the channel (as a broken TCP connection).
                        self.disconnect(a, b);
                        break;
                    }
                    for frame in frames {
                        self.devices[to].engine.on_frame(from_id, conn(a, b), frame);
                    }
                }
            }
            for i in 0..self.devices.len() {
                if self.devices[i].run_merges() {
                    self.rounds_from(i);
                    moved = true;
                }
                let events = self.devices[i].engine.take_events();
                for e in &events {
                    if let SyncEvent::CloseChannel { peer, .. } = e {
                        if let Some(j) = self.devices.iter().position(|d| d.id == *peer) {
                            self.disconnect(i, j);
                        }
                    }
                }
                self.devices[i].events.extend(events);
            }
            if !moved {
                return;
            }
        }
        panic!("simulation did not settle");
    }

    /// Starts rounds from device `i` with every connected peer.
    pub fn rounds_from(&mut self, i: usize) {
        for j in 0..self.devices.len() {
            let (a, b) = if i < j { (i, j) } else { (j, i) };
            if self.links.contains(&(a, b)) {
                self.start_round(i, j);
            }
        }
    }

    pub fn all_rounds(&mut self) {
        for i in 0..self.devices.len() {
            self.rounds_from(i);
            self.settle();
        }
    }

    pub fn tick(&mut self) -> i64 {
        self.clock += 1;
        self.clock
    }
}

pub fn conn(a: usize, b: usize) -> u64 {
    (a * 100 + b) as u64
}

/// Used to silence unused warnings in tests that only build frames.
pub fn _frame(f: Frame) -> Frame {
    f
}
