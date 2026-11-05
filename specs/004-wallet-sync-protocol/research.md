# Research: Wallet Sync Protocol (004)

Phase 0 decisions for [spec.md](spec.md). Format per decision: Decision / Rationale /
Alternatives. Non-interactive session: every open choice takes the most secure, then simplest
option consistent with the constitution and the roadmap global rules. R2 changes a spec decision
(FR-012/FR-030); the spec was amended to match (see the "Plan amendment" note in spec.md).

## R1. Crate layout (hexagonal boundary)

- **Decision**:
  - `crates/vault-core` (domain, extended): file format v2 (R3), wallet state vector (R4),
    conflict versions, merge and resolution (R5), password-change epoch (R6), opening a
    received copy with the vault's own key or with a password, and one additive default method
    on the `VaultStorage` port (`store_versioned`, R12). Still no I/O, no network.
  - `crates/wallet-sync` (NEW domain crate, sans-IO): sync message codec (R8), blinded tags and
    state digests (R9), per-peer round state machine, decisions (want / refuse / rollback flags,
    R10), sync-record codec and two-phase journal (R12), scheduler and backoff (R14). Ports:
    `SyncStore` (records, pending and incoming copies), `WalletSide` (summaries, stored bytes,
    merge requests), `PeerSink` (send sync frames), `MonoClock`, `WallClock`, injected RNG.
    Depends on `vault-core` (ids, `StateVector`) and on `hmac`/`sha2`; not on `device-link`
    (session hash and peer ids are plain `[u8; 32]`), not on `wallet-service`.
  - `crates/wallet-service` (extended): sync-facing operations under its existing locks
    (merge a copy into an unlocked wallet, merge pending copies inside the unlock call while the
    password is still held, resolve conflicts, accept older state), never touching idle timers.
  - `crates/device-link` (extended, additive): channel protocol v2 (Hello version byte 2,
    prologue `passwsync-channel-v2`), opaque `Payload::SyncCtl` / `Payload::CopyData`
    passthrough, `Channel::session_hash()` and `Channel::sync_enabled()`.
  - `crates/device-link-net` (extended): v2-then-v1 dialing, delivery of sync frames to an
    injected `SyncFrameSink`, and `Node::send_sync(peer, conn, body)` (seal + write under the
    channel mutex so nonce order equals write order).
  - `crates/passwsyncd` (adapters): `sync_store.rs` (file `SyncStore`, following 003's
    `net_store.rs` precedent), `sync_runtime.rs` (threads, glue between `wallet-sync`,
    `wallet-service` and `device-link-net`), journaling `VaultStorage` decorator, HTTP routes,
    UI, config key, log events.
- **Rationale**: Principle IV: protocol and merge logic are testable with in-memory fakes;
  merge lives in vault-core because the entry list and its invariants are private there; the
  network crates stay ignorant of wallets. One new crate only.
- **Alternatives**: sync logic inside `passwsyncd` (not reusable by 007, cannot be tested
  without I/O); merge in `wallet-sync` (would need vault-core to expose mutable entry
  internals); a separate `wallet-sync-file` crate (one more crate for ~200 lines; 003 put its
  file adapter in `passwsyncd`, so we follow that until 007 needs reuse).

## R2. Where the wallet id and state vector live (header metadata decision)

The clarified spec placed the wallet id and the wallet state vector in the unencrypted (but
authenticated) wallet-file header so that a locked device could summarize and rollback-check a
file. Scrutiny:

**What a plaintext header would reveal** to anyone who sees the file (backups, shared or
cloud-synced folders, a stolen disk image), without any password:

1. Wallet id: links every copy and every historical version of the same wallet across
   devices and backups. (Marginal: the v1 header already contains the per-wallet `kdf_salt`,
   which stays constant until the password changes and links copies the same way.)
2. State vector, the real leak:
   - the number of distinct devices that ever edited the wallet;
   - per-device edit counters, i.e. activity volume; two snapshots (e.g. daily backups) reveal
     how many edits happened between them and on which device;
   - cross-wallet linkage: the 002 device id is the same for every wallet on an installation,
     so two otherwise unrelated wallet files (say "work" and "personal" stored in different
     places) are provably edited by the same device(s), i.e. the same person;
   - staleness of a copy relative to another, telling an attacker which backup is newest.
3. Integrity value is low: while a wallet is locked the header cannot be authenticated, so
   a locked-time rollback check based on it trusts attacker-controlled values (an attacker who
   restores an old file can also raise its header vector to mask the rollback until unlock).

Peers are paired and trusted, so the wire is not the concern (the channel is encrypted and
all metadata on it is session-blinded, R9). The concern is files at rest outside the data
directory.

- **Decision**: Do NOT add any plaintext metadata to the file. Format v2 keeps exactly the v1
  header layout (only `format_version = 2`); the wallet id (already in the v1 payload), the
  state vector, conflict versions and the password-change epoch live only inside the encrypted
  payload. A locked device works from its own **sync record** (R10, R12): an owner-only file
  in the per-user data area, written only by the service and only from authenticated state
  (after unlock, a local save, or a merge), holding the wallet id, the authenticated state
  vector, the SHA-256 digest of the wallet file it describes, the high-water mark and the
  per-peer marks. Before summarizing or offering a locked wallet, the service recomputes the
  file digest; any mismatch means "file changed outside the service" and the wallet is treated
  as possibly rolled back (not offered, still receives) until the next unlock authenticates the
  file and compares its real state vector with the mark.
- **Rationale**:
  - Leaks less: a wallet file found anywhere reveals what a v1 file reveals (KDF parameters,
    salt, size) and nothing more. The record never leaves the data directory, which already
    holds the device private key (far more sensitive) under the same 0700/0600 protection.
  - Rollback detection is stronger, not weaker: the spec's worry was that "a separate index
    could drift from the file". The digest binds the record to the exact file bytes, so any
    drift or external modification (restored backup, forged header, manual copy) is detected
    exactly, without trusting unauthenticated values; the authenticated comparison happens at
    unlock. The header design could only detect a restore that also left the header vector
    lower.
  - Summaries of locked wallets come from authenticated values (recorded while unlocked), not
    from an unauthenticated header.
  - Cost: a wallet file that this device has never unlocked (e.g. just copied in by hand) is
    not synced until its first unlock here; the spec already accepts this for v1 wallets
    (edge case "not synced until unlocked and saved once"). An externally replaced file stops
    being offered until unlock. Both are visible in the UI.
- **Alternatives**:
  - Plaintext authenticated header (spec original): rejected for the leaks above.
  - Header metadata encrypted under a device-local key: equivalent to the sidecar record in
    who can read it, but adds a key file and still puts per-device data into shared files.
  - Keyed blinding of the header vector (e.g. HMAC of device ids with the wallet id): the wallet
    id is in the same header, so anyone can recompute it; no gain.

## R3. File format v2 and migration of v1 wallets

- **Decision**: [contracts/file-format-v2.md](contracts/file-format-v2.md). Header identical
  to v1 except `format_version = 2`; parse steps unchanged except step 3 accepts 1 or 2.
  Payload v2 adds `state: StateVector` (≤ 256 devices), `password_epoch: VersionVector`, and
  per entry a `current` version plus `conflicts: Vec<Version>` (total versions per entry ≤ 16).
  Writers always write v2. Reading v1 maps each entry to a single-version entry, sets
  `password_epoch` empty and initializes `state[d] = Σ over all entries (live and tombstone) of
  entry.version[d]`. With 001's "+1 per change of that entry" rule this sum is exactly the
  number of changes device `d` made, so it is a correct change count (the component-wise max
  would undercount and could make two different states look equal).
  Migration trigger: a v1 wallet is rewritten as v2 on its next save, and additionally at
  unlock when networking is on and at least one peer is paired (pairing + networking is the
  sync opt-in, FR-006c); log `wallet upgraded to format 2`. With networking off a v1 file is
  left as is (keeps a downgrade path to pre-004 builds for people who never sync).
- **Rationale**: Additive, one new version number, v1 rules (sizes, ranges, generic error)
  preserved; no new plaintext.
- **Alternatives**: migrate only on next edit (a read-only wallet would never sync); migrate
  every v1 file at service start (needs the password; impossible).

## R4. Wallet state vector

- **Decision**: `StateVector` = sorted map `DeviceId → u64` (0..=256 entries, counters ≥ 1).
  Every local change (add, edit, delete, conflict resolution, password change, and the
  "merge change" of R5) does `state[me] += 1`; entry version vectors keep 001 semantics
  (`increment(me)` on the changed entry; a resolution uses `join(all versions)` then
  `increment(me)`). Merge sets `state = join(state_a, state_b)` (component-wise max).
  Property: with whole-state transfer, a copy holding device `d`'s change #k holds all of
  `d`'s changes 1..k, so `a ≥ b` component-wise ⇔ `a` contains all of `b`'s changes.
  Counter overflow is unreachable in practice; `checked_add` fails the change with an error.
  Jump bound (anti-DoS, R11): a received copy whose authenticated state has some component
  `> local[d] + 2^32` is rejected as invalid.
- **Rationale**: FR-011; minimal; keeps the 001 `VersionVector` API.
- **Alternatives**: dotted version vectors (more state, solves counter reuse but needs a format
  and API rewrite); hybrid logical clocks (no concurrency detection).

## R5. Merge algorithm and storage of concurrent versions

- **Decision**: `Vault::merge(&mut self, copy: OpenedCopy) -> MergeReport` in vault-core.
  - Precondition: authenticated `copy.wallet_id == self.wallet_id` (else `WalletMismatch`).
  - Per entry id, take the union of all versions from both sides (current + conflicts). A
    version's identity is its content hash `H = SHA-256(postcard(Version))` (covers version
    vector, timestamps, device, state). Drop exact duplicates (same `H`). Drop every version
    whose version vector is strictly older than another version's in the union. What remains
    is the set of maximal versions (an antichain).
  - Two versions with **equal version vectors but different content** are both kept (they
    are not "equal"): this can only arise from counter reuse after an undetected rollback
    (R10) or a buggy/hostile peer, and keeping both is the only lossless choice. FR-013's
    "equal → keep" therefore means "equal vector and equal content".
  - If one version remains: no conflict. If several: the current one is chosen by the FR-014
    order: live before tombstone, then later `modified_at`, then larger `last_modified_by`,
    then larger `H`; the rest are stored in `conflicts` in the same order. More than 16
    versions → `MergeError::TooManyConflicts`, nothing changes (pending copy stays, status
    "too many conflicts, resolve first").
  - Entries on one side only are taken as they are. Wallet: `state = join`, `created_at = min`,
    password epoch per R6.
  - Union-then-maximal-elements and component-wise max are both lattice joins, so merge is
    deterministic, commutative, associative and idempotent (FR-015); verified by property
    tests over random histories and merge orders (SC-002).
  - Merge change (lossless propagation guard): after merging, if the merged state vector equals
    the state vector of one input but the merged entries differ from that input's entries, the
    merging device records a merge change (`state[me] += 1`, no entry change). Never happens in
    normal operation (it requires counter reuse); when it happens it guarantees peers that
    believe they are in sync will fetch the merged content.
  - A merge never moves an entry backwards: dominated versions are exactly the older ones
    (FR-020). Copies whose state is ≤ local are not requested (FR-009); if one is merged anyway
    (pending copy at unlock) the result equals local by construction unless counter reuse
    happened, in which case data is preserved as a conflict.
  - Resolution (FR-016): `resolve(entry, Keep(i))` → new current = version `i`'s state with
    `version = join(all) + increment(me)`, `modified_at = now`, `last_modified_by = me`,
    conflicts cleared; `resolve(entry, KeepBoth)` → as `Keep(current)` plus every other live
    version becomes a new entry (new id, `{me: 1}`); tombstone versions are simply resolved
    away. Each resolution is one change (`state[me] += 1`). A dominating version arriving by
    merge clears the conflict automatically (FR-017) because the older versions are dropped.
- **Rationale**: Principle VI (never silently overwrite), FR-013 to FR-017, smallest change to
  the 001 entry model.
- **Alternatives**: per-field CRDT merge (over-scoped, can produce passwords nobody typed);
  last-writer-wins by timestamp (silent loss, forbidden); storing conflict versions as separate
  hidden entries (breaks the one-id-one-credential model and complicates search).

## R6. Password-change epoch and copies under different passwords

- **Decision**: `password_epoch: VersionVector` in the payload; empty until the first change;
  `change_master_password` does `password_epoch.increment(me)` and `state[me] += 1`.
  Opening a copy: if its header `(kdf, salt)` equals the unlocked vault's, open with the
  in-memory key (no KDF); otherwise a key must be derived from a password: inside the unlock
  call (password still held, one derivation at a time under the 002 KDF lock and memory cap via
  `peek_kdf_config`), or later when the person types that copy's password. Merge: epochs equal
  → keep the local key; copy's epoch newer → the merged vault adopts the copy's KDF parameters,
  salt and key (UI notice "master password was changed on another device; use the new password
  next time"); local newer → keep local; concurrent → no automatic merge: the copy stays
  pending with status "password changed on two devices", and the person resolves by choosing
  which copy's password to keep and typing it (verified by opening that copy); the merge then
  runs with that key and the epoch becomes `join + increment(me)`, dominating both.
  A copy that cannot be opened stays pending with "cannot open: different master password or
  corrupted" (FR-008) and can be opened with another password or discarded.
- **Rationale**: FR-022 with the least machinery; a password is never stored or sent.
- **Alternatives**: deterministic winner among concurrent password changes (the person might
  not know the winning password and lose access); re-encrypting under both (impossible without
  both passwords).

## R7. Protocol negotiation over the 003 channel

- **Decision**: Channel protocol v2 = 003 channel with Hello `PWSC || 0x02 || 0x01` and
  Noise prologue `passwsync-channel-v2 || Hello`; identical framing (`len:u16`, body ≤ 1024)
  and handshake. A v2 responder accepts Hello version 1 (channel without sync) and 2. A v2
  dialer dials v2; if the connection is closed before Noise message 2 arrives, it marks the peer
  `legacy` in memory and redials with v1 immediately; `legacy` is retried as v2 after 24 h or a
  service restart. Pairing (kind 0x02) stays version 1. Sync frames are valid only on v2
  channels; on a v1 channel the 003 rules apply unchanged (FR-004).
- **Rationale**: 003 v1 receivers close on any unknown type or trailing byte, so the only
  ignorable signal is the plaintext Hello, which a v1 peer rejects before any crypto. The
  version is bound into the Noise prologue, so it cannot be altered without failing the
  handshake; an active attacker can only force v1, i.e. "no sync", which is no worse than
  dropping traffic (no wallet data ever flows on v1).
  **Amended by 009 (pending 009 implementation)**: this rationale is wrong. The review of 2026-11-05 forced v1 with one
  datagram and one closed connection, with no on-path position, and the effect outlasted the
  attacker by up to 24 h. The memory is removed; 009 research R1.
- **Alternatives**: capability field in `ChannelHello` (v1 peers close on trailing bytes);
  new Noise payload in msg2 (same problem); separate TCP port for sync (more sockets, a second
  handshake, duplicates the pin logic).

## R8. Sync message set and round flow (bounded memory and bandwidth)

- **Decision**: [contracts/sync-protocol.md](contracts/sync-protocol.md). Two new Noise
  payload types in the 003 type space: `0x20 SyncCtl` (fragment of a control message,
  reassembled ≤ 24 KiB) and `0x21 CopyData` (≤ 1000 bytes of wallet ciphertext, streamed to
  disk). Control messages: `Tags`, `Matches`, `Summary`, `Want`, `Refuse`, `CopyStart`,
  `CopyEnd`, `CopyAbort`, `Done`, `Busy`. A round:
  1. initiator → `Tags{round, [(tag, state_digest)] ≤ 512}`;
  2. responder computes the initiator-role tags of all its syncable wallets, replies
     `Matches{round, [(idx, in_sync)]}`, then a `Summary{idx, flags, state}` for every matched
     wallet that differs;
  3. initiator sends its `Summary` for those idx;
  4. each side `Want`s the peer's copy when the peer has a change it lacks and the mark checks
     pass (R10); copies stream as `CopyStart{size}` + `CopyData`* + `CopyEnd`;
  5. each side sends `Done` when it has nothing left to want or serve; the round ends when both
     have.
  In-sync wallets cost 32 bytes in `Tags` + 3 bytes in `Matches`: 10 wallets ≈ 600 bytes per
  round with framing, one round per peer per safety interval → < 1 KiB/peer/hour (SC-006).
  Whole encrypted files are the transfer unit (spec assumption); size is announced and refused
  above 64 MiB before any byte is stored; the receiver counts bytes and aborts on excess.
  One copy in flight per direction per channel; ≤ 2 transfers service-wide (FR-029).
  Inactivity of 30 s inside a round aborts it (failure → backoff).
  Simultaneous round starts: the round started by the channel dialer wins; the other side drops
  its own `Tags` and answers.
- **Rationale**: Keeps the 1024-byte 003 frame bound (a DoS bound already reviewed); the
  responder never reveals wallets the initiator does not hold; summaries exchange full vectors
  only when states differ.
- **Alternatives**: raise the frame limit for sync (changes a reviewed bound; 64 MiB in 1000-byte
  frames is ~67 k AEAD operations, negligible CPU); block-level delta transfer (deferred by the
  spec); push without `Want` (receiver loses control of storage and marks).

## R9. Blinded wallet tags and session binding

- **Decision**: `session` = Noise handshake hash `h` (32 bytes, unique per channel, equal on
  both sides; captured from `snow` before transport mode). With `wid` = the 16-byte wallet id
  as HMAC key:
  - `tag = HMAC-SHA256(wid, "passwsync-sync-tag-v1" || session || round:u32 || role:u8)[..16]`
  - `state_digest = HMAC-SHA256(wid, "passwsync-sync-state-v1" || session || round || role ||
    canonical(state))[..16]`
  (`role` 0 = round initiator is the channel dialer, 1 = responder). A peer without the
  wallet id (128-bit random, never on the wire, never in a plaintext file after R2) cannot
  compute or link tags; tags differ per session and round, so nothing links across rounds.
  Summaries and wants refer to wallets only by `idx` into the current round's `Tags`, so every
  sync message is meaningful only inside its session and round (FR-019); Noise already rejects
  replay and reordering.
- **Rationale**: FR-010, FR-019; HMAC via the RustCrypto `hmac` crate already in the
  dependency tree (R18); no custom construction.
- **Alternatives**: private set intersection (heavy, unnecessary between paired devices);
  plain wallet id inside the channel (lets a paired device that lacks the wallet recognize it
  across sessions, violating Story 1 scenario 6).

## R10. Rollback and replay protection

- **Decision**:
  - Replay: 003 Noise channel (fresh keys per session, nonces enforce order) plus session- and
    round-bound tags (R9). Replayed frames fail AEAD and close the channel.
  - Per-wallet high-water mark `mark` and per-peer marks `peer_mark[p]` live in the sync record
    (R12), with the file digest and authenticated `state` of the last file this service saved
    or verified.
  - Local rollback detection (FR-021): at service start and before each round, for each
    wallet with a record, recompute the file's SHA-256. Equal to the record → the recorded
    `state` is the file's authenticated state; flag `possible_rollback` if `state ≱ mark`.
    Different → `possible_rollback (unlock to check)`: not offered, `Summary` flag `no_offer`
    with the recorded state (so peers send what they have); at unlock the authenticated state is
    compared with `mark`: `≥` → record updated, flag cleared (e.g. a newer file copied in by
    hand); otherwise the flag stays until a merge brings the state to `≥ mark` or the person
    chooses "accept this older state" (logged; resets `mark` to the current state).
  - Peer rollback (FR-021a): a peer `Summary` with `state ≱ peer_mark[p]` → do not `Want`,
    record "older state offered" for that peer and log it. An authenticated copy whose state is
    `≱ peer_mark[p]` is refused likewise. Marks are raised only from **authenticated** copy
    states after the merged result is saved; summaries never raise marks.
  - Copy authenticity: after decryption, the authenticated wallet id must equal the wallet the
    copy was requested for and the authenticated state must equal the state claimed in that
    peer's `Summary`; otherwise the copy is rejected as invalid (warning naming the peer).
  - Self-rollback seen by peers: if an authenticated copy from a peer carries
    `state[me] > local.state[me]`, this device had lost its own changes (whole-installation
    restore); log/warn "this device had lost changes; recovered from <peer>". Unauthenticated
    claims never raise this warning (a peer without the password cannot cause false alarms).
  - Counter reuse after an undetected whole-installation restore (wallet file, record and
    device id restored together): handled losslessly where detectable (equal vector, different
    content → conflict; merge change, R5). Residual risk, documented: an edit made on the
    restored device before it resyncs can be dominated by a pre-restore edit of the same
    entry made elsewhere; peers flag "older state offered" for that device, so the person is
    warned. Eliminating it needs trusted monotonic storage (TPM/Keystore), out of scope.
  - Tampering with the record by someone with file access: the record is 0700/0600 in the data
    directory next to the device private key; a writer with the person's OS-user rights is out
    of scope (spec trust model: such an attacker can replace the service binary). A checksum
    line detects corruption (→ sync disabled for that wallet, FR-025). No MAC is used: a MAC
    keyed from the wallet key cannot be verified across password changes or an externally
    replaced file, and a device-local MAC key would sit in the same directory as the record.
    The design is fail-safe instead: tampering can only (a) raise marks → false warnings,
    recoverable (R11); or (b) lower marks / fake the digest → hide a local rollback, which every
    peer that saw the newer state still detects through its own `peer_mark` ("older state
    offered"), and which the merge never turns into data loss on peers.
- **Rationale**: FR-019 to FR-021a, SC-004, with distributed witnesses (peers) covering what a
  single device cannot prove about itself.
- **Alternatives**: header-based check (R2, weaker); OS keyring or TPM counter (not portable,
  not on all targets; revisit in 007/008).

## R11. Can the marks lock out legitimate sync? (DoS analysis and recovery)

- **Decision / analysis**:
  1. Inflation by an outsider or a paired peer without the password: impossible; marks are
     raised only from authenticated states after a saved merge; summaries never raise marks.
  2. Inflation by a holder of the wallet password (compromised own device): could push
     counters towards `u64::MAX`; prevented by the jump bound (R4: reject any component
     > local + 2^32), leaving ~2^32 merges of headroom.
  3. Restored device (old file, or whole installation): peers refuse its offers ("older state
     offered") but refusal is one-directional: a refused peer's summary still drives sending
     our copy to it. It merges our copy on unlock, its state becomes ≥ the marks, and it is
     accepted again. Self-healing, no person action.
  4. Own `possible_rollback` that never clears: when no peer holds a newer state (the newer
     state is truly lost), the person chooses "accept this older state" (unlocked, logged,
     resets `mark`).
  5. A peer whose mark at our side can never be reached (its newer state is lost everywhere):
     impossible while we hold that state, because a mark is set only after we merged that state,
     so our copy carries it back to the peer. If our own state is also lost (we accepted an
     older state), "accept this older state" also resets the per-peer marks for that wallet,
     and revoking/re-pairing a peer (003) deletes its marks.
  6. Corrupted or tampered record: sync disabled for that wallet with a clear message, never
     silently reset (FR-025); the person runs "reset sync state" (wallet unlocked, logged):
     record rebuilt from the authenticated file (`mark = state`, per-peer marks cleared,
     pending copies kept and re-validated on merge).
  7. Too many conflicts (≥ 16 versions) caused by a hostile password holder: merge refused for
     that wallet until the person resolves conflicts; no data lost.
  8. Wall-clock time is never used for ordering or marks, so clock changes cannot lock out.
- **Rationale**: Every refusal is either self-healing or has an explicit, logged,
  person-initiated recovery that never accepts older data silently (FR-036).
- **Alternatives**: expiring marks (would re-open rollback after the expiry); automatic reset on
  corruption (forbidden by FR-025).

## R12. Crash-safe application and sync-record storage

- **Decision**: Layout `$XDG_DATA_HOME/passwsync/sync/` (0700) → per wallet
  `<wallet-id hex>/` (0700) containing `record` (0600, text, atomic write: temp file, fsync,
  rename, directory fsync), `pending-<peer-id hex>` (0600) and `incoming-<peer-id hex>.part`
  (0600). Format in [data-model.md](data-model.md).
  - Saves (local edits, merges, migration, resolution) are journaled two-phase through a
    `VaultStorage` decorator: vault-core gains an additive default method
    `VaultStorage::store_versioned(bytes, &SaveMeta{wallet_id, state})` (default: `store`),
    called by `save`. The decorator (1) writes `prepared <digest> <state> <peer-mark updates>` to
    the record, (2) calls the inner atomic store, (3) writes the record with `digest`, `state`,
    `mark = join(mark, state)`, the peer-mark updates, consumed pending lines removed and
    `prepared` cleared, then (4) deletes consumed pending files.
  - Start-up recovery: delete every `*.part`; if the file digest equals `prepared` → finish step
    3; equals `digest` → drop `prepared`; else → external change (R10). Pending files without a
    record line are deleted; lines without files are dropped.
  - Receiving: chunks are appended to `incoming-*.part`; on `CopyEnd` with the exact announced
    size: fsync, rename over `pending-<peer>` (at most one per wallet per peer, FR-029a), fsync
    directory, record line `pending <peer> <claimed state> <received_at> waiting`. A pending
    copy dominated by local state or by another pending copy is deleted instead.
  - Storage full or any write error: nothing replaced, status "sync error", round fails →
    backoff.
- **Rationale**: FR-023 to FR-026, SC-007; the wallet file uses the unchanged 001 atomic
  save; the record is always describable as "old" or "new" after a crash.
- **Alternatives**: a database (SQLite: large dependency); one global record file (a single
  corruption would disable sync for all wallets).

## R13. Locked wallets and the unlock flow

- **Decision**: Per FR-006. Locked: answer from the record (digest-verified), send the stored
  file (digest re-checked while streaming; mismatch → `CopyAbort`), store wanted copies as
  pending, never write the wallet file. Unlock (`wallet-service`): after the vault opens, while
  the password is still held, merge each pending copy one at a time (open with own key or
  derive per R6), then one journaled save, then wipe the password; copies that cannot be opened
  stay pending with their status. Unlocked: a received copy is merged on the `sync-merge`
  worker under the wallet's state lock (so the merge applies to the latest local state,
  FR-026) and saved. Sync operations never call the idle-timer touch (FR-006b); if the wallet
  locks before the merge takes the lock, the merge is skipped and the copy stays pending.
- **Rationale**: Spec clarifications Q1, Q4; merges serialized with key derivations keep peak
  memory within the 002 locked budget (SC-008).
- **Alternatives**: decrypt-and-merge on a locked device (impossible without the key);
  forwarding pending copies (forbidden, FR-006a).

## R14. Scheduling, backoff and resource budget

- **Decision**: One `sync-sched` thread sleeps on a condvar until the earliest deadline (no
  polling). Triggers per FR-027: channel up (v2), wallet saved (5 s quiet period coalesces
  edits; rounds with every connected v2 peer, since blinded tags prevent knowing in advance who
  holds it), unlock with pending copies, "Sync now", safety interval (`sync_interval_minutes`,
  default 60, 15..=1440; reset by any completed round with that peer, whichever side started
  it). Backoff after failure: 30 s doubling to 1 h, ±20 % jitter from `OsRng`, reset on success;
  "Sync now" bypasses once; presses during a running round are coalesced. Limits: 1 round per
  peer, 2 transfers service-wide (a sender without a free slot within 10 s answers
  `Refuse(busy)`, retried after 30 s without counting as failure), ≤ 1 MiB buffers per
  transfer (1 KiB frame + 64 KiB file buffer), 512 wallets per round (rotating window beyond).
  Threads added: `sync-sched`, `sync-merge` (idle), ≤ 2 short-lived `sync-send` (128 KiB stacks).
- **Rationale**: FR-027 to FR-029b, SC-006, battery use for 007 (timings in a `SyncTiming`
  struct as 003 did).
- **Alternatives**: periodic polling (forbidden); per-wallet timers (more wakes).

## R15. HTTP API, UI and logging

- **Decision**: [contracts/http-api-sync.md](contracts/http-api-sync.md) and
  [contracts/host-runtime-sync.md](contracts/host-runtime-sync.md). `GET /api/state` gains a
  `sync` object per wallet; new background `GET /api/sync`; deliberate routes for sync details,
  conflicts (list, view, reveal a version's field, resolve), pending copies (open with password,
  discard), accept older state, reset sync state, sync now, dismiss warnings. All behind the 002
  guards; none returns credential data while locked. Closed set of new log events, no
  secrets, no wallet names of other devices.
- **Rationale**: FR-032 to FR-038.
- **Alternatives**: separate sync UI page (more assets for no benefit).

## R16. Testing strategy (TDD)

- **Decision**: vault-core: v1→v2 known-answer files, v2 round-trip, bounds, merge property
  tests (commutative, associative, idempotent, never backwards, no version lost) with a small
  deterministic PRNG (no new crate), counter-reuse cases. wallet-sync: sans-IO round tests with
  in-memory `SyncStore`/`WalletSide`/`PeerSink`, tag unlinkability, mark rules, crash-point
  recovery of the journal, scheduler/backoff with fake clocks, a 5-device random-partition
  simulator (SC-002). device-link(-net): v2/v1 negotiation and fallback, sync frames refused on
  v1, loopback transfer of a 64 MiB+1 copy refused. passwsyncd: raw-HTTP tests for routes,
  plaintext-marker scan of captured channel plaintext and ciphertext (SC-005), crash tests by
  fault-injecting storage between journal steps (SC-007), `#[ignore]` resource tests (SC-006,
  SC-008).
- **Rationale**: Principle III; mirrors 001–003.

## R17. Dependencies

- **Decision**: New direct dependencies: `hmac` 0.12 (RustCrypto; already in `Cargo.lock` via
  `hkdf`/`spake2`) and `sha2` 0.10 (workspace dep already used by `device-link`). No new crate
  enters the dependency tree; `cargo deny check` and `cargo audit` results are unchanged and
  remain release gates. No async runtime, no database, no serialization crate beyond the
  existing `postcard`/`serde`.
- **Rationale**: Constitution workflow gate (minimal, vetted dependencies).
- **Alternatives**: `blake2` keyed MAC (also in tree via `snow`, but HMAC-SHA-256 matches the
  `sha2` digest already used for file digests: one hash family).
