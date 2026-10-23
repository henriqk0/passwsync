# Data Model: Local Service with Web UI (Feature 002)

Entities owned by `wallet-service` (application layer) and `passwsyncd` (adapters). Wallet
and entry content are vault-core types ([001 data model](../001-vault-core/data-model.md));
nothing here is persisted except the device identifier, wallet files, and the launch file.

## Settings (`passwsyncd`, read-only after start)

| Field | Type | Default | Range |
|-------|------|---------|-------|
| `port` | u16 | 27471 | 1024–65535 |
| `auto_lock_minutes` | Duration | 15 min | 1–240 min |
| `clipboard_clear_seconds` | Duration | 30 s | 5–300 s |

Validation: see [contracts/host-runtime.md](contracts/host-runtime.md). Not secret.

## WalletName (`wallet-service`)

Newtype over `String`. Valid iff 1–64 chars, all in `[A-Za-z0-9 _.-]`, first char not `.`,
last char not space. Ordering: byte order. Constructed only through `WalletName::parse`, so
an invalid name (path traversal) is unrepresentable. Not secret.

## Ports (`wallet-service`)

```rust
pub trait WalletDirectory: Send + Sync {
    fn list(&self) -> Result<Vec<WalletName>, StorageError>;      // sorted
    fn exists(&self, name: &WalletName) -> Result<bool, StorageError>;
    fn storage(&self, name: &WalletName) -> Box<dyn VaultStorage + Send>;
}
pub trait ElapsedClock: Send + Sync {
    fn monotonic(&self) -> Duration;   // stops during suspend
    fn boottime(&self) -> Duration;    // includes suspend
}
```

Adapters: `FsWalletDirectory` (`passwsyncd`, `<dir>/<name>.pwsw` via `FileStorage`),
`OsElapsedClock` (`rustix` `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`). Fakes:
`MemoryWalletDirectory`, `FakeElapsedClock`.

## WalletSlot (`wallet-service`, one per known wallet, in memory)

| Field | Type | Notes |
|-------|------|-------|
| `name` | WalletName | key in the registry |
| `state` | `Locked` \| `Unlocked { vault: Vault, last_activity: Duration (monotonic) }` | |

State transitions:

```text
            create (valid, new name) ───────────────┐
                                                    ▼
 Locked ── unlock(correct pw, KDF ≤ cap) ──▶ Unlocked ── deliberate action ──▶ Unlocked (last_activity = now)
   ▲  ▲                                         │
   │  └── unlock(wrong pw / format error): stays Locked, generic or format error
   └──── lock | lock-all | idle ≥ auto_lock | suspend detected | shutdown ◀──┘
```

- Locking calls `Vault::lock` (zeroizes key and entries) and drops nothing else secret.
- Operations other than unlock on `Locked` → `WalletLocked` (no data).
- Background requests (`/api/state`) never update `last_activity`.
- Slots are created lazily from `WalletDirectory::list` and on create; a slot whose file
  disappeared stays usable while unlocked (next save rewrites the file atomically).

## Registry / Service (`wallet-service`)

| Field | Type | Notes |
|-------|------|-------|
| `slots` | `Mutex<BTreeMap<WalletName, Arc<Mutex<WalletSlot>>>>` | per-wallet serialization (FR-017) |
| `kdf_gate` | `Mutex<()>` | one key derivation at a time (locked-memory budget) |
| `kdf_memory_cap_kib` | u32 = 131 072 | refuse larger wallet KDF before Argon2 |
| `suspend_offset` | `Mutex<Duration>` | last `boottime − monotonic` |
| `sessions` | `Mutex<Sessions>` | below |
| `device`, `clock`, `elapsed`, `dir`, `kdf_config` | injected | `KdfConfig::DEFAULT` in production |

`check_suspend()`: if `(boottime − monotonic) − suspend_offset > 5 s` → lock all, update
offset, return `true`. Called before every request and by the sweeper.
`sweep()`: lock every unlocked slot with `monotonic − last_activity ≥ auto_lock`.

## LaunchToken and Sessions (`wallet-service`)

| Entity | Fields | Rules |
|--------|--------|-------|
| `LaunchToken` | `Zeroizing<[u8; 32]>` | random (OsRng); single-use: a successful `exchange` replaces it and returns the new value for the launch file; compared in constant time |
| `BrowserSession` | `id: Zeroizing<[u8; 32]>`, `csrf: Zeroizing<[u8; 32]>`, `created: Duration` | created by `exchange`; valid only in this run (in-memory); max 32, oldest evicted |
| `Sessions` | `launch: LaunchToken`, `list: Vec<BrowserSession>` | `authenticate(cookie) -> Option<SessionRef>`, `check_csrf(session, header) -> bool` (constant time) |

All token values are hex-encoded (64 chars) at the HTTP boundary only. Never logged.

## Device identifier (`passwsyncd`)

`$XDG_CONFIG_HOME/passwsync/device-id`: 32 lowercase hex chars from OsRng, created once,
mode 0600, wrapped in `vault_core::DeviceId`. Not secret, not an identity.

## Request DTOs (`passwsyncd`, serde)

| DTO | Fields | Secret handling |
|-----|--------|-----------------|
| `CreateWallet` | `name: String`, `password: Zeroizing<String>`, `password_confirm: Zeroizing<String>` | password moved into `MasterPassword`; confirm wiped on drop |
| `Unlock` | `password: Zeroizing<String>` | moved into `MasterPassword` |
| `Search` | `query: Zeroizing<String>` | |
| `EntryInput` | `title, username, password, url, notes: Zeroizing<String>`, `keep_password: bool` (update only) | converted to `EntryFields` (ZeroizeOnDrop) |
| `FieldRequest` | `field: "password" \| "username"` | |

`#[serde(deny_unknown_fields)]` on all DTOs. Raw request body: `Zeroizing<Vec<u8>>`.
Responses with credential data are written into a pre-sized `Zeroizing<Vec<u8>>`.

## Rejection counters (`passwsyncd`)

`AtomicU64` per reason: `host`, `origin`, `csrf`, `session`, `size`, `peer`. Logged
aggregated by the sweeper at most once per minute, then reset.

## Mutation rollback

Add/update/delete use vault-core `*_saved` methods
([contracts/vault-core-additions.md](contracts/vault-core-additions.md)): on save failure the
affected record is restored exactly and the API returns `500 storage_error`.
