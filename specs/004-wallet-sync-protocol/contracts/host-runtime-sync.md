# Contract: `passwsyncd` host runtime changes for sync

Extends 002 `host-runtime.md` and 003 `host-runtime-network.md`. Rationale:
[research.md](../research.md) R10–R14.

## Files (added)

| Path | Mode | Content | Written by |
|------|------|---------|------------|
| `$XDG_DATA_HOME/passwsync/sync/` | 0700 | — | service |
| `…/sync/<wallet-id hex32>/` | 0700 | — | service |
| `…/<wallet-id>/record` | 0600 | sync record (below), atomic write | service |
| `…/<wallet-id>/pending-<peer hex64>` | 0600 | received encrypted wallet copy (ciphertext only) | service |
| `…/<wallet-id>/incoming-<peer hex64>.part` | 0600 | partial copy; deleted at start | service |

Wallet files keep their 002 location; the v2 format adds no plaintext metadata.

## Record format (text, ≤ 1 MiB)

```text
passwsync-sync-record-v1
wallet_id <hex32>
wallet_name <hex of UTF-8 name>
digest <sha256 hex64>
state <sv>
prepared <sha256 hex64> <sv> <peer-updates> <consumed-peers> | prepared -
mark <sv>
flags <comma list or ->
peer <hex64> <sv or -> <last_round unix or -> <outcome> <position>
pending <hex64> <claimed sv> <size> <received unix> <status>
warning <id> <kind> <peer hex64 or -> <unix>
check <sha256 hex64 of all preceding bytes>
```

`<sv>` = `-` (empty) or comma-separated `<device-id hex>:<counter>` sorted by device id.
Unknown lines, bad values, or checksum mismatch → record corrupted → sync disabled for the
wallet with a clear message (never reset silently).

## Configuration (added key)

```text
sync_interval_minutes = 60   # 15..=1440; safety interval per peer
```

## Start-up (appended after 003 step 5b)

5c. Create `sync/` if missing; for each record: recover the save journal, delete `*.part`,
drop orphan pending files/lines, verify each wallet digest and set flags. 5d. Start
`sync-sched` and `sync-merge` only when networking is on. Exit codes unchanged; a corrupted
record never stops the service.

## Unlock, revoke, shutdown

- Unlock merges pending copies before returning (research R13).
- Revoking a peer deletes its pending copies and peer lines in every record.
- Shutdown: abort rounds (partial files deleted), stop sync threads before closing the network.

## Log events (added, closed set)

`sync round start <fingerprint>`, `sync round end <fingerprint> (<ok|failed|busy|timeout|protocol>) sent=<bytes> received=<bytes>`,
`sync merged wallet=<local name> peer=<fingerprint> conflicts=<n>`,
`sync pending stored wallet=<local name> peer=<fingerprint>`,
`sync possible rollback wallet=<local name>`, `sync older state offered wallet=<local name> peer=<fingerprint>`,
`sync invalid copy wallet=<local name> peer=<fingerprint>`, `sync cannot open copy wallet=<local name> peer=<fingerprint>`,
`sync self rollback recovered wallet=<local name> peer=<fingerprint>`,
`sync accepted older state wallet=<local name>`, `sync state reset wallet=<local name>`,
`sync record corrupted wallet=<local name>`, `wallet upgraded to format 2 wallet=<local name>`,
`sync peer legacy <fingerprint>`.
Never: credential data, titles, keys, passwords, wallet ids, state vectors, other devices'
wallet names.
