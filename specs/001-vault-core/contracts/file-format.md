# Contract: Encrypted Wallet File Format, version 1

Status: normative for feature 001. All integers are little-endian.

## Layout

| Offset | Size | Field | Value / rule |
|-------:|-----:|-------|--------------|
| 0 | 4 | `magic` | ASCII `PWSV` (`50 57 53 56`) |
| 4 | 2 | `format_version` | `1` (u16) |
| 6 | 1 | `kdf_id` | `1` = Argon2id (v0x13); any other value → `UnsupportedKdf` |
| 7 | 4 | `kdf_memory_kib` | u32, 19 456 ≤ x ≤ 1 048 576 |
| 11 | 4 | `kdf_iterations` | u32, 2 ≤ x ≤ 100 |
| 15 | 4 | `kdf_parallelism` | u32, 1 ≤ x ≤ 16 |
| 19 | 32 | `kdf_salt` | random per wallet; regenerated on master-password change |
| 51 | 12 | `nonce` | random per save |
| 63 | n ≥ 16 | `ciphertext‖tag` | AES-256-GCM output; tag is the last 16 bytes |

Header = bytes `[0, 63)`. Total size ≥ 79 bytes and ≤ 64 MiB.

## Cryptography

- `key = Argon2id(password = NFC(master_password) as UTF-8, salt = kdf_salt,
  m = kdf_memory_kib, t = kdf_iterations, p = kdf_parallelism, output = 32 bytes)`
- `ciphertext‖tag = AES-256-GCM-Encrypt(key, nonce, plaintext = postcard(payload),
  aad = header[0..63])`

The file never contains the master password, the derived key, or any account/identity data.
The only input needed to decrypt it on any device is the master password (FR-005a/FR-005b).

## Payload (plaintext, postcard-encoded)

```text
Payload   { wallet_id: [u8;16], created_at: i64, entries: Vec<Entry> }
Entry     { id: [u8;16], created_at: i64, modified_at: i64, last_modified_by: String,
            version: Vec<(String, u64)>  /* sorted by device id, no duplicates */,
            state: EntryState }
EntryState = Live { title, username, password, url, notes: String }
           | Deleted { deleted_at: i64 }
```

Decoding rejects duplicate entry ids, unsorted/duplicate version keys, zero counters, empty
titles on live entries, and trailing bytes → `InvalidPasswordOrCorrupted` (the payload is only
reachable after successful authentication, so these indicate a bug or a forged-but-authentic
file; they are reported generically).

## Parse order and errors at unlock

Checks run in this order; the first failure is returned. No key derivation happens before
step 5.

1. Length < 79 or > 64 MiB → `MalformedFile`
2. `magic` ≠ `PWSV` → `MalformedFile`
3. `format_version` ≠ 1 → `UnsupportedVersion(v)`
4. `kdf_id` ≠ 1 → `UnsupportedKdf`; any KDF parameter out of range → `KdfParamsOutOfRange`
5. Derive key; AEAD decrypt with header as AAD; failure → `InvalidPasswordOrCorrupted`
6. Decode and validate payload; failure → `InvalidPasswordOrCorrupted`

`InvalidPasswordOrCorrupted` is the single generic authentication error (FR-003). Errors never
include key material, plaintext, or byte dumps.

## Versioning rules

- Any change to layout, KDF set, cipher, or payload schema requires a new `format_version`.
- Readers MUST reject versions they do not implement (no best-effort parsing).
- Writers in feature 001 always write version 1.
