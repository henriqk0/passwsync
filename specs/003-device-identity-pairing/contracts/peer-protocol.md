# Contract: LAN peer protocol v1 (discovery, pairing, channel)

Normative wire format. Rationale: [research.md](../research.md) R2–R9.
All integers big-endian. Peers: IPv4 private/link-local only (R9).

## Discovery datagram (UDP, default port 27473)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic `PWSD` |
| 4 | 1 | version `0x01` |
| 5 | 32 | device ID |
| 37 | 2 | peer TCP port (1024–65535) |

Exactly 39 bytes; anything else is ignored (counted `malformed`). Sent to each in-use
interface's directed broadcast address, only while the sender has ≥ 1 pin or an active
pairing code; immediately on start / network change / code shown (each only while the sender has ≥ 1 pin or an active code), then every 30 s.
Never creates trust.

## TCP framing (default port 27472)

`frame = len:u16 (1..=1024) || body[len]`. Violations close the connection.
Each read step (other than waiting for the person's decision) times out after 10 s.

First frame: Hello (plaintext, 6 bytes) `PWSC || 0x01 || kind` with kind `0x01` channel,
`0x02` pairing. Unknown magic/version/kind → close.

## Pairing (kind 0x02): B (joiner, dials) → A (shows code)

| # | Dir | Frame body |
|---|-----|-----------|
| 1 | B→A | Hello(pair) |
| 2 | B→A | `SPAKE_B` (33 bytes, `spake2` Ed25519 side B, password = 8 digits, ids `passwsync-pair-initiator-v1` / `passwsync-pair-joiner-v1`) |
| 3 | A→B | `SPAKE_A` (33 bytes). A closes instead if it has no active code or a pairing is already in progress (B: `refused_not_pairing`). A valid frame 2 consumes the code. |
| 4 | B→A | Noise `Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s` msg1 `e` (psk = SPAKE2 output, prologue `passwsync-pair-v1` ‖ frame1 ‖ frame2 ‖ frame3) |
| 5 | A→B | msg2 `e, ee, s, es, psk`, empty payload. B: decrypt failure → `wrong_code_or_tampered`; A's ID = self → `self`; ≠ expected ID → `id_mismatch`; already pinned → `already_paired` |
| 6 | B→A | msg3 `s, se`, payload `PairHello` |
| 7 | A→B | transport `PairPending` (or `PairReject` if self / already paired / limit) |
| 8 | A→B | transport `PairCommit` after the person accepts and A has saved the pin, or `PairReject` on reject/expiry |
| 9 | B→A | transport `PairAck` after B has saved the pin; both close |

## Channel (kind 0x01): dialer → responder

Noise `Noise_XX_25519_ChaChaPoly_BLAKE2s`, prologue `passwsync-channel-v1` ‖ Hello.

| # | Dir | Body |
|---|-----|------|
| 1 | D→R | Hello(channel) |
| 2 | D→R | msg1 `e` |
| 3 | R→D | msg2 `e, ee, s, es`, empty payload. D: static ≠ pin of the dialed peer → close, warning |
| 4 | D→R | msg3 `s, se`, payload `ChannelHello` |
| 5 | R→D | transport `Welcome` if the dialer's key is pinned, else `Refused` then close |

Then transport messages only: `Keepalive` (if nothing sent for 60 s), `NameUpdate`,
`Close`. No other message type is valid in v1 (FR-031); unknown type → close. Any AEAD
failure → close. Nothing received for 150 s → close. Duplicate channel to the same peer:
keep the one whose dialer has the smaller device ID.

## Payload encoding (inside Noise)

`type:u8 || fields`; strings as `len:u8 || UTF-8` (DeviceName rules, ≤ 64 scalars, ≤ 255
bytes). Trailing bytes → protocol error.

| Type | Name | Fields |
|------|------|--------|
| 0x01 | PairHello | name |
| 0x02 | PairPending | seconds_left:u16 |
| 0x03 | PairCommit | name |
| 0x04 | PairReject | reason:u8 (1 rejected, 2 expired, 3 self, 4 already_paired, 5 limit) |
| 0x05 | PairAck | — |
| 0x10 | ChannelHello | name |
| 0x11 | Welcome | name |
| 0x12 | Refused | — |
| 0x13 | Keepalive | — |
| 0x14 | NameUpdate | name |
| 0x15 | Close | reason:u8 (1 shutdown, 2 duplicate) |

Revocation sends nothing (FR-034): the revoking side just closes the connection, and the
revoked device learns it from `Refused` on its next attempt.
