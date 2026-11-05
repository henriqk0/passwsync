# Contract: Peer Behaviour (009)

Behaviour other devices and the local API can observe. **Bytes on the wire do not change**: frames,
Hello values, Noise patterns, prologues and announcements are as in 003-005. Older builds keep
working.

This contract supersedes the clauses named below once 009 is implemented.

## Version negotiation

Supersedes `004/contracts/sync-protocol.md` (dialer rule) and `005/contracts/share-protocol.md`
(negotiation).

1. Every dial to a paired device starts at Hello v3.
2. A close before Noise message 2 moves **that dial** to the next lower version. All waits before
   message 2 in one dial share one step timeout.
3. When the dial ends, successful or not, nothing about the peer's version is kept. The version
   known to the device is that of the channel currently up.
4. The responder accepts Hello v1, v2 and v3, as today.
5. While a channel is up below v3, the device probes v3 at the last known address every 6 hours. A
   channel at a higher version replaces a lower one. Equal versions follow 003 FR-029.

## Pairing

Supersedes `003/spec.md` FR-021 in the parts stated.

| Contact does | Code on display | Exchange slot |
|--------------|-----------------|---------------|
| Opens and closes, or sends nothing | stays valid | not held |
| Sends a Hello only | stays valid | not held |
| Sends a malformed key message | stays valid | released |
| Sends a well-formed key message, then anything or nothing | **used up** | held until the exchange ends |
| Completes the exchange and the person accepts | accepted | released |

At most one key message is answered per code. Other 003 rules are unchanged: 300 s validity, a
refusal at once when no valid code is shown, one exchange at a time.

**Code limit**, over the same sliding 10 minutes: at most 5 codes nobody tried, and at most 20 codes
in total.

## Dialing and announcements

Supersedes `003/research.md` "A received announcement ... triggers one dial attempt" and the backoff
rule in the parts stated.

- Dials to the last known address and to announced addresses have separate slots and backoffs. A
  failure on one never delays the other.
- An announcement for a paired, unconnected peer:
  - adds or refreshes its source in that peer's table (at most 4 addresses);
  - starts a hint dial if none runs, the spacing has passed and an address is due;
  - wakes the last known path no sooner than the minimum backoff after its last attempt.
- Announcements never change the last known address or a pin. Only an authenticated channel does.
- Malformed, own-id, unknown-id, out-of-subnet and public-source datagrams change no dial state.

## Local HTTP API (`crates/passwsyncd`)

Shapes unchanged, and `crates/passwsyncd/tests` is untouched.

| Item | Change |
|------|--------|
| `POST /api/pairing/start` when refused | still 429 `too_many_codes`; message text no longer says "at most 5" |
| `pairing.state` | `exchanging` starts at the key message, so an ignored Hello keeps `waiting` |
| `pairing.reason` | same values |
| Sync peer `sync: "unsupported"` | only while a v1 channel is up |
| Share peer `share` | never `unsupported` from an unauthenticated event |

## UI text

On the device showing the code, after a used-up code: "Another device tried to pair. Show a new
code." Never includes the code, the guess or key material.

## Logs

`sync peer legacy` and `share peer unsupported` are written when an authenticated channel registers
below the version, not when a dial closes early. Existing log formats are unchanged, and no new line
contains a code or key.
