# Quickstart: Validating LAN Denial-of-Service Hardening

Everything below runs offline on the development host, over loopback. Contract:
[contracts/peer-behaviour.md](contracts/peer-behaviour.md).

## Reproduce the findings before the fix

`evidence/poc_lan.rs.txt` holds the review's attacks. Copied to
`crates/device-link-net/tests/poc_lan.rs` on the unfixed code:

```sh
cargo test --offline -p device-link-net --test poc_lan -- --nocapture --test-threads=1
```

Measured on 2026-11-05, in the fast test timing:

| Test | Result before the fix |
|------|----------------------|
| control | v3, 1 sync channel |
| poc1 | both devices poisoned in about 60 ms; real peers then connect at v1 with 0 sync channels |
| poc2 | correct code refused 5 of 5 times; then `TooManyCodes`, in about 200 ms |
| poc3 | channel never up during an 8 s flood (3 of 3 runs) |

## Validate the fix

```sh
cargo test --offline -p device-link -p device-link-net
```

| Scenario | Expected | Requirement |
|----------|----------|-------------|
| Early-close attack, then real announcements | v3 with sync, no wait and no restart, 10 of 10 | SC-001 |
| v1, v2 and v3 peers on either side | highest common version | SC-002 |
| During the attack, peer status | never "sync unsupported by peer" | SC-003 |
| 20 Hello-only contacts, then the correct code | pairs, 10 of 10 | SC-004 |
| One well-formed key message, then abort | code refused afterward; notice shown | SC-004, FR-009 |
| 5 burned codes, then a sixth | granted; the 21st in 10 minutes refused | SC-004 |
| 5 untried codes, then a sixth | refused as today | SC-004 |
| 1000 datagrams/s flood, one source, device moved or not | connects within 30 s, 10 of 10 | SC-005 |
| Same flood, many forged sources, device at last known address | connects within 30 s | SC-005 |
| Channel below v3, peer later offers v3, clock past 6 hours | replaced by a v3 channel | FR-006 |
| Returning device, no attack | no slower than today | SC-006 |
| 5 minute flood (`#[ignore]`, run on request) | dial rate under the bound, flat memory | SC-007 |

## Gates

```sh
scripts/gate.sh                       # includes the fuzz targets and budgets
android/verify.sh                     # fails if crates/passwsyncd/tests differs from main
python3 scripts/check_threat_model.py
git diff --quiet main -- crates/passwsyncd/tests && echo unchanged
```

Expected: every gate passes with no change under `crates/passwsyncd/tests`. A leak search of attack
run logs and notices finds no code, key or wallet data (SC-009).

## Not covered on this host

Real networks and devices: UDP source forging across a physical LAN and Android background behaviour
need [M] and [D] checks by a maintainer.
