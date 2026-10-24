# Quickstart: validating Device Identity and Pairing (003)

Validation guide, not implementation. Wire format: [contracts/peer-protocol.md](contracts/peer-protocol.md);
API: [contracts/http-api-network.md](contracts/http-api-network.md); files/config/log:
[contracts/host-runtime-network.md](contracts/host-runtime-network.md).

## Prerequisites

- Rust stable (MSRV 1.85), `cargo-deny`, `cargo-audit`; `ulimit -l 262144` (002 rule).
- For two-device scenarios: two Linux hosts on one LAN, or two network namespaces joined by
  a veth pair with `10.99.0.1/24` and `10.99.0.2/24` (root needed only to create them).

## Automated checks

```sh
cargo test --workspace                       # unit + loopback integration (testkit policy)
cargo test --workspace --release -- --ignored # SC-007 / SC-008 resource and flood tests
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit              # only RUSTSEC-2023-0089 accepted
```

Expected: all green; `device-link` tests cover pairing success/wrong code/expiry/reuse/MITM/
QR mismatch, channel replay/tamper/reorder/cross-connection rejection, file corruption.

## Manual scenarios

1. **Identity (US1)**: empty `~/.config/passwsync`, start `passwsyncd`, open the launch URL
   → Devices view shows name `passwsync device XXXX` and a fingerprint; `device-key` is 0600;
   restart → same fingerprint. `chmod 644 device-key`, set `network = on`, restart → status
   "device identity unusable", file unchanged, wallets still usable.
2. **Networking off (SC-002)**: default config → `ss -tunap | grep passwsyncd` shows only
   `127.0.0.1:27471`.
3. **Networking on**: `network = on` on both devices, restart → `ss` shows the UI listener,
   `0.0.0.0:27472/tcp`, `0.0.0.0:27473/udp`, nothing else; UI lists interfaces.
4. **Pairing (US2, SC-001)**: on A "Pair a device" → code + QR + countdown. On B pick A in
   Nearby (or type `10.99.0.1:27472`), enter the code → A shows B's name/fingerprint →
   Accept → both list each other as paired and connected within seconds. Compare
   fingerprints on both screens.
5. **Failures (SC-003)**: wrong code → both fail, A's code invalid; wait 5 min → expired;
   Reject on A → nothing pinned on either side; a 6th code within 10 min → refused.
6. **Discovery (US3)**: with no pins and no code, `tcpdump -ni any udp port 27473` shows no
   packets from that device; with a code shown, 39-byte packets every 30 s containing no
   name (SC-006).
7. **Channel and offline (US4, SC-005)**: stop B → A shows B offline within 3 min; start B
   → reconnects without re-pairing. `tcpdump` of port 27472 contains no device names or
   codes in clear.
8. **Impersonation**: delete B's `device-key`, restart B (new identity) → A refuses B and
   shows the "unpaired key at address" warning; pin unchanged.
9. **Revocation (US5)**: revoke B on A → channel closes < 1 s; B shows A "refused by peer";
   only a new pairing restores trust.
10. **Resources (SC-007)**: idle with peers online for 10 min → RSS delta < 10 MB versus
    `network = off`, CPU < 1 % (`pidstat -p <pid> 60`).
