# Contract: `passwsyncd` host runtime changes (network re-scope, files, config, log)

Amends [002 host-runtime.md](../../002-local-service-web-ui/contracts/host-runtime.md).
Rationale: [research.md](../research.md) R8, R10–R13.

## Sockets (re-scoped guarantee)

| `network` | Sockets the process may hold |
|-----------|-----------------------------|
| `off` (default) | the 002 UI listener `127.0.0.1:<port>` and its accepted connections. Nothing else. |
| `on` | the above + one TCP listener `0.0.0.0:<peer_port>` + one UDP socket `0.0.0.0:<discovery_port>` (both only while an eligible interface exists) + TCP connections to/from peers that pass the address policy, only for pairing or channels. |

No DNS, no internet destination, no other socket, ever. IPv6 sockets are never opened.

## Files (added)

| Path | Mode | Content | Written by |
|------|------|---------|-----------|
| `$XDG_CONFIG_HOME/passwsync/device-key` | 0600 | `passwsync-device-key-v1\n<64 hex>\n` | service, only when missing |
| `$XDG_CONFIG_HOME/passwsync/peers` | 0600 | `passwsync-peers-v1\n` + ≤ 32 lines `<pk hex64> <paired_at> <last_seen or -> <a.b.c.d:port or -> <name as hex>` | service (atomic) |

`device-key` or `peers` unreadable, malformed, permissive or not owned → networking stays
off with status `identity_unusable` / `peers_unusable`; the file is never rewritten. These
do NOT cause exit 2 (unlike 002 files): the loopback UI keeps working. The 002 `device-id`
file is unchanged.

## Configuration (added keys)

Grammar extension: value = decimal integer | `on` | `off` | `"string"` (no escapes, no
`"` inside). Same error handling as 002 (exit 2).

```text
network = off                    # on|off
peer_port = 27472                # 1024..=65535, distinct from port and discovery_port
discovery_port = 27473           # 1024..=65535, distinct
device_name = "Laptop"           # 1..64 chars, no control chars; default "passwsync device XXXX"
network_interface = "wlan0"      # optional; 1..15 of [A-Za-z0-9._-]
```

## Start-up sequence (appended after 002 step 5)

5a. Load or create `device-key` (status `identity_unusable` on error). 5b. If
`network = on` and identity ok: load `peers`, enumerate interfaces, bind TCP then UDP
(`port_in_use` on failure, the other socket closed), start `net-accept`, `net-discovery`.
Otherwise wipe the private key. Exit codes unchanged.

## Shutdown (added)

Before locking wallets: send `Close(shutdown)` on channels, close sockets, save
`last_seen`, wipe the private key and any pairing code.

## Log events (added, closed set)

`network off`, `network on peer=<port> discovery=<port> interfaces=<names>`,
`network unavailable (<identity-unusable|peers-unusable|port-in-use <port>|no-local-network>)`,
`network interfaces changed <names>`, `pairing started`, `pairing succeeded <fingerprint>`,
`pairing failed (<reason>)`, `peer connected <fingerprint>`, `peer disconnected
<fingerprint> (<timeout|closed|error|duplicate>)`, `peer refused <fingerprint> (<unpaired|revoked|key-mismatch>)`,
`refused by peer <fingerprint>`, `device revoked <fingerprint>`,
`dropped public=<n> malformed=<n> oversized=<n> overflow=<n> timeout=<n>` (at most once per
minute, only non-zero). Never: codes, keys, session keys, names in transit, payloads.
