//! Target 2 `wallet_payload` (FR-011, FR-006 rule P): the post-decryption payload decoder,
//! reached through `vault_core::testkit::decode_payload`. The first input byte selects the
//! format (1: version 1, anything else: version 2); the rest is the plaintext.

use hardening::mutate::{Input, Seed};
use hardening::oracle::Verdict;
use hardening::runner::Target;
use vault_core::testkit::{DecodedPayload, decode_payload, encode_payload, encode_payload_v1};
use vault_core::{
    DeviceId, Entry, EntryFields, EntryId, MAX_VERSIONS, StateVector, VaultError, Version,
    VersionVector, WalletId,
};

use super::common::{check, round_trip, verdict};

pub const MAX_FIELD: usize = 1024 * 1024;

fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn fields(title: &str, notes: usize) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: "fz-user".into(),
        password: "fz-pass".into(),
        url: "https://fz.example".into(),
        notes: "z".repeat(notes),
    }
}

pub fn live(id: u8, title: &str, notes: usize) -> Entry {
    let a = device("fz-a");
    let v = Version::new_live(fields(title, notes), 10, a.clone(), VersionVector::new(&a)).unwrap();
    Entry::from_versions(EntryId::from_bytes([id; 16]), 10, vec![v]).unwrap()
}

pub fn tombstone(id: u8) -> Entry {
    let a = device("fz-a");
    let v = Version::new_deleted(20, 20, a.clone(), VersionVector::new(&a));
    Entry::from_versions(EntryId::from_bytes([id; 16]), 10, vec![v]).unwrap()
}

fn conflicted(id: u8) -> Entry {
    let (a, b) = (device("fz-a"), device("fz-b"));
    let va = Version::new_live(fields("fz-x", 4), 5, a.clone(), VersionVector::new(&a)).unwrap();
    let vb = Version::new_live(fields("fz-y", 4), 6, b.clone(), VersionVector::new(&b)).unwrap();
    Entry::from_versions(EntryId::from_bytes([id; 16]), 5, vec![va, vb]).unwrap()
}

pub fn payload(entries: Vec<Entry>) -> DecodedPayload {
    DecodedPayload {
        wallet_id: WalletId::from_bytes([0x42; 16]),
        created_at: 1_761_000_000,
        state: StateVector::from_pairs(vec![(device("fz-a"), 1), (device("fz-b"), 1)]).unwrap(),
        password_epoch: VersionVector::empty(),
        entries,
        format: 2,
    }
}

fn with_version(version: u8, plaintext: Vec<u8>) -> Vec<u8> {
    let mut out = vec![version];
    out.extend(plaintext);
    out
}

/// Replaces the 1 MiB length prefix of the 1 MiB notes field with 1 MiB + 1 and adds one
/// byte (hand-assembled: the encoder refuses it).
fn over_limit(at_limit: &[u8]) -> Vec<u8> {
    let needle: Vec<u8> = [0x80, 0x80, 0x40].into_iter().chain([b'z'; 8]).collect();
    let at = at_limit
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("1 MiB field");
    let mut out = at_limit[..at].to_vec();
    out.extend_from_slice(&[0x81, 0x80, 0x40, b'z']);
    out.extend_from_slice(&at_limit[at + 3..]);
    out
}

pub fn seeds() -> Vec<Seed> {
    let fifty: Vec<Entry> = (0..50u8).map(|i| live(i, &format!("fz-{i}"), 8)).collect();
    let mixed = vec![live(1, "fz-1", 8), tombstone(2), conflicted(3)];
    let big = encode_payload(&payload(vec![live(9, "fz-big", MAX_FIELD)]));
    vec![
        Seed::new(
            "v2-empty",
            with_version(2, encode_payload(&payload(Vec::new()))),
        ),
        Seed::new(
            "v2-one",
            with_version(2, encode_payload(&payload(vec![live(1, "fz-1", 8)]))),
        ),
        Seed::new("v2-fifty", with_version(2, encode_payload(&payload(fifty)))),
        Seed::new("v2-mixed", with_version(2, encode_payload(&payload(mixed)))),
        Seed::new("v2-1mib", with_version(2, big.clone())),
        Seed::new("v2-1mib+1", with_version(2, over_limit(&big))),
        Seed::new(
            "v1-one",
            with_version(1, encode_payload_v1(&payload(vec![live(1, "fz-1", 8)]))),
        ),
        Seed::new(
            "v1-tombstone",
            with_version(
                1,
                encode_payload_v1(&payload(vec![live(1, "fz-1", 8), tombstone(2)])),
            ),
        ),
    ]
}

fn text_fields(entry: &Entry) -> bool {
    entry.versions().iter().all(|v| {
        v.fields().is_none_or(|f| {
            [&f.title, &f.username, &f.password, &f.url, &f.notes]
                .iter()
                .all(|t| t.len() <= MAX_FIELD)
        })
    })
}

fn bounds(p: &DecodedPayload) -> Result<(), Verdict> {
    let mut ids: Vec<EntryId> = p.entries.iter().map(Entry::id).collect();
    ids.sort();
    let before = ids.len();
    ids.dedup();
    check(ids.len() == before, "accepted duplicate entry ids")?;
    check(
        p.entries.iter().all(text_fields),
        "accepted a text field over 1 MiB",
    )?;
    check(
        p.entries.iter().all(|e| e.versions().len() <= MAX_VERSIONS),
        "accepted over 16 versions",
    )?;
    let within = p.entries.iter().all(|e| {
        e.versions()
            .iter()
            .all(|v| v.version().iter().all(|(d, c)| p.state.get(d) >= c))
    });
    check(within, "accepted a version beyond the state")?;
    Ok(())
}

pub fn decode_input(bytes: &[u8]) -> (u16, &[u8]) {
    match bytes.split_first() {
        Some((1, rest)) => (1, rest),
        Some((_, rest)) => (2, rest),
        None => (2, &[]),
    }
}

pub fn one(input: &Input) -> Verdict {
    let (version, plaintext) = decode_input(&input.bytes);
    verdict(|| match decode_payload(version, plaintext) {
        Err(VaultError::InvalidPasswordOrCorrupted) => {
            Ok(Verdict::Rejected("InvalidPasswordOrCorrupted"))
        }
        Err(_) => Ok(Verdict::Rejected("other")),
        Ok(p) => {
            check(
                p.format == version,
                "format differs from the requested version",
            )?;
            bounds(&p)?;
            if !input.mutated {
                let again = if version == 1 {
                    encode_payload_v1(&p)
                } else {
                    encode_payload(&p)
                };
                round_trip(
                    again == plaintext,
                    "seed payload does not re-encode byte-identically",
                )?;
            }
            // Rule P: the re-encoding decodes to an equal value (a fixed point).
            let encoded = encode_payload(&p);
            let reread = decode_payload(2, &encoded);
            round_trip(
                reread.is_ok_and(|q| encode_payload(&q) == encoded),
                "re-encoded payload does not decode to an equal value",
            )?;
            Ok(Verdict::Accepted)
        }
    })
}

pub fn target() -> Target {
    Target::new("wallet_payload", seeds, one)
        .alloc_bound(72 * 1024 * 1024)
        .error_kinds(&["InvalidPasswordOrCorrupted"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
