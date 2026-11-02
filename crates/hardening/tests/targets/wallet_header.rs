//! Target 1 `wallet_header` (FR-010, FR-006): the wallet header checks that run before any key
//! derivation. Strict round trip of the 63-byte header.

use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;
use vault_core::testkit::{HeaderFields, header_bytes, parse_header};
use vault_core::{KdfConfig, VaultError, peek_format_version, peek_kdf_config};

use super::common::{check, round_trip, verdict};

pub const KINDS: &[&str] = &[
    "MalformedFile",
    "UnsupportedVersion",
    "UnsupportedKdf",
    "KdfParamsOutOfRange",
];
const MIN_FILE: usize = 79;
const MAX_FILE: usize = 64 * 1024 * 1024;

pub fn kind(error: &VaultError) -> &'static str {
    match error {
        VaultError::MalformedFile => "MalformedFile",
        VaultError::UnsupportedVersion(_) => "UnsupportedVersion",
        VaultError::UnsupportedKdf => "UnsupportedKdf",
        VaultError::KdfParamsOutOfRange => "KdfParamsOutOfRange",
        _ => "other",
    }
}

fn file(version: u16, kdf: KdfConfig, body: usize) -> Vec<u8> {
    let mut bytes = header_bytes(&HeaderFields {
        version,
        kdf,
        salt: [0x5a; 32],
        nonce: [0xa5; 12],
    })
    .to_vec();
    bytes.extend((0..body).map(|i| i as u8));
    bytes
}

fn header_fields(seed: Seed) -> Seed {
    seed.field(Field::new(4, Width::U16Le, 2))
        .field(Field::new(7, Width::U32Le, 1_048_576))
        .field(Field::new(11, Width::U32Le, 100))
        .field(Field::new(15, Width::U32Le, 16))
}

pub fn seeds() -> Vec<Seed> {
    let kdf = |memory_kib, iterations, parallelism| KdfConfig {
        memory_kib,
        iterations,
        parallelism,
    };
    let mut out = Vec::new();
    for (label, version, cfg) in [
        ("v2-minimum", 2, KdfConfig::MINIMUM),
        ("v2-default", 2, KdfConfig::DEFAULT),
        ("v1-minimum", 1, KdfConfig::MINIMUM),
        ("v1-default", 1, KdfConfig::DEFAULT),
        ("memory-max", 2, kdf(1_048_576, 2, 1)),
        ("memory-max+1", 2, kdf(1_048_577, 2, 1)),
        ("memory-min-1", 2, kdf(19_455, 2, 1)),
        ("iterations-max", 2, kdf(19_456, 100, 1)),
        ("iterations-max+1", 2, kdf(19_456, 101, 1)),
        ("iterations-min-1", 2, kdf(19_456, 1, 1)),
        ("lanes-max", 2, kdf(19_456, 2, 16)),
        ("lanes-max+1", 2, kdf(19_456, 2, 17)),
        ("lanes-zero", 2, kdf(19_456, 2, 0)),
        ("version-3", 3, KdfConfig::MINIMUM),
    ] {
        out.push(header_fields(Seed::new(label, file(version, cfg, 120))));
    }
    // Lengths at the bound: 79 is the smallest file, 78 one below (hand-assembled).
    out.push(header_fields(Seed::new(
        "len-79",
        file(2, KdfConfig::MINIMUM, 16),
    )));
    out.push(header_fields(Seed::new(
        "len-78",
        file(2, KdfConfig::MINIMUM, 15),
    )));
    let mut kdf_id = file(2, KdfConfig::MINIMUM, 40);
    kdf_id[6] = 2;
    out.push(header_fields(Seed::new("kdf-id-2", kdf_id)));
    out
}

pub fn one(input: &Input) -> Verdict {
    oracle(&input.bytes)
}

pub fn oracle(bytes: &[u8]) -> Verdict {
    verdict(|| {
        let kdf = peek_kdf_config(bytes);
        let version = peek_format_version(bytes);
        let header = parse_header(bytes);
        // The three entry points run the same checks: same outcome and error kind.
        let kinds = [
            kdf.as_ref().err().map(kind),
            version.as_ref().err().map(kind),
            header.as_ref().err().map(kind),
        ];
        check(
            kinds[0] == kinds[1] && kinds[1] == kinds[2],
            "header entry points disagree",
        )?;
        if !(MIN_FILE..=MAX_FILE).contains(&bytes.len()) {
            check(
                kinds[2] == Some("MalformedFile"),
                "length outside 79..=64 MiB not MalformedFile",
            )?;
        }
        match header {
            Err(error) => Ok(Verdict::Rejected(kind(&error))),
            Ok(fields) => {
                check(fields.kdf.validate().is_ok(), "accepted KDF out of range")?;
                check(matches!(fields.version, 1 | 2), "accepted unknown version")?;
                check(kdf.ok() == Some(fields.kdf), "peeked KDF differs")?;
                check(
                    version.ok() == Some(fields.version),
                    "peeked version differs",
                )?;
                round_trip(
                    header_bytes(&fields)[..] == bytes[..63],
                    "header does not re-encode to the same 63 bytes",
                )?;
                Ok(Verdict::Accepted)
            }
        }
    })
}

pub fn target() -> Target {
    Target::new("wallet_header", seeds, one)
        .alloc_bound(64 * 1024 * 1024)
        .error_kinds(KINDS)
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
