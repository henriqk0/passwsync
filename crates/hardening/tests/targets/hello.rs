//! Target 5 `hello` (FR-013): the 6-byte Hello, strict round trip through `hello_versioned`.

use device_link::wire::{
    HELLO_LEN, HelloKind, HelloVersion, hello_versioned, parse_hello, parse_hello_versioned,
};
use hardening::mutate::{Input, Seed};
use hardening::oracle::Verdict;
use hardening::runner::Target;

use super::common::{check, round_trip, verdict};

const DOCUMENTED: [(HelloKind, HelloVersion); 4] = [
    (HelloKind::Channel, HelloVersion::V1),
    (HelloKind::Pairing, HelloVersion::V1),
    (HelloKind::Channel, HelloVersion::V2),
    (HelloKind::Channel, HelloVersion::V3),
];

pub fn seeds() -> Vec<Seed> {
    let mut out = Vec::new();
    for kind in [HelloKind::Channel, HelloKind::Pairing] {
        for version in [HelloVersion::V1, HelloVersion::V2, HelloVersion::V3] {
            out.push(Seed::new("hello", hello_versioned(kind, version).to_vec()));
        }
    }
    out
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    verdict(|| {
        let v1 = parse_hello(bytes);
        match parse_hello_versioned(bytes) {
            Ok((kind, version)) => {
                check(bytes.len() == HELLO_LEN, "accepted Hello is not 6 bytes")?;
                check(
                    DOCUMENTED.contains(&(kind, version)),
                    "accepted an undocumented Hello",
                )?;
                round_trip(
                    hello_versioned(kind, version)[..] == bytes[..],
                    "Hello does not re-encode to the same bytes",
                )?;
                check(
                    (version == HelloVersion::V1) == v1.is_ok(),
                    "parse_hello accepts other than version 1",
                )?;
                check(v1.map_or(true, |k| k == kind), "parse_hello kind differs")?;
                Ok(Verdict::Accepted)
            }
            Err(_) => {
                check(
                    v1.is_err(),
                    "parse_hello accepts what the versioned parser rejects",
                )?;
                Ok(Verdict::Rejected("Protocol"))
            }
        }
    })
}

pub fn target() -> Target {
    Target::new("hello", seeds, one)
        .alloc_bound(4 * 1024)
        .error_kinds(&["Protocol"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
