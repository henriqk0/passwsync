//! Target 7 `discovery` (FR-013): LAN announcements, strict round trip.

use device_link::discovery::{ANNOUNCE_LEN, decode_announce, encode_announce};
use device_link::error::DropReason;
use device_link::identity::DeviceId;
use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;

use super::common::{check, round_trip, verdict};

fn own() -> DeviceId {
    DeviceId::from_public(&[0x11; 32])
}

fn other() -> DeviceId {
    DeviceId::from_public(&[0x22; 32])
}

pub fn seeds() -> Vec<Seed> {
    let port = Field::new(37, Width::U16Be, 1024);
    [
        ("port-1024", other(), 1024),
        ("port-65535", other(), 65_535),
        ("port-1023", other(), 1023),
        ("own-id", own(), 40_000),
    ]
    .into_iter()
    .map(|(label, id, p)| Seed::new(label, encode_announce(&id, p).to_vec()).field(port))
    .collect()
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    verdict(|| match decode_announce(bytes, &own()) {
        Ok((id, port)) => {
            check(
                bytes.len() == ANNOUNCE_LEN,
                "accepted announcement is not 39 bytes",
            )?;
            check(&bytes[..5] == b"PWSD\x01", "accepted a wrong magic")?;
            check(port >= 1024, "accepted a port below 1024")?;
            check(id != own(), "accepted our own id")?;
            round_trip(
                encode_announce(&id, port)[..] == bytes[..],
                "announcement does not re-encode to the same bytes",
            )?;
            Ok(Verdict::Accepted)
        }
        Err(DropReason::Malformed) => Ok(Verdict::Rejected("Malformed")),
        Err(_) => Ok(Verdict::Rejected("other")),
    })
}

pub fn target() -> Target {
    Target::new("discovery", seeds, one)
        .alloc_bound(4 * 1024)
        .error_kinds(&["Malformed"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
