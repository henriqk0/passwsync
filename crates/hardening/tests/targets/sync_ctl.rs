//! Target 12 `sync_ctl` (FR-014): sync control messages, strict round trip.

use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;
use vault_core::{DeviceId, StateVector};
use wallet_sync::codec::{
    AbortReason, Ctl, MAX_COPY, MAX_CTL, MAX_TAGS, MIN_COPY, RefuseReason, decode, encode,
};

use super::common::{check, round_trip, verdict};

fn state(n: usize) -> StateVector {
    StateVector::from_pairs(
        (0..n)
            .map(|i| (DeviceId::new(format!("fz-{i:03}")).unwrap(), i as u64 + 1))
            .collect(),
    )
    .unwrap()
}

pub fn seeds() -> Vec<Seed> {
    let round = 7;
    let tags = |n: usize| Ctl::Tags {
        round,
        entries: (0..n).map(|i| ([i as u8; 16], [!(i as u8); 16])).collect(),
    };
    let matches = |n: usize| Ctl::Matches {
        round,
        entries: (0..n).map(|i| (i as u16, i % 2 == 0)).collect(),
    };
    let count = Field::new(5, Width::U16Be, MAX_TAGS as u64);
    let size = Field::new(7, Width::U32Be, u64::from(MAX_COPY));
    let devices = Field::new(8, Width::U16Be, StateVector::MAX_DEVICES as u64);
    let mut out = Vec::new();
    for n in [0, 1, 511, 512, 513] {
        out.push(Seed::new("tags", encode(&tags(n))).field(count));
        out.push(Seed::new("matches", encode(&matches(n))).field(count));
    }
    for n in [0, 1, 3] {
        let ctl = Ctl::Summary {
            round,
            idx: 2,
            no_offer: n == 1,
            state: state(n),
        };
        out.push(Seed::new("summary", encode(&ctl)).field(devices));
    }
    out.push(Seed::new("want", encode(&Ctl::Want { round, idx: 3 })));
    for reason in [
        RefuseReason::Busy,
        RefuseReason::NotOfferable,
        RefuseReason::Changed,
        RefuseReason::Storage,
    ] {
        out.push(Seed::new(
            "refuse",
            encode(&Ctl::Refuse {
                round,
                idx: 1,
                reason,
            }),
        ));
    }
    for s in [MIN_COPY - 1, MIN_COPY, MAX_COPY, MAX_COPY + 1] {
        let ctl = Ctl::CopyStart {
            round,
            idx: 0,
            size: s,
        };
        out.push(Seed::new("copy-start", encode(&ctl)).field(size));
    }
    out.push(Seed::new(
        "copy-end",
        encode(&Ctl::CopyEnd { round, idx: 0 }),
    ));
    for reason in [
        AbortReason::ReadError,
        AbortReason::Changed,
        AbortReason::TooLarge,
        AbortReason::Storage,
        AbortReason::Cancelled,
    ] {
        out.push(Seed::new(
            "copy-abort",
            encode(&Ctl::CopyAbort {
                round,
                idx: 0,
                reason,
            }),
        ));
    }
    out.push(Seed::new("done", encode(&Ctl::Done { round })));
    out.push(Seed::new("busy", encode(&Ctl::Busy { round })));
    out
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    verdict(|| match decode(bytes) {
        Err(_) => Ok(Verdict::Rejected("Protocol")),
        Ok(ctl) => {
            check(bytes.len() <= MAX_CTL, "accepted a message over 24 KiB")?;
            match &ctl {
                Ctl::Tags { entries, .. } => {
                    check(entries.len() <= MAX_TAGS, "accepted over 512 tags")?
                }
                Ctl::Matches { entries, .. } => {
                    check(entries.len() <= MAX_TAGS, "accepted over 512 matches")?
                }
                Ctl::CopyStart { size, .. } => check(
                    (MIN_COPY..=MAX_COPY).contains(size),
                    "accepted a copy size outside 79..=64 MiB",
                )?,
                Ctl::Summary { state, .. } => check(
                    state.len() <= StateVector::MAX_DEVICES,
                    "accepted a state over 256 devices",
                )?,
                _ => {}
            }
            round_trip(
                encode(&ctl) == *bytes,
                "control message does not re-encode to the same bytes",
            )?;
            Ok(Verdict::Accepted)
        }
    })
}

pub fn target() -> Target {
    Target::new("sync_ctl", seeds, one)
        .alloc_bound(64 * 1024)
        .error_kinds(&["Protocol"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
