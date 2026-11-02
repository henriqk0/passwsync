//! Target 15 `share_msg` (FR-015): share control messages, strict round trip.

use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;
use wallet_sync::share::codec::{AbortReason, MAX_SECONDS_LEFT, ShareMsg};

use super::common::{check, round_trip, verdict};

pub fn seeds() -> Vec<Seed> {
    let rid = 0x0102_0304;
    let mut msgs = vec![
        ShareMsg::Redeem {
            rid,
            proof: [0x3c; 32],
        },
        ShareMsg::Pending {
            rid,
            seconds_left: 0,
        },
        ShareMsg::Pending {
            rid,
            seconds_left: 1,
        },
        ShareMsg::Pending {
            rid,
            seconds_left: 300,
        },
        ShareMsg::Pending {
            rid,
            seconds_left: 301,
        },
        ShareMsg::Offer { rid, size: 79 },
        ShareMsg::Offer {
            rid,
            size: 64 * 1024 * 1024,
        },
        ShareMsg::End { rid },
        ShareMsg::Stored { rid },
    ];
    for code in 1..=10 {
        msgs.push(ShareMsg::Abort {
            rid,
            reason: AbortReason::from_code(code).unwrap(),
        });
    }
    msgs.into_iter()
        .map(|msg| {
            let seed = Seed::new("share", msg.encode());
            match msg {
                ShareMsg::Pending { .. } => seed.field(Field::new(5, Width::U16Be, 300)),
                _ => seed,
            }
        })
        .collect()
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    verdict(|| match ShareMsg::decode(bytes) {
        Err(_) => Ok(Verdict::Rejected("Protocol")),
        Ok(msg) => {
            if let ShareMsg::Pending { seconds_left, .. } = msg {
                check(
                    (1..=MAX_SECONDS_LEFT).contains(&seconds_left),
                    "accepted seconds_left outside 1..=300",
                )?;
            }
            round_trip(
                msg.encode() == *bytes,
                "share message does not re-encode to the same bytes",
            )?;
            Ok(Verdict::Accepted)
        }
    })
}

pub fn target() -> Target {
    Target::new("share_msg", seeds, one)
        .alloc_bound(8 * 1024)
        .error_kinds(&["Protocol"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
