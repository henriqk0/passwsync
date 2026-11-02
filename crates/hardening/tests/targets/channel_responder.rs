//! Target 10 `channel_responder` (FR-013): `ChannelResponder::on_frame` fed a genuine
//! transcript of two paired devices with one message replaced (msg1 or msg3), for Hello v1,
//! v2 and v3. A mutated handshake message never yields a `Channel` and ends in a protocol or
//! authentication error (or the exchange stalls because the dialer already gave up).

use std::sync::OnceLock;

use hardening::mutate::{Input, Seed};
use hardening::oracle::Verdict;
use hardening::runner::Target;

use super::handshake::{ChannelSide, Substitute, channel_one, channel_run};

pub const SLOTS: usize = 2;

fn recorded() -> &'static Vec<Vec<Vec<u8>>> {
    static RECORDED: OnceLock<Vec<Vec<Vec<u8>>>> = OnceLock::new();
    RECORDED.get_or_init(|| {
        super::handshake::VERSIONS
            .iter()
            .map(|version| {
                let run = channel_run(*version, None, None);
                assert!(run.responder_channel.is_some(), "genuine handshake");
                run.to_responder
            })
            .collect()
    })
}

pub fn seeds() -> Vec<Seed> {
    let labels = ["msg1", "msg3"];
    let mut out = Vec::new();
    for per_version in recorded() {
        for (slot, label) in labels.iter().enumerate() {
            out.push(Seed::new(label, vec![0; per_version[slot].len()]));
        }
    }
    out
}

pub fn one(input: &Input) -> Verdict {
    channel_one(
        input,
        SLOTS,
        recorded(),
        ChannelSide::Responder,
        |version, sub: &Substitute<'_>| channel_run(version, Some(sub), None),
    )
}

pub fn target() -> Target {
    Target::new("channel_responder", seeds, one)
        .alloc_bound(1024 * 1024)
        .error_kinds(super::handshake::CHANNEL_KINDS)
}

pub fn one_bytes(data: &[u8]) {
    let seed = data.first().map_or(0, |b| usize::from(*b) % (SLOTS * 3));
    hardening::runner::check_bytes(&target(), seed, data.get(1..).unwrap_or_default());
}
