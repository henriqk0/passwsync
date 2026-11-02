//! Target 6 `channel_payload` (FR-013): payload decoders v1/v2/v3 with strict round trip, and
//! the same bytes sealed by a real channel and opened by its peer (`seal_any` -> `open`).

use std::cell::RefCell;
use std::rc::Rc;

use device_link::channel::Channel;
use device_link::name::DeviceName;
use device_link::wire::{CloseReason, HelloVersion, Payload, RejectReason};
use hardening::mutate::{Input, Seed};
use hardening::oracle::Verdict;
use hardening::runner::Target;

use super::common::{check, round_trip, verdict};
use super::handshake::channel_pair;

fn name(text: &str) -> DeviceName {
    DeviceName::parse(text).unwrap()
}

pub fn payloads() -> Vec<Payload> {
    let long = "fz".repeat(32);
    vec![
        Payload::PairHello { name: name("fz-a") },
        Payload::PairPending { seconds_left: 300 },
        Payload::PairCommit { name: name(&long) },
        Payload::PairReject {
            reason: RejectReason::Rejected,
        },
        Payload::PairReject {
            reason: RejectReason::Limit,
        },
        Payload::PairAck,
        Payload::ChannelHello { name: name("fz-b") },
        Payload::Welcome { name: name("fz-c") },
        Payload::Refused,
        Payload::Keepalive,
        Payload::NameUpdate { name: name("fz-d") },
        Payload::Close {
            reason: CloseReason::Shutdown,
        },
        Payload::Close {
            reason: CloseReason::Duplicate,
        },
        Payload::SyncCtl {
            more: true,
            fragment: vec![0x01; 1000],
        },
        Payload::SyncCtl {
            more: false,
            fragment: vec![0x09],
        },
        Payload::CopyData {
            bytes: vec![0x5a; 999],
        },
        Payload::ShareMsg {
            body: vec![0x04, 0, 0, 0, 1],
        },
        Payload::ShareData {
            bytes: vec![0xa5; 1000],
        },
    ]
}

fn transport(payload: &Payload) -> bool {
    matches!(
        payload,
        Payload::Keepalive
            | Payload::NameUpdate { .. }
            | Payload::Close { .. }
            | Payload::SyncCtl { .. }
            | Payload::CopyData { .. }
            | Payload::ShareMsg { .. }
            | Payload::ShareData { .. }
    )
}

pub fn seeds() -> Vec<Seed> {
    let mut out: Vec<Seed> = payloads()
        .iter()
        .map(|p| Seed::new("payload", p.encode()))
        .collect();
    // One over the chunk bound (the encoder writes it; the decoders refuse it).
    out.push(Seed::new(
        "copy-1001",
        Payload::CopyData {
            bytes: vec![1; 1001],
        }
        .encode(),
    ));
    out
}

fn decoders(bytes: &[u8]) -> Result<Option<Payload>, Verdict> {
    let v1 = Payload::decode(bytes);
    let v2 = Payload::decode_v2(bytes);
    let v3 = Payload::decode_v3(bytes);
    let kind = bytes.first().copied();
    if let Ok(p) = &v1 {
        check(
            !matches!(kind, Some(0x20 | 0x21 | 0x30 | 0x31)),
            "v1 decoder accepted a v2/v3 type",
        )?;
        check(v2.as_ref() == Ok(p), "v2 decoder disagrees with v1")?;
    }
    if let Ok(p) = &v2 {
        check(
            !matches!(kind, Some(0x30 | 0x31)),
            "v2 decoder accepted a v3 type",
        )?;
        check(v3.as_ref() == Ok(p), "v3 decoder disagrees with v2")?;
    }
    if let Ok(p) = &v3 {
        round_trip(
            p.encode() == bytes,
            "payload does not re-encode to the same bytes",
        )?;
    }
    Ok(v3.ok())
}

type Pair = Rc<RefCell<Option<(Channel, Channel)>>>;

fn through_channel(pair: &Pair, bytes: &[u8], decoded: Option<&Payload>) -> Result<(), Verdict> {
    let mut slot = pair.borrow_mut();
    if slot.is_none() {
        *slot = Some(channel_pair(HelloVersion::V3));
    }
    let (a, b) = slot.as_mut().expect("pair");
    let Ok(frame) = a.seal_any(bytes) else {
        *slot = None;
        return Ok(());
    };
    match b.open(&frame) {
        Ok(payload) => {
            check(
                Some(&payload) == decoded,
                "channel opened a payload the decoder refuses",
            )?;
            check(
                transport(&payload),
                "channel accepted a handshake-only payload",
            )?;
        }
        Err(_) => {
            check(
                !decoded.is_some_and(transport),
                "channel refused a valid transport payload",
            )?;
            check(b.is_closed(), "channel stays open after an error")?;
            *slot = None;
        }
    }
    Ok(())
}

pub fn target() -> Target {
    let pair: Pair = Rc::new(RefCell::new(None));
    Target::new("channel_payload", seeds, move |input: &Input| {
        verdict(|| {
            let decoded = decoders(&input.bytes)?;
            through_channel(&pair, &input.bytes, decoded.as_ref())?;
            Ok(match decoded {
                Some(_) => Verdict::Accepted,
                None => Verdict::Rejected("Protocol"),
            })
        })
    })
    .alloc_bound(8 * 1024)
    .error_kinds(&["Protocol"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
