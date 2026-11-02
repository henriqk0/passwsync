//! Target 13 `sync_reassembly` (FR-014): `Reassembler::push` over fragment sequences. The
//! input is a list of records `more:u8 || len:u16be || fragment`; mutations reorder,
//! duplicate, drop and re-chunk them. The buffer never exceeds 24 KiB, an unmutated sequence
//! completes to the original message, an oversize sequence resets and errors.

use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;
use wallet_sync::codec::{MAX_CTL, MAX_FRAGMENT, Reassembler, fragment};

use super::common::{check, verdict};

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn records(fragments: &[(bool, Vec<u8>)]) -> (Vec<u8>, Vec<Field>) {
    let mut out = Vec::new();
    let mut fields = Vec::new();
    for (more, bytes) in fragments {
        out.push(u8::from(*more));
        fields.push(Field::new(out.len(), Width::U16Be, MAX_FRAGMENT as u64));
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    (out, fields)
}

fn seed(label: &'static str, fragments: &[(bool, Vec<u8>)]) -> Seed {
    let (bytes, fields) = records(fragments);
    let mut seed = Seed::new(label, bytes).chunks(Vec::new());
    // Declare the first few length fields only (the mutator picks one at random).
    for field in fields.into_iter().take(8) {
        seed = seed.field(field);
    }
    seed
}

/// The original message of each seed (unmutated sequences must complete to it).
fn originals() -> Vec<Option<Vec<u8>>> {
    vec![
        Some(message(1)),
        Some(message(999)),
        Some(message(1000)),
        Some(message(1001)),
        Some(message(MAX_CTL)),
        None,
        None,
    ]
}

pub fn seeds() -> Vec<Seed> {
    let mut out = Vec::new();
    for (label, len) in [
        ("msg-1", 1),
        ("msg-999", 999),
        ("msg-1000", 1000),
        ("msg-1001", 1001),
        ("msg-24k", MAX_CTL),
    ] {
        out.push(seed(label, &fragment(&message(len))));
    }
    // 24 KiB + 1 (hand-assembled from the encoder's fragments) and one 1001-byte fragment.
    out.push(seed("msg-24k+1", &fragment(&message(MAX_CTL + 1))));
    out.push(seed("frag-1001", &[(false, message(1001))]));
    out
}

/// Parses records leniently (stops at the first incomplete one). With chunk points, the
/// fragment contents are concatenated and re-split there (`Rechunk`).
fn fragments(input: &Input) -> Vec<(bool, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = &input.bytes[..];
    while rest.len() >= 3 {
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        let Some(bytes) = rest.get(3..3 + len) else {
            break;
        };
        out.push((rest[0] != 0, bytes.to_vec()));
        rest = &rest[3 + len..];
    }
    match &input.chunks {
        Some(points) if !points.is_empty() => {
            let all: Vec<u8> = out.into_iter().flat_map(|(_, b)| b).collect();
            let mut pieces = Vec::new();
            let mut start = 0;
            for &p in points.iter().filter(|p| **p < all.len()) {
                if p > start {
                    pieces.push((true, all[start..p].to_vec()));
                    start = p;
                }
            }
            pieces.push((false, all[start..].to_vec()));
            pieces
        }
        _ => out,
    }
}

pub fn one(input: &Input) -> Verdict {
    let frags = fragments(input);
    verdict(|| {
        let mut r = Reassembler::default();
        let mut completed = Vec::new();
        let mut errors = 0;
        let mut held = 0usize;
        for (more, bytes) in &frags {
            match r.push(*more, bytes) {
                Ok(None) => {
                    held += bytes.len();
                    check(held <= MAX_CTL, "reassembly buffer over 24 KiB")?;
                    check(r.in_progress(), "partial message not in progress")?;
                }
                Ok(Some(msg)) => {
                    check(msg.len() <= MAX_CTL, "completed message over 24 KiB")?;
                    check(msg.len() == held + bytes.len(), "completed message length")?;
                    check(!r.in_progress(), "still in progress after completion")?;
                    held = 0;
                    completed.push(msg);
                }
                Err(_) => {
                    check(
                        bytes.is_empty()
                            || bytes.len() > MAX_FRAGMENT
                            || held + bytes.len() > MAX_CTL,
                        "valid fragment refused",
                    )?;
                    check(!r.in_progress(), "error did not reset the buffer")?;
                    held = 0;
                    errors += 1;
                }
            }
        }
        if !input.mutated {
            if let Some(Some(original)) = originals().get(input.seed) {
                check(
                    completed.len() == 1 && completed[0] == *original,
                    "unmutated fragments did not complete to the original",
                )?;
            }
        }
        Ok(if errors > 0 {
            Verdict::Rejected("Protocol")
        } else if completed.is_empty() {
            Verdict::Rejected("Incomplete")
        } else {
            Verdict::Accepted
        })
    })
}

pub fn target() -> Target {
    Target::new("sync_reassembly", seeds, one)
        .alloc_bound(64 * 1024)
        .error_kinds(&["Protocol", "Incomplete"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), usize::MAX, data);
}
