//! Target 4 `frame` (FR-013): frame length header and body extraction, strict round trip.

use device_link::error::Error;
use device_link::wire::{MAX_FRAME, decode_frame, encode_frame, frame_len};
use hardening::mutate::{Field, Input, Seed, Width};
use hardening::oracle::Verdict;
use hardening::runner::Target;

use super::common::{check, round_trip, verdict};

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7) as u8).collect()
}

fn framed(label: &'static str, bytes: Vec<u8>) -> Seed {
    Seed::new(label, bytes).field(Field::new(0, Width::U16Be, MAX_FRAME as u64))
}

pub fn seeds() -> Vec<Seed> {
    let mut out: Vec<Seed> = [
        (1, "body-1"),
        (512, "body-512"),
        (1023, "body-1023"),
        (1024, "body-1024"),
    ]
    .into_iter()
    .map(|(len, label)| framed(label, encode_frame(&body(len)).unwrap()))
    .collect();
    // 1025: the encoder refuses it, so assemble it from the documented layout.
    let mut over = 1025u16.to_be_bytes().to_vec();
    over.extend(body(1025));
    out.push(framed("body-1025", over));
    let mut two = encode_frame(&body(10)).unwrap();
    two.extend(encode_frame(&body(20)).unwrap());
    out.push(framed("two-frames", two));
    out
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    verdict(|| match decode_frame(bytes) {
        Err(Error::Protocol) => {
            check(bytes.len() >= 2, "error without a full header")?;
            check(
                frame_len([bytes[0], bytes[1]]).is_err(),
                "error for a valid length header",
            )?;
            Ok(Verdict::Rejected("Protocol"))
        }
        Err(_) => Ok(Verdict::Rejected("other")),
        Ok(None) => {
            let complete = bytes.len() >= 2
                && frame_len([bytes[0], bytes[1]]).is_ok_and(|len| bytes.len() >= 2 + len);
            check(!complete, "incomplete reported for a complete frame")?;
            Ok(Verdict::Rejected("Incomplete"))
        }
        Ok(Some((frame, consumed))) => {
            check(
                (1..=MAX_FRAME).contains(&frame.len()),
                "body length out of 1..=1024",
            )?;
            check(
                consumed == 2 + frame.len(),
                "consumed is not 2 + body length",
            )?;
            check(
                frame == &bytes[2..consumed],
                "body is not the bytes after the header",
            )?;
            round_trip(
                encode_frame(frame).is_ok_and(|enc| enc[..] == bytes[..consumed]),
                "frame does not re-encode to the same bytes",
            )?;
            Ok(Verdict::Accepted)
        }
    })
}

pub fn target() -> Target {
    Target::new("frame", seeds, one)
        .alloc_bound(4 * 1024)
        .error_kinds(&["Protocol", "Incomplete"])
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
