//! QR code for pairing (FR-038), generated locally with `qrcodegen` and returned as an SVG
//! path the UI turns into an `<svg>` with DOM APIs (no external resource, CSP unchanged).

use std::fmt::Write as _;
use std::net::SocketAddrV4;
use std::time::Duration;

use device_link::code::PairingCode;
use qrcodegen::{QrCode, QrCodeEcc};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Quiet zone in modules on each side.
const BORDER: i32 = 4;

pub struct QrSvg {
    /// Width and height in modules, quiet zone included.
    pub size: usize,
    /// One `M{x} {y}h1v1h-1z` square per dark module.
    pub path: String,
}

/// `passwsync://pair?v=1&code=<8>&id=<64hex>&addr=<ip:port>`.
pub fn pair_text(code: &str, device_id: &str, addr: SocketAddrV4) -> String {
    format!("passwsync://pair?v=1&code={code}&id={device_id}&addr={addr}")
}

pub fn svg_path(text: &str) -> Option<QrSvg> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let size = qr.size();
    let mut path = String::with_capacity((size * size) as usize * 8);
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                let _ = write!(path, "M{} {}h1v1h-1z", x + BORDER, y + BORDER);
            }
        }
    }
    Some(QrSvg {
        size: (size + 2 * BORDER) as usize,
        path,
    })
}

/// 005: a new 8-digit invite code from the OS CSPRNG through the reviewed 003 generator
/// (uniform rejection sampling, wiped on drop). Validity is enforced by the share engine.
pub fn new_invite_code() -> Option<Zeroizing<String>> {
    let code = PairingCode::generate(&mut OsRng, Duration::ZERO).ok()?;
    Some(Zeroizing::new(code.digits().to_owned()))
}

/// `1234 5678`.
pub fn group_code(digits: &str) -> String {
    match (digits.get(..4), digits.get(4..)) {
        (Some(head), Some(tail)) => format!("{head} {tail}"),
        _ => digits.to_owned(),
    }
}

/// 005: `passwsync://share?v=1&code=<8 digits>&id=<64hex>&addr=<ip:port>`.
pub fn share_text(code: &str, device_id: &str, addr: SocketAddrV4) -> String {
    format!("passwsync://share?v=1&code={code}&id={device_id}&addr={addr}")
}

/// What a share QR carries.
pub struct ShareUri {
    pub code: Zeroizing<String>,
    /// 64 lowercase hex digits.
    pub device_id: String,
    pub addr: SocketAddrV4,
}

/// Longest share text accepted (the real one is about 130 characters).
const MAX_SHARE_TEXT: usize = 256;

/// Parses a share text exactly in the documented order; anything else is refused.
pub fn parse_share_text(text: &str) -> Option<ShareUri> {
    if text.len() > MAX_SHARE_TEXT {
        return None;
    }
    let rest = text.strip_prefix("passwsync://share?v=1&code=")?;
    let (code, rest) = rest.split_once("&id=")?;
    let (device_id, addr) = rest.split_once("&addr=")?;
    if code.len() != 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if device_id.len() != 64
        || !device_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let addr: SocketAddrV4 = addr.parse().ok()?;
    if addr.port() == 0 {
        return None;
    }
    Some(ShareUri {
        code: Zeroizing::new(code.to_owned()),
        device_id: device_id.to_owned(),
        addr,
    })
}
