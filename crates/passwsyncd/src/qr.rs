//! QR code for pairing (FR-038), generated locally with `qrcodegen` and returned as an SVG
//! path the UI turns into an `<svg>` with DOM APIs (no external resource, CSP unchanged).

use std::fmt::Write as _;
use std::net::SocketAddrV4;

use qrcodegen::{QrCode, QrCodeEcc};

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
