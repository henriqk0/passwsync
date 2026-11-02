//! Target 17 `ffi_args` (FR-013 family, SC-001): the input-taking boundary functions of the
//! Android app library with networking off, plus the share text parser. The first input byte
//! selects the entry: 0 `passwsyncd::qr::parse_share_text`, 1 `join_pairing(peer_id, code)`,
//! 2 `redeem_invitation(sender_id, code)`; for 1 and 2 the rest is split at the first NUL into
//! the id (lossy UTF-8, as the platform passes strings) and the code bytes.
//!
//! Oracles: malformed ids and codes return only documented `CoreError` kinds and change no
//! state (pairing view, paired devices); share text over its maximum length is rejected; an
//! accepted share text re-encodes to the same text (strict round trip).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::report::Render;
use hardening::runner::Target;
use passwsync_ffi::api::{Deps, Instance, PasswsyncCore};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::CoreConfig;
use passwsync_ffi::testkit::{
    FakeClipboard, FakeProcess, FakeSealer, RecordingLog, RecordingNotifier,
};
use passwsyncd::qr::{parse_share_text, share_text};
use vault_core::KdfConfig;
use wallet_service::testkit::FakeElapsedClock;

use super::common::{check, round_trip, verdict, violation};

/// Longest share text accepted (`passwsyncd::qr`, private there).
pub const MAX_SHARE_TEXT: usize = 256;
const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const KINDS: &[&str] = &[
    "Malformed",
    "InvalidUtf8",
    "InvalidInput",
    "NetworkOff",
    "NoPeer",
    "Busy",
    "Pairing",
    "Share",
];

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One core per process (networking off, in the foreground), shared by every input.
fn core() -> &'static Arc<PasswsyncCore> {
    static CORE: OnceLock<(Arc<PasswsyncCore>, Dir)> = OnceLock::new();
    &CORE
        .get_or_init(|| {
            use std::os::unix::fs::DirBuilderExt;
            let dir =
                std::env::temp_dir().join(format!("passwsync-fuzz-ffi-{}", std::process::id()));
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .unwrap();
            let core = PasswsyncCore::start_with(
                CoreConfig {
                    data_dir: dir.to_string_lossy().into_owned(),
                    eligible_interfaces: Vec::new(),
                },
                Arc::new(FakeSealer::new()),
                Arc::new(FakeClipboard::new()),
                Arc::new(RecordingLog::new()),
                Arc::new(RecordingNotifier::new()),
                Deps {
                    process: Arc::new(FakeProcess::new()),
                    elapsed: Arc::new(FakeElapsedClock::new()),
                    wallet_kdf: KdfConfig::MINIMUM,
                    instance: Arc::new(Instance::new()),
                    ..Deps::production()
                },
            )
            .expect("core starts");
            core.on_foreground();
            (core, Dir(dir))
        })
        .0
}

fn kind(error: CoreError) -> &'static str {
    match error {
        CoreError::InvalidInput => "InvalidInput",
        CoreError::NetworkOff => "NetworkOff",
        CoreError::NoPeer => "NoPeer",
        CoreError::Busy => "Busy",
        CoreError::Pairing { .. } => "Pairing",
        CoreError::Share { .. } => "Share",
        _ => "other",
    }
}

fn entry(selector: u8, id: &str, code: &[u8]) -> Vec<u8> {
    let mut out = vec![selector];
    out.extend_from_slice(id.as_bytes());
    out.push(0);
    out.extend_from_slice(code);
    out
}

fn text(t: &str) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(t.as_bytes());
    out
}

pub fn seeds() -> Vec<Seed> {
    let valid = format!("passwsync://share?v=1&code=12345678&id={ID}&addr=192.168.1.20:47100");
    let long = format!("{valid}{}", "0".repeat(MAX_SHARE_TEXT - valid.len()));
    vec![
        Seed::new("share-text", text(&valid)),
        Seed::new("share-text-port-0", text(&valid.replace(":47100", ":0"))),
        Seed::new("share-text-256", text(&long[..MAX_SHARE_TEXT])),
        Seed::new("share-text-257", text(&format!("{long}0"))),
        Seed::new("join", entry(1, ID, b"12345678")),
        Seed::new("join-grouped", entry(1, ID, b"1234 5678")),
        Seed::new("join-bad-utf8", entry(1, ID, b"\xff\xfe")),
        Seed::new("redeem", entry(2, ID, b"87654321")),
        Seed::new("redeem-short-id", entry(2, "0123", b"87654321")),
    ]
}

fn split(rest: &[u8]) -> (String, Vec<u8>) {
    match rest.iter().position(|b| *b == 0) {
        Some(at) => (
            String::from_utf8_lossy(&rest[..at]).into_owned(),
            rest[at + 1..].to_vec(),
        ),
        None => (String::from_utf8_lossy(rest).into_owned(), Vec::new()),
    }
}

pub fn one(input: &Input) -> Verdict {
    let Some((&selector, rest)) = input.bytes.split_first() else {
        return Verdict::Rejected("Malformed");
    };
    verdict(|| match selector % 3 {
        0 => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return Ok(Verdict::Rejected("InvalidUtf8"));
            };
            match parse_share_text(text) {
                None => Ok(Verdict::Rejected("Malformed")),
                Some(uri) => {
                    check(
                        text.len() <= MAX_SHARE_TEXT,
                        "accepted share text over 256 bytes",
                    )?;
                    round_trip(
                        share_text(&uri.code, &uri.device_id, uri.addr) == text,
                        "share text does not re-encode to the same text",
                    )?;
                    Ok(Verdict::Accepted)
                }
            }
        }
        which => {
            let core = core();
            let (id, code) = split(rest);
            let before = (core.pairing(), core.network().paired.len());
            let result = if which == 1 {
                core.join_pairing(id, code)
            } else {
                core.redeem_invitation(id, code)
            };
            let after = (core.pairing(), core.network().paired.len());
            if before != after {
                return Err(violation(
                    FailureKind::StateLeak,
                    "a refused call changed state",
                ));
            }
            match result {
                Ok(()) => Err(violation(
                    FailureKind::StateLeak,
                    "a call succeeded with networking off",
                )),
                Err(error) => Ok(Verdict::Rejected(kind(error))),
            }
        }
    })
}

pub fn target() -> Target {
    Target::new("ffi_args", seeds, one)
        .alloc_bound(1024 * 1024)
        .render(Render::Text)
        .error_kinds(KINDS)
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
