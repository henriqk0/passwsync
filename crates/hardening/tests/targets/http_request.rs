//! Target 16 `http_request` (FR-016): `passwsyncd::http::request::read_request` over an
//! in-memory reader that delivers the input in arbitrary chunks (EOF at the end, so it never
//! blocks), then `http::guard::admit` with an `AppState` holding one live session.
//!
//! Every accepted request is checked against an independent scan of the raw head; an `Api`
//! admission of a non-GET request implies the exact Host, the exact Origin, a valid session
//! and the matching CSRF token, else `GuardBypass`.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use device_link::identity::DeviceKey;
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::testkit::MemoryPeerStore;
use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::report::Render;
use hardening::runner::Target;
use host_runtime::log::{Log, Rejections};
use host_runtime::net_runtime::{IdentityError, IdentityStore, NetDeps};
use host_runtime::wiring::{HostCore, HostDirs};
use passwsyncd::config::Settings;
use passwsyncd::http::AppState;
use passwsyncd::http::guard::{Admitted, admit};
use passwsyncd::http::request::{
    MAX_BODY_BYTES, MAX_HEAD_BYTES, MAX_HEADERS, Method, RequestError, read_request,
};
use vault_core::{DeviceId, KdfConfig};
use wallet_service::testkit::FakeElapsedClock;
use wallet_service::{ServiceConfig, Sessions};

use super::common::{check, hex, verdict, violation};

pub const PORT: u16 = 41_234;
/// Placeholders the seeds carry instead of the live (random) session values, so seeds, counts
/// and printed inputs are deterministic and never show a live token. `one` swaps them in.
pub const COOKIE_PLACEHOLDER: &str =
    "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
pub const CSRF_PLACEHOLDER: &str =
    "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
const LAUNCH_PLACEHOLDER: &str = "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0";
pub const KINDS: &[&str] = &[
    "HeadTooLarge",
    "BodyTooLarge",
    "TransferEncoding",
    "BadRequest",
    "Closed",
    "Refused",
];

/// Reads `data` in the given pieces, then EOF.
pub struct ChunkReader<'a> {
    pieces: Vec<&'a [u8]>,
    at: usize,
    offset: usize,
}

impl<'a> ChunkReader<'a> {
    pub fn new(pieces: Vec<&'a [u8]>) -> Self {
        Self {
            pieces,
            at: 0,
            offset: 0,
        }
    }
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(piece) = self.pieces.get(self.at) {
            let rest = &piece[self.offset..];
            if rest.is_empty() {
                self.at += 1;
                self.offset = 0;
                continue;
            }
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.offset += n;
            return Ok(n);
        }
        Ok(0)
    }
}

struct MemoryIdentity;

impl IdentityStore for MemoryIdentity {
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError> {
        Ok(DeviceKey::from_private([0x31; 32]))
    }

    fn peer_store(&self, _own: [u8; 32], _policy: AddressPolicy) -> Arc<dyn PeerStore> {
        Arc::new(MemoryPeerStore::new())
    }
}

/// The shared state and the one live session's cookie and CSRF values (hex).
pub struct Fixture {
    pub state: AppState,
    pub cookie: String,
    pub csrf: String,
    _dir: TempDir,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_dir(path: &PathBuf) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .expect("private directory");
}

pub fn fixture() -> &'static Mutex<Fixture> {
    static FIXTURE: OnceLock<Mutex<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("passwsync-fuzz-http-{}", std::process::id()));
        let dirs = HostDirs {
            wallets: root.join("wallets"),
            sync: root.join("sync"),
            received: root.join("received"),
        };
        for d in [&root, &dirs.wallets, &dirs.sync, &dirs.received] {
            private_dir(d);
        }
        let settings = Settings {
            port: PORT,
            ..Settings::default()
        };
        let (log, _buffer) = Log::to_buffer();
        let elapsed = Arc::new(FakeElapsedClock::new());
        let core = HostCore::assemble(
            &dirs,
            &settings,
            &MemoryIdentity,
            NetDeps::production(),
            ServiceConfig {
                device: DeviceId::new("fz-http").unwrap(),
                wallet_kdf: KdfConfig::MINIMUM,
                auto_lock: Duration::from_secs(900),
            },
            elapsed.clone(),
            &log,
        );
        let mut sessions = Sessions::new().expect("sessions");
        let token = *sessions.launch_token();
        let grant = sessions.exchange(&token).expect("session");
        let cookie = hex(&grant.session_id[..]);
        let csrf = hex(&grant.csrf[..]);
        let state = AppState {
            port: PORT,
            settings,
            sessions: Mutex::new(sessions),
            rejections: Arc::new(Rejections::default()),
            log,
            launch_file: root.join("launch-url"),
            elapsed,
            service: core.service,
            net: core.net,
            sync: core.sync,
            share: core.share,
        };
        Mutex::new(Fixture {
            state,
            cookie,
            csrf,
            _dir: TempDir(root),
        })
    })
}

fn request(method: &str, path: &str, extra: &[String], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nOrigin: http://127.0.0.1:{PORT}\r\n\
         Cookie: pws_session={COOKIE_PLACEHOLDER}\r\nX-CSRF-Token: {CSRF_PLACEHOLDER}\r\n"
    );
    for line in extra {
        head.push_str(line);
        head.push_str("\r\n");
    }
    if !body.is_empty() || method != "GET" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A GET whose head is exactly `size` bytes (padding header).
fn head_of_size(size: usize) -> Vec<u8> {
    let base = request("GET", "/api/wallets", &["X-Pad: ".to_owned()], &[]);
    let pad = size.saturating_sub(base.len());
    request(
        "GET",
        "/api/wallets",
        &[format!("X-Pad: {}", "p".repeat(pad))],
        &[],
    )
}

fn headers(n: usize) -> Vec<u8> {
    // The fixed request already sends 4 headers.
    let extra: Vec<String> = (0..n.saturating_sub(4))
        .map(|i| format!("X-H{i}: v"))
        .collect();
    request("GET", "/api/wallets", &extra, &[])
}

pub fn seeds() -> Vec<Seed> {
    let launch = LAUNCH_PLACEHOLDER;
    let json = br#"{"name":"fz"}"#.to_vec();
    let chunked = |label, bytes: Vec<u8>| {
        let points = vec![1, bytes.len() / 2];
        Seed::new(label, bytes).chunks(points)
    };
    vec![
        chunked("get-api", request("GET", "/api/wallets", &[], &[])),
        chunked("post-api", request("POST", "/api/wallets", &[], &json)),
        chunked("put-api", request("PUT", "/api/wallets/fz", &[], &json)),
        chunked("delete-api", request("DELETE", "/api/wallets/fz", &[], &[])),
        chunked(
            "post-8k",
            request("POST", "/api/wallets", &[], &[b'{'; 8192]),
        ),
        chunked(
            "launch",
            request("GET", &format!("/launch/{launch}"), &[], &[]),
        ),
        chunked("static", request("GET", "/static/app.js", &[], &[])),
        chunked("index", request("GET", "/", &[], &[])),
        chunked("head-16k-1", head_of_size(MAX_HEAD_BYTES - 1)),
        chunked("head-16k", head_of_size(MAX_HEAD_BYTES)),
        chunked("head-16k+1", head_of_size(MAX_HEAD_BYTES + 1)),
        chunked("headers-48", headers(MAX_HEADERS)),
        chunked("headers-49", headers(MAX_HEADERS + 1)),
        chunked(
            "transfer-encoding",
            request(
                "POST",
                "/api/wallets",
                &["Transfer-Encoding: chunked".to_owned()],
                &json,
            ),
        ),
    ]
}

fn kind(error: RequestError) -> &'static str {
    match error {
        RequestError::HeadTooLarge => "HeadTooLarge",
        RequestError::BodyTooLarge => "BodyTooLarge",
        RequestError::TransferEncoding => "TransferEncoding",
        RequestError::BadRequest => "BadRequest",
        RequestError::Closed => "Closed",
        RequestError::Timeout => "Timeout",
    }
}

/// Independent scan of a raw request head (reference for the oracles).
struct RawHead<'a> {
    len: usize,
    target: &'a [u8],
    lines: Vec<&'a [u8]>,
}

fn raw_head(bytes: &[u8]) -> Option<RawHead<'_>> {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = &bytes[..end - 4];
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    for i in 0..head.len() {
        if head[i] == b'\n' {
            lines.push(&head[start..i.saturating_sub(1).max(start)]);
            start = i + 1;
        }
    }
    lines.push(&head[start..]);
    let first = lines.remove(0);
    let target = first.split(|b| *b == b' ').nth(1).unwrap_or_default();
    Some(RawHead {
        len: end,
        target,
        lines,
    })
}

fn header_values<'a>(head: &RawHead<'a>, name: &str) -> Vec<&'a [u8]> {
    head.lines
        .iter()
        .filter_map(|line| {
            let colon = line.iter().position(|b| *b == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(name.as_bytes())
                .then(|| line[colon + 1..].trim_ascii())
        })
        .collect()
}

fn bare_lf(head: &[u8]) -> bool {
    head.iter()
        .enumerate()
        .any(|(i, b)| *b == b'\n' && (i == 0 || head[i - 1] != b'\r'))
}

/// Replaces every occurrence of `from` by `to` (same length, so chunk points stay valid).
fn swap(bytes: &mut [u8], from: &str, to: &str) {
    let (from, to) = (from.as_bytes(), to.as_bytes());
    let mut i = 0;
    while i + from.len() <= bytes.len() {
        if &bytes[i..i + from.len()] == from {
            bytes[i..i + from.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
}

pub fn one(input: &Input) -> Verdict {
    let mut live = input.clone();
    {
        let f = fixture()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        swap(&mut live.bytes, COOKIE_PLACEHOLDER, &f.cookie);
        swap(&mut live.bytes, CSRF_PLACEHOLDER, &f.csrf);
    }
    let input = &live;
    let bytes = &input.bytes;
    let mut reader = ChunkReader::new(input.pieces());
    let req = match read_request(&mut reader) {
        Err(error) => return Verdict::Rejected(kind(error)),
        Ok(req) => req,
    };
    let f = fixture()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    verdict(|| {
        let Some(head) = raw_head(bytes) else {
            return Err(violation(
                FailureKind::ValueBound,
                "accepted a head without CRLFCRLF",
            ));
        };
        check(head.len <= MAX_HEAD_BYTES, "accepted a head over 16 KiB")?;
        check(head.lines.len() <= MAX_HEADERS, "accepted over 48 headers")?;
        check(
            !bare_lf(&bytes[..head.len]),
            "accepted a bare LF in the head",
        )?;
        check(
            header_values(&head, "transfer-encoding").is_empty(),
            "accepted Transfer-Encoding",
        )?;
        check(
            std::str::from_utf8(head.target).is_ok(),
            "accepted a non-UTF-8 target",
        )?;
        let lengths = header_values(&head, "content-length");
        let length = match lengths.as_slice() {
            [] => 0,
            [one] => {
                check(
                    !one.is_empty() && one.iter().all(u8::is_ascii_digit),
                    "accepted a non-numeric Content-Length",
                )?;
                std::str::from_utf8(one)
                    .ok()
                    .and_then(|t| t.parse::<usize>().ok())
                    .unwrap_or(usize::MAX)
            }
            _ => {
                return Err(violation(
                    FailureKind::ValueBound,
                    "accepted two Content-Length",
                ));
            }
        };
        check(length <= MAX_BODY_BYTES, "accepted a body over 8 MiB")?;
        check(
            req.body.len() == length,
            "body length differs from Content-Length",
        )?;
        check(
            bytes.get(head.len..head.len + length) == Some(&req.body[..]),
            "body differs from the bytes after the head",
        )?;
        let single = |name: &str, got: Option<&str>| {
            let values = header_values(&head, name);
            match values.as_slice() {
                [one] => std::str::from_utf8(one).ok() == got,
                _ => got.is_none(),
            }
        };
        check(
            single("host", req.host.as_deref()),
            "Host not taken from exactly one header",
        )?;
        check(
            single("origin", req.origin.as_deref()),
            "Origin not taken from exactly one header",
        )?;
        check(
            single("x-csrf-token", req.csrf.as_ref().map(|c| c.as_str())),
            "CSRF not taken from exactly one header",
        )?;
        let admitted = admit(&f.state, &req);
        if let Ok(Admitted::Api { .. }) = admitted {
            let host_ok = req.host.as_deref() == Some(f.state.host().as_str());
            let session_ok = req.session_cookie.as_ref().map(|c| c.as_str()) == Some(&f.cookie);
            let csrf_ok = req.csrf.as_ref().map(|c| c.as_str()) == Some(&f.csrf);
            let origin_ok = req.method == Method::Get
                || req.origin.as_deref() == Some(f.state.origin().as_str());
            if !(host_ok && session_ok && csrf_ok && origin_ok) {
                return Err(violation(
                    FailureKind::GuardBypass,
                    "admitted without every check",
                ));
            }
        }
        Ok(match admitted {
            Ok(_) => Verdict::Accepted,
            Err(_) => Verdict::Rejected("Refused"),
        })
    })
}

pub fn target() -> Target {
    Target::new("http_request", seeds, one)
        .alloc_bound((MAX_BODY_BYTES + MAX_HEAD_BYTES) as u64)
        .render(Render::Text)
        .error_kinds(KINDS)
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
