//! 003 routes: devices, pairing and revocation (contracts/http-api-network.md). They run
//! behind the unchanged 002 guard pipeline, never touch wallets and never reset wallet idle
//! timers (FR-037).

use std::net::SocketAddrV4;

use device_link::code::normalize_code;
use device_link::error::FailReason;
use device_link::identity::DeviceId;
use device_link::link::Warning;
use device_link::pairing::{AcceptError, PeerInfo};
use device_link_net::{JoinError, PairStartError, PairingView, RevokeError, Snapshot};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::AppState;
use super::api::json;
use super::request::{Method, Request};
use super::response::{JSON, Response};
use crate::net_runtime::NetState;
use crate::qr;

#[derive(Serialize)]
struct ErrorView {
    error: &'static str,
    message: &'static str,
}

fn fail(status: u16, error: &'static str, message: &'static str) -> Response {
    let mut body = Zeroizing::new(Vec::with_capacity(128));
    let _ = serde_json::to_writer(&mut *body, &ErrorView { error, message });
    Response::owned(status, JSON, body)
}

fn bad_request() -> Response {
    fail(400, "bad_request", "malformed request body")
}

fn networking_off() -> Response {
    fail(409, "networking_off", "networking is off")
}

#[derive(Serialize)]
struct Empty {}

fn ok_empty() -> Response {
    json(200, &Empty {}, 8)
}

#[derive(Serialize)]
struct SettingsView<'a> {
    network: &'static str,
    peer_port: u16,
    discovery_port: u16,
    interface: Option<&'a str>,
}

#[derive(Serialize)]
struct InterfaceView<'a> {
    name: &'a str,
    addr: String,
    prefix: u8,
}

#[derive(Serialize)]
struct StatusView<'a> {
    state: &'static str,
    port: Option<u16>,
    interfaces: Vec<InterfaceView<'a>>,
}

#[derive(Serialize)]
struct ThisDeviceView<'a> {
    name: &'a str,
    fingerprint: &'a str,
    device_id: String,
}

#[derive(Serialize)]
struct PeerView {
    device_id: String,
    fingerprint: String,
    name: Option<String>,
}

impl PeerView {
    fn of(info: &PeerInfo) -> Self {
        Self {
            device_id: info.id.to_hex(),
            fingerprint: info.id.fingerprint().to_string(),
            name: Some(info.name.as_str().to_owned()),
        }
    }

    fn id_only(id: &DeviceId) -> Self {
        Self {
            device_id: id.to_hex(),
            fingerprint: id.fingerprint().to_string(),
            name: None,
        }
    }
}

#[derive(Serialize)]
struct NearbyItem {
    device_id: String,
    fingerprint: String,
    addr: String,
    paired: bool,
}

#[derive(Serialize)]
struct PairedItem {
    device_id: String,
    fingerprint: String,
    name: String,
    paired_at: u64,
    last_seen: Option<u64>,
    status: &'static str,
}

#[derive(Serialize)]
struct QrView {
    size: usize,
    path: String,
}

#[derive(Serialize)]
struct PairingObject {
    state: &'static str,
    code: Option<Zeroizing<String>>,
    expires_in: u64,
    qr: Option<QrView>,
    qr_text: Option<Zeroizing<String>>,
    peer: Option<PeerView>,
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct JoinObject {
    state: &'static str,
    peer: Option<PeerView>,
    seconds_left: Option<u16>,
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct WarningView {
    kind: &'static str,
    addr: String,
    fingerprint: String,
    claimed_fingerprint: String,
}

#[derive(Serialize)]
struct NetworkView<'a> {
    settings: SettingsView<'a>,
    status: StatusView<'a>,
    this_device: Option<ThisDeviceView<'a>>,
    nearby: Vec<NearbyItem>,
    paired: Vec<PairedItem>,
    pairing: Option<PairingObject>,
    join: Option<JoinObject>,
    warnings: Vec<WarningView>,
}

fn reason(reason: Option<FailReason>) -> Option<&'static str> {
    reason.map(FailReason::as_str)
}

fn pairing_object(state: &AppState, view: &PairingView, snapshot: &Snapshot) -> PairingObject {
    let net = &state.net;
    let (code, qr, qr_text) = match (&view.code, net.this_device.as_ref()) {
        (Some(digits), Some(device)) => {
            let mut grouped = Zeroizing::new(String::with_capacity(9));
            grouped.push_str(&digits[..4]);
            grouped.push(' ');
            grouped.push_str(&digits[4..]);
            let text = net
                .local_peer_addr(&snapshot.interfaces)
                .map(|addr| Zeroizing::new(qr::pair_text(digits, &device.id.to_hex(), addr)));
            let qr = text.as_ref().and_then(|t| qr::svg_path(t)).map(|q| QrView {
                size: q.size,
                path: q.path,
            });
            (Some(grouped), qr, text)
        }
        _ => (None, None, None),
    };
    PairingObject {
        state: view.state,
        code,
        expires_in: view.expires_in,
        qr,
        qr_text,
        peer: view.peer.as_ref().map(PeerView::of),
        reason: reason(view.reason),
    }
}

fn warning_view(warning: &Warning) -> WarningView {
    match warning {
        Warning::UnpairedKeyAtAddress {
            addr,
            presented,
            claimed,
        } => WarningView {
            kind: "unpaired_key_at_address",
            addr: addr.to_string(),
            fingerprint: presented.fingerprint().to_string(),
            claimed_fingerprint: claimed.fingerprint().to_string(),
        },
    }
}

/// Handles `/api/network...`, `/api/pairing/...` and `/api/devices/...`; `None` when the
/// path is not one of them.
pub fn handle(state: &AppState, req: &Request, path: &str) -> Option<Response> {
    let post = req.method == Method::Post;
    let response = match path {
        "/network" => match req.method {
            Method::Get => get_network(state),
            _ => Response::method_not_allowed(),
        },
        "/pairing/start" if post => start(state),
        "/pairing/cancel" if post => {
            state.net.cancel_pairing();
            ok_empty()
        }
        "/pairing/accept" if post => accept(state, &req.body),
        "/pairing/reject" if post => {
            state.net.reject();
            ok_empty()
        }
        "/pairing/join" if post => join(state, &req.body),
        "/network/warnings/clear" if post => {
            state.net.clear_warnings();
            ok_empty()
        }
        "/pairing/start"
        | "/pairing/cancel"
        | "/pairing/accept"
        | "/pairing/reject"
        | "/pairing/join"
        | "/network/warnings/clear" => Response::method_not_allowed(),
        _ => {
            let id = path.strip_prefix("/devices/")?.strip_suffix("/revoke")?;
            if post {
                revoke(state, id)
            } else {
                Response::method_not_allowed()
            }
        }
    };
    Some(response)
}

fn get_network(state: &AppState) -> Response {
    let net = &state.net;
    let settings = &net.settings;
    let net_state = net.state();
    let snapshot = net.snapshot().unwrap_or_default();
    let port = match net_state {
        NetState::PortInUse(port) => Some(port),
        _ => None,
    };
    let view = NetworkView {
        settings: SettingsView {
            network: if settings.enabled { "on" } else { "off" },
            peer_port: settings.peer_port,
            discovery_port: settings.discovery_port,
            interface: settings.interface.as_deref(),
        },
        status: StatusView {
            state: net_state.as_str(),
            port,
            interfaces: snapshot
                .interfaces
                .iter()
                .map(|i| InterfaceView {
                    name: i.name.as_str(),
                    addr: i.addr.to_string(),
                    prefix: i.prefix,
                })
                .collect(),
        },
        this_device: net.this_device.as_ref().map(|d| ThisDeviceView {
            name: d.name.as_str(),
            fingerprint: d.fingerprint.as_str(),
            device_id: d.id.to_hex(),
        }),
        nearby: snapshot
            .nearby
            .iter()
            .map(|n| NearbyItem {
                device_id: n.id.to_hex(),
                fingerprint: n.id.fingerprint().to_string(),
                addr: n.addr.to_string(),
                paired: n.paired,
            })
            .collect(),
        paired: snapshot
            .paired
            .iter()
            .map(|p| PairedItem {
                device_id: p.id.to_hex(),
                fingerprint: p.id.fingerprint().to_string(),
                name: p.name.as_str().to_owned(),
                paired_at: p.paired_at,
                last_seen: p.last_seen,
                status: p.status.as_str(),
            })
            .collect(),
        pairing: snapshot
            .pairing
            .as_ref()
            .map(|p| pairing_object(state, p, &snapshot)),
        join: snapshot.join.as_ref().map(|j| JoinObject {
            state: j.state,
            peer: j.peer.as_ref().map(|id| {
                let mut view = PeerView::id_only(id);
                view.name = j.peer_name.as_ref().map(|n| n.as_str().to_owned());
                view
            }),
            seconds_left: j.seconds_left,
            reason: reason(j.reason),
        }),
        warnings: snapshot.warnings.iter().map(warning_view).collect(),
    };
    json(200, &view, 16 * 1024)
}

fn start(state: &AppState) -> Response {
    match state.net.start_pairing() {
        Err(_) => networking_off(),
        Ok(Err(PairStartError::Busy)) => fail(409, "busy", "a join is in progress"),
        Ok(Err(PairStartError::Limit)) => fail(409, "pair_limit", "32 devices are paired"),
        Ok(Err(PairStartError::TooManyCodes)) => {
            fail(429, "too_many_codes", "at most 5 codes per 10 minutes")
        }
        Ok(Err(PairStartError::Random)) => fail(500, "internal", "internal error"),
        Ok(Ok(())) => {
            let snapshot = state.net.snapshot().unwrap_or_default();
            match snapshot.pairing.as_ref() {
                Some(view) => json(200, &pairing_object(state, view, &snapshot), 24 * 1024),
                None => fail(500, "internal", "internal error"),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptBody {
    device_id: String,
}

#[derive(Serialize)]
struct AcceptedView {
    peer: PeerView,
}

fn accept(state: &AppState, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<AcceptBody>(body) else {
        return bad_request();
    };
    let Ok(id) = DeviceId::from_hex(&input.device_id) else {
        return fail(400, "invalid_device_id", "not a device id");
    };
    match state.net.accept(&id) {
        Ok(peer) => json(
            200,
            &AcceptedView {
                peer: PeerView::of(&peer),
            },
            256,
        ),
        Err(AcceptError::NothingPending) => fail(409, "nothing_pending", "no pairing to accept"),
        Err(AcceptError::Mismatch) => fail(
            409,
            "pairing_mismatch",
            "not the device awaiting acceptance",
        ),
        Err(AcceptError::Expired) => fail(409, "expired", "the pairing code expired"),
        Err(AcceptError::Storage) => fail(
            500,
            "storage_error",
            "the paired devices file cannot be written",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinBody {
    address: String,
    code: Zeroizing<String>,
    #[serde(default)]
    device_id: Option<String>,
}

/// IPv4 literal and port only; no host names, so no resolver is ever reached (FR-012).
fn parse_address(text: &str) -> Option<SocketAddrV4> {
    let addr: SocketAddrV4 = text.parse().ok()?;
    (addr.to_string() == text && addr.port() != 0).then_some(addr)
}

fn join(state: &AppState, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<JoinBody>(body) else {
        return bad_request();
    };
    let invalid_address = || fail(400, "invalid_address", "an IPv4 LAN address and port");
    let Some(addr) = parse_address(&input.address) else {
        return invalid_address();
    };
    if !state.net.policy().allows_v4(*addr.ip()) {
        return invalid_address();
    }
    let Ok(code) = normalize_code(&input.code) else {
        return fail(400, "invalid_code", "the code has 8 digits");
    };
    let expected = match input.device_id.as_deref() {
        None => None,
        Some(text) => match DeviceId::from_hex(text) {
            Ok(id) => Some(id),
            Err(_) => return fail(400, "invalid_device_id", "not a device id"),
        },
    };
    if expected.is_some() && expected == state.net.this_device.as_ref().map(|d| d.id) {
        return fail(409, "self", "this is this device");
    }
    match state.net.join(addr, &code, expected) {
        Err(_) => networking_off(),
        Ok(Ok(())) => json(202, &Empty {}, 8),
        Ok(Err(JoinError::InvalidAddress)) => invalid_address(),
        Ok(Err(JoinError::InvalidCode)) => fail(400, "invalid_code", "the code has 8 digits"),
        Ok(Err(JoinError::Busy)) => fail(409, "busy", "a pairing is in progress"),
        Ok(Err(JoinError::AlreadyPaired)) => fail(409, "already_paired", "already paired"),
        Ok(Err(JoinError::Limit)) => fail(409, "pair_limit", "32 devices are paired"),
        Ok(Err(JoinError::SelfPair)) => fail(409, "self", "this is this device"),
    }
}

fn revoke(state: &AppState, id: &str) -> Response {
    let not_found = || fail(404, "device_not_found", "no such paired device");
    let Ok(id) = DeviceId::from_hex(id) else {
        return not_found();
    };
    match state.net.revoke(&id) {
        Ok(()) => ok_empty(),
        Err(RevokeError::NotFound) => not_found(),
        Err(RevokeError::Storage) => fail(
            500,
            "storage_error",
            "the paired devices file cannot be written",
        ),
    }
}
