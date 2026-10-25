//! 005 routes: wallet sharing (contracts/http-api-share.md). Behind the unchanged 002 guard
//! pipeline. Only `POST /api/wallets/{name}/share` counts as activity on a wallet. No
//! response carries a code after redemption, a proof, a wallet id or credential data.

use std::net::SocketAddrV4;

use device_link::code::normalize_code;
use device_link::identity::DeviceId;
use serde::{Deserialize, Serialize};
use wallet_service::ServiceError;
use wallet_sync::ports::{PeerId, ReceivedStore};
use wallet_sync::share::{CancelOutcome, InvitationView, NoticeKind, RECEIVED_RETENTION_SECS};
use zeroize::Zeroizing;

use super::AppState;
use super::api::{decode_name, json};
use super::request::{Method, Request};
use super::response::{JSON, Response};
use crate::qr;
use crate::share_runtime::ShareError;
use crate::sync_runtime::device;

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

#[derive(Serialize)]
struct ReasonError {
    error: &'static str,
    message: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct ExistingError<'a> {
    error: &'static str,
    message: &'static str,
    existing: &'a str,
}

fn bad_request() -> Response {
    fail(400, "bad_request", "malformed request body")
}

#[derive(Serialize)]
struct Empty {}

fn ok_empty(status: u16) -> Response {
    json(status, &Empty {}, 8)
}

pub(crate) fn share_error(error: ShareError) -> Response {
    match error {
        ShareError::NetworkingOff => fail(409, "networking_off", "networking is off"),
        ShareError::WalletNotFound => super::api::error(ServiceError::WalletNotFound),
        ShareError::WalletLocked => fail(423, "wallet_locked", "wallet is locked"),
        ShareError::LockedCancelled => fail(
            409,
            "wallet_locked",
            "the wallet was locked; the invitation was cancelled",
        ),
        ShareError::NotEligible(reason) => json(
            409,
            &ReasonError {
                error: "not_eligible",
                message: "this wallet cannot be shared now",
                reason,
            },
            160,
        ),
        ShareError::DeviceNotFound => fail(404, "device_not_found", "no such paired device"),
        ShareError::PeerUnsupported => fail(
            409,
            "peer_unsupported",
            "this device does not support sharing",
        ),
        ShareError::Busy => fail(409, "busy", "a share is in progress"),
        ShareError::TooManyInvitations => fail(
            429,
            "too_many_invitations",
            "at most 5 invitations per 10 minutes",
        ),
        ShareError::NothingPending => fail(409, "nothing_pending", "no share to accept"),
        ShareError::Mismatch => fail(409, "share_mismatch", "not the device awaiting acceptance"),
        ShareError::Expired => fail(409, "expired", "the invitation expired"),
        ShareError::SenderError => fail(500, "storage_error", "the wallet file could not be read"),
        ShareError::SelfDevice => fail(409, "self", "this is this device"),
        ShareError::ReceivedLimit => fail(
            409,
            "received_limit",
            "8 received wallets already wait for opening",
        ),
        ShareError::ReceivedNotFound => fail(404, "received_not_found", "no such received wallet"),
        ShareError::AlreadyPresent(existing) => json(
            409,
            &ExistingError {
                error: "already_present",
                message: "this wallet is already on this device",
                existing: &existing,
            },
            192,
        ),
        ShareError::Service(e) => super::api::error(e),
        ShareError::Internal => fail(500, "internal", "internal error"),
    }
}

#[derive(Serialize)]
struct PeerView {
    device_id: String,
    fingerprint: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct PeerItem {
    device_id: String,
    fingerprint: String,
    name: String,
    status: &'static str,
    share: &'static str,
}

#[derive(Serialize)]
struct QrView {
    size: usize,
    path: String,
}

#[derive(Serialize)]
struct ProgressSent {
    sent: u64,
    size: u64,
}

#[derive(Serialize)]
struct ProgressReceived {
    received: u64,
    size: u64,
}

#[derive(Serialize)]
struct InvitationObject {
    state: &'static str,
    wallet: String,
    recipient: PeerView,
    code: Option<Zeroizing<String>>,
    expires_in: u64,
    qr: Option<QrView>,
    qr_text: Option<Zeroizing<String>>,
    progress: Option<ProgressSent>,
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct ReceiveObject {
    state: &'static str,
    sender: Option<PeerView>,
    seconds_left: Option<u16>,
    progress: Option<ProgressReceived>,
    reason: Option<&'static str>,
    received_id: Option<String>,
}

#[derive(Serialize)]
struct ReceivedItem {
    id: String,
    sender: PeerView,
    received_at: u64,
    expires_at: u64,
    size: u64,
}

#[derive(Serialize)]
struct NoticeItem {
    id: u64,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    existing: Option<String>,
    at: u64,
}

#[derive(Serialize)]
struct ShareView {
    available: bool,
    unavailable_reason: Option<&'static str>,
    peers: Vec<PeerItem>,
    invitation: Option<InvitationObject>,
    receive: Option<ReceiveObject>,
    received: Vec<ReceivedItem>,
    notices: Vec<NoticeItem>,
}

fn hex16(bytes: &[u8; 16]) -> String {
    crate::hex::encode(bytes)
}

fn parse_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, i) in out.iter_mut().zip((0..32).step_by(2)) {
        *slot = u8::from_str_radix(&text[i..i + 2], 16).ok()?;
    }
    Some(out)
}

/// The peer object of `peer`: name from the 003 pins when known.
fn peer_view(state: &AppState, peer: &PeerId) -> PeerView {
    let id = device(*peer);
    let name = state.net.snapshot().and_then(|s| {
        s.paired
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.as_str().to_owned())
    });
    PeerView {
        device_id: id.to_hex(),
        fingerprint: id.fingerprint().to_string(),
        name,
    }
}

fn invitation_object(state: &AppState, view: &InvitationView) -> InvitationObject {
    let (code, qr, qr_text) = match (&view.code, state.net.this_device.as_ref()) {
        (Some(digits), Some(this)) => {
            let grouped = Zeroizing::new(qr::group_code(digits));
            let text = state
                .net
                .snapshot()
                .and_then(|s| state.net.local_peer_addr(&s.interfaces))
                .map(|addr| Zeroizing::new(qr::share_text(digits, &this.id.to_hex(), addr)));
            let qr = text.as_ref().and_then(|t| qr::svg_path(t)).map(|q| QrView {
                size: q.size,
                path: q.path,
            });
            (Some(grouped), qr, text)
        }
        _ => (None, None, None),
    };
    InvitationObject {
        state: view.state,
        wallet: view.wallet.clone(),
        recipient: peer_view(state, &view.recipient),
        code,
        expires_in: view.expires_in,
        qr,
        qr_text,
        progress: view
            .progress
            .map(|(sent, size)| ProgressSent { sent, size }),
        reason: view.reason,
    }
}

fn get_share(state: &AppState) -> Response {
    let share = &state.share;
    let unavailable = share.unavailable_reason();
    let view = share.core().engine().view();
    let snapshot = state.net.snapshot().unwrap_or_default();
    let peers = snapshot
        .paired
        .iter()
        .map(|p| PeerItem {
            device_id: p.id.to_hex(),
            fingerprint: p.id.fingerprint().to_string(),
            name: p.name.as_str().to_owned(),
            status: p.status.as_str(),
            share: share.core().peer_share(&p.id),
        })
        .collect();
    let received = if share.received_unusable() {
        Vec::new()
    } else {
        share.core().received.list().unwrap_or_default()
    };
    let notices = view
        .notices
        .iter()
        .map(|n| {
            let mut item = NoticeItem {
                id: n.id,
                kind: "",
                sender: None,
                count: None,
                existing: None,
                at: n.at,
            };
            match &n.kind {
                NoticeKind::ReceivedExpired { sender } => {
                    item.kind = "received_expired";
                    item.sender = Some(device(*sender).fingerprint().to_string());
                }
                NoticeKind::ReceivedDeletedRevoked { sender } => {
                    item.kind = "received_deleted_revoked";
                    item.sender = Some(device(*sender).fingerprint().to_string());
                }
                NoticeKind::ReceivedCleaned { count } => {
                    item.kind = "received_cleaned";
                    item.count = Some(*count);
                }
                NoticeKind::AlreadyPresent { local_name } => {
                    item.kind = "already_present";
                    item.existing = Some(local_name.clone());
                }
            }
            item
        })
        .collect();
    let body = ShareView {
        available: unavailable.is_none(),
        unavailable_reason: unavailable,
        peers,
        invitation: view
            .invitation
            .as_ref()
            .map(|inv| invitation_object(state, inv)),
        receive: view.receive.as_ref().map(|r| ReceiveObject {
            state: r.state,
            sender: r.sender.as_ref().map(|p| peer_view(state, p)),
            seconds_left: r.seconds_left,
            progress: r
                .progress
                .map(|(received, size)| ProgressReceived { received, size }),
            reason: r.reason,
            received_id: r.received_id.as_ref().map(hex16),
        }),
        received: received
            .iter()
            .map(|m| ReceivedItem {
                id: hex16(&m.id),
                sender: peer_view(state, &m.sender),
                received_at: m.received_at,
                expires_at: m.received_at + RECEIVED_RETENTION_SECS,
                size: m.size,
            })
            .collect(),
        notices,
    };
    json(200, &body, 24 * 1024)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBody {
    device_id: String,
}

fn parse_device(body: &[u8]) -> Result<DeviceId, Response> {
    let input: DeviceBody = serde_json::from_slice(body).map_err(|_| bad_request())?;
    DeviceId::from_hex(&input.device_id)
        .map_err(|_| fail(400, "invalid_device_id", "not a device id"))
}

fn create(state: &AppState, segment: &str, body: &[u8]) -> Response {
    // The network check comes first (contracts/http-api-share.md).
    if state.share.unavailable_reason().is_some() {
        return share_error(ShareError::NetworkingOff);
    }
    let name = match decode_name(segment) {
        Ok(name) => name,
        Err(e) => return super::api::error(e),
    };
    let recipient = match parse_device(body) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match state.share.create(&name, &recipient) {
        Ok(()) => match state.share.core().engine().view().invitation {
            Some(view) => json(200, &invitation_object(state, &view), 16 * 1024),
            None => fail(500, "internal", "internal error"),
        },
        Err(e) => share_error(e),
    }
}

#[derive(Serialize)]
struct StateOnly {
    state: &'static str,
}

fn accept(state: &AppState, body: &[u8]) -> Response {
    let recipient = match parse_device(body) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match state.share.accept(&recipient) {
        Ok(()) => json(
            200,
            &StateOnly {
                state: "transferring",
            },
            32,
        ),
        Err(e) => share_error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveBody {
    code: Zeroizing<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

/// IPv4 literal and port only (003 policy; no resolver).
fn parse_address(text: &str) -> Option<SocketAddrV4> {
    let addr: SocketAddrV4 = text.parse().ok()?;
    (addr.to_string() == text && addr.port() != 0).then_some(addr)
}

fn receive(state: &AppState, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<ReceiveBody>(body) else {
        return bad_request();
    };
    let Ok(code) = normalize_code(&input.code) else {
        return fail(400, "invalid_code", "the code has 8 digits");
    };
    let hint = match input.address.as_deref() {
        None => None,
        Some(text) => match parse_address(text) {
            Some(addr) if state.net.policy().allows_v4(*addr.ip()) => Some(addr),
            _ => return fail(400, "invalid_address", "an IPv4 LAN address and port"),
        },
    };
    let sender = match input.device_id.as_deref() {
        None => None,
        Some(text) => match DeviceId::from_hex(text) {
            Ok(id) => Some(id),
            Err(_) => return fail(400, "invalid_device_id", "not a device id"),
        },
    };
    if sender.is_none() && hint.is_none() {
        return fail(400, "missing_sender", "choose a device or enter an address");
    }
    match state.share.redeem(code, sender, hint) {
        Ok(()) => ok_empty(202),
        Err(e) => share_error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBody {
    name: String,
    password: Zeroizing<String>,
}

#[derive(Serialize)]
struct OpenedView<'a> {
    name: &'a str,
    unlocked: bool,
}

fn open(state: &AppState, id: &str, body: &[u8]) -> Response {
    let Some(id) = parse_hex16(id) else {
        return share_error(ShareError::ReceivedNotFound);
    };
    let Ok(input) = serde_json::from_slice::<OpenBody>(body) else {
        return bad_request();
    };
    match state.share.open(id, &input.name, input.password) {
        Ok(name) => json(
            200,
            &OpenedView {
                name: name.as_str(),
                unlocked: true,
            },
            128,
        ),
        Err(e) => share_error(e),
    }
}

#[derive(Serialize)]
struct Delivered {
    already_delivered: bool,
}

fn cancel(state: &AppState) -> Response {
    match state.share.cancel() {
        CancelOutcome::Cancelled => json(200, &StateOnly { state: "cancelled" }, 32),
        CancelOutcome::AlreadyDelivered => json(
            200,
            &Delivered {
                already_delivered: true,
            },
            32,
        ),
        CancelOutcome::Nothing => ok_empty(200),
    }
}

fn discard(state: &AppState, id: &str) -> Response {
    let Some(id) = parse_hex16(id) else {
        return share_error(ShareError::ReceivedNotFound);
    };
    match state.share.discard(id) {
        Ok(()) => ok_empty(200),
        Err(e) => share_error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DismissBody {
    ids: Vec<u64>,
}

fn dismiss(state: &AppState, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<DismissBody>(body) else {
        return bad_request();
    };
    state.share.dismiss(&input.ids);
    ok_empty(200)
}

/// Handles the sharing routes; `None` when the path is not one of them.
pub fn handle(state: &AppState, req: &Request, path: &str) -> Option<Response> {
    let post = req.method == Method::Post;
    let response = match path {
        "/share" => match req.method {
            Method::Get => get_share(state),
            _ => Response::method_not_allowed(),
        },
        "/share/accept" if post => accept(state, &req.body),
        "/receive" if post => receive(state, &req.body),
        "/share/cancel" if post => cancel(state),
        "/share/reject" if post => match state.share.reject() {
            Ok(()) => ok_empty(200),
            Err(e) => share_error(e),
        },
        "/receive/cancel" if post => {
            state.share.cancel_redemption();
            ok_empty(200)
        }
        "/share/notices/dismiss" if post => dismiss(state, &req.body),
        "/share/accept"
        | "/receive"
        | "/share/cancel"
        | "/share/reject"
        | "/receive/cancel"
        | "/share/notices/dismiss" => Response::method_not_allowed(),
        _ => {
            if let Some(rest) = path.strip_prefix("/received/") {
                let (id, action) = rest.split_once('/')?;
                match (action, post) {
                    ("open", true) => open(state, id, &req.body),
                    ("discard", true) => discard(state, id),
                    ("open" | "discard", false) => Response::method_not_allowed(),
                    _ => return None,
                }
            } else {
                let rest = path.strip_prefix("/wallets/")?;
                let (segment, action) = rest.split_once('/')?;
                if action != "share" {
                    return None;
                }
                if post {
                    create(state, segment, &req.body)
                } else {
                    Response::method_not_allowed()
                }
            }
        }
    };
    Some(response)
}
