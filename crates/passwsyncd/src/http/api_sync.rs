//! 004 routes (contracts/http-api-sync.md): conflicts, sync status, pending copies and
//! recovery actions. Behind the unchanged 002 guard pipeline; no route returns credential
//! content for a locked wallet.

use device_link::identity::DeviceId;
use serde::{Deserialize, Serialize};
use vault_core::{EntryId, PasswordChoice, Resolution};
use wallet_service::{Field, PeerRef, ServiceError, WalletName};
use zeroize::Zeroizing;

use super::AppState;
use super::api::{bad_request, capacity_for, decode_name, error, json, parse};
use super::request::{Method, Request};
use super::response::Response;

#[derive(Serialize)]
struct ConflictItem<'a> {
    id: String,
    title: &'a str,
    versions: usize,
}

#[derive(Serialize)]
struct ConflictList<'a> {
    entries: Vec<ConflictItem<'a>>,
}

#[derive(Serialize)]
struct VersionView<'a> {
    index: usize,
    deleted: bool,
    title: Option<&'a str>,
    username: Option<&'a str>,
    url: Option<&'a str>,
    notes: Option<&'a str>,
    modified_at: i64,
    device: &'static str,
}

#[derive(Serialize)]
struct VersionsView<'a> {
    versions: Vec<VersionView<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldRequest {
    index: usize,
    field: String,
}

#[derive(Serialize)]
struct ValueView<'a> {
    value: &'a str,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Keep {
    Index(usize),
    Word(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    keep: Keep,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChooseRequest {
    keep: String,
    password: Zeroizing<String>,
}

#[derive(Serialize)]
struct Merged {
    merged: bool,
}

#[derive(Serialize)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    confirm: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dismiss {
    ids: Vec<u64>,
}

#[derive(Serialize)]
struct PeerItem {
    device_id: String,
    fingerprint: String,
    name: String,
    sync: &'static str,
    last_round_at: Option<u64>,
    last_outcome: Option<&'static str>,
}

#[derive(Serialize)]
struct WarningItem {
    id: u64,
    kind: &'static str,
    wallet: String,
    peer: Option<String>,
    at: u64,
}

#[derive(Serialize)]
struct SyncOverview {
    enabled: bool,
    interval_minutes: u64,
    running: Vec<String>,
    peers: Vec<PeerItem>,
    warnings: Vec<WarningItem>,
}

/// The `sync` object of a wallet in `GET /api/state`.
#[derive(Serialize)]
pub struct WalletSyncView {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    conflicts: u32,
    last_synced_at: Option<u64>,
}

#[derive(Serialize)]
struct PendingItem {
    peer: String,
    received_at: u64,
    status: &'static str,
}

#[derive(Serialize)]
struct WalletPeerItem {
    peer: String,
    name: String,
    position: &'static str,
    last_round_at: Option<u64>,
}

#[derive(Serialize)]
struct WalletSyncDetail {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    pending: Vec<PendingItem>,
    peers: Vec<WalletPeerItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncNow {
    wallet: Option<String>,
}

#[derive(Serialize)]
struct Created {
    created: Vec<String>,
}

/// Dispatches the 004 routes; `None` for paths that are not ours.
pub fn handle(state: &AppState, req: &Request, path: &str) -> Option<Response> {
    let parts: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    let get = req.method == Method::Get;
    let post = req.method == Method::Post;
    let response = match parts.as_slice() {
        ["wallets", name, "conflicts"] => {
            if !get {
                return Some(Response::method_not_allowed());
            }
            with_name(name, |name| conflicts(state, &name))
        }
        ["wallets", name, "conflicts", id] => {
            if !get {
                return Some(Response::method_not_allowed());
            }
            with_entry(name, id, |name, id| versions(state, &name, id))
        }
        ["wallets", name, "conflicts", id, "field"] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            with_entry(name, id, |name, id| field(state, &name, id, &req.body))
        }
        ["wallets", name, "conflicts", id, "resolve"] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            with_entry(name, id, |name, id| resolve(state, &name, id, &req.body))
        }
        ["wallets", _, "conflicts", ..] => Response::not_found(),
        ["sync"] => {
            if !get {
                return Some(Response::method_not_allowed());
            }
            overview(state)
        }
        ["sync", "now"] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            sync_now(state, &req.body)
        }
        ["wallets", name, "sync"] => {
            if !get {
                return Some(Response::method_not_allowed());
            }
            with_name(name, |name| wallet_detail(state, &name))
        }
        ["sync", "warnings", "dismiss"] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            match parse::<Dismiss>(&req.body) {
                Ok(input) => {
                    state.sync.dismiss(&input.ids);
                    json(200, &Empty {}, 8)
                }
                Err(response) => response,
            }
        }
        ["wallets", name, "sync", action @ ("accept-older" | "reset")] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            with_name(name, |name| recovery(state, &name, action, &req.body))
        }
        [
            "wallets",
            name,
            "sync",
            "pending",
            peer,
            action @ ("open" | "choose-password" | "discard"),
        ] => {
            if !post {
                return Some(Response::method_not_allowed());
            }
            with_name(name, |name| match DeviceId::from_hex(peer) {
                Ok(peer) => pending(state, &name, &peer, action, &req.body),
                Err(_) => error(ServiceError::EntryNotFound),
            })
        }
        _ => return None,
    };
    Some(response)
}

fn with_name(segment: &str, action: impl FnOnce(WalletName) -> Response) -> Response {
    match decode_name(segment) {
        Ok(name) => action(name),
        Err(e) => error(e),
    }
}

fn with_entry(
    segment: &str,
    id: &str,
    action: impl FnOnce(WalletName, EntryId) -> Response,
) -> Response {
    with_name(segment, |name| match id.parse::<EntryId>() {
        Ok(id) => action(name, id),
        Err(_) => error(wallet_service::ServiceError::EntryNotFound),
    })
}

fn conflicts(state: &AppState, name: &WalletName) -> Response {
    match state.service.conflicts(name) {
        Ok(list) => {
            let capacity = list
                .iter()
                .map(|c| capacity_for(&[&c.title]) + 64)
                .sum::<usize>()
                + 32;
            let view = ConflictList {
                entries: list
                    .iter()
                    .map(|c| ConflictItem {
                        id: c.id.to_string(),
                        title: &c.title,
                        versions: c.versions,
                    })
                    .collect(),
            };
            json(200, &view, capacity)
        }
        Err(e) => error(e),
    }
}

fn text(o: &Option<zeroize::Zeroizing<String>>) -> Option<&str> {
    o.as_ref().map(|t| t.as_str())
}

fn versions(state: &AppState, name: &WalletName, id: EntryId) -> Response {
    match state.service.conflict_versions(name, id) {
        Ok(list) => {
            let capacity = list
                .iter()
                .map(|v| {
                    capacity_for(&[
                        text(&v.title).unwrap_or(""),
                        text(&v.username).unwrap_or(""),
                        text(&v.url).unwrap_or(""),
                        text(&v.notes).unwrap_or(""),
                    ]) + 128
                })
                .sum::<usize>()
                + 32;
            let view = VersionsView {
                versions: list
                    .iter()
                    .map(|v| VersionView {
                        index: v.index,
                        deleted: v.deleted,
                        title: text(&v.title),
                        username: text(&v.username),
                        url: text(&v.url),
                        notes: text(&v.notes),
                        modified_at: v.modified_at,
                        device: if v.this_device {
                            "this device"
                        } else {
                            "unknown device"
                        },
                    })
                    .collect(),
            };
            json(200, &view, capacity)
        }
        Err(e) => error(e),
    }
}

fn field(state: &AppState, name: &WalletName, id: EntryId, body: &[u8]) -> Response {
    let input: FieldRequest = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let Some(which) = Field::parse(&input.field) else {
        return bad_request();
    };
    match state.service.conflict_field(name, id, input.index, which) {
        Ok(value) => json(200, &ValueView { value: &value }, capacity_for(&[&value])),
        Err(e) => error(e),
    }
}

fn resolve(state: &AppState, name: &WalletName, id: EntryId, body: &[u8]) -> Response {
    let input: ResolveRequest = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let how = match input.keep {
        Keep::Index(i) => Resolution::Keep(i),
        Keep::Word(word) if word == "both" => Resolution::KeepBoth,
        Keep::Word(_) => return bad_request(),
    };
    match state.service.resolve_conflict(name, id, how) {
        Ok(created) => json(
            200,
            &Created {
                created: created.iter().map(ToString::to_string).collect(),
            },
            64 + created.len() * 40,
        ),
        Err(e) => error(e),
    }
}

fn pending(
    state: &AppState,
    name: &WalletName,
    peer: &DeviceId,
    action: &str,
    body: &[u8],
) -> Response {
    let peer_ref = PeerRef(*peer.as_bytes());
    let result = match action {
        "discard" => {
            return if state.sync.discard(name, peer) {
                json(200, &Empty {}, 8)
            } else {
                error(ServiceError::EntryNotFound)
            };
        }
        "open" => {
            let input: OpenRequest = match parse(body) {
                Ok(input) => input,
                Err(response) => return response,
            };
            state
                .service
                .open_pending_with_password(name, &peer_ref, input.password)
        }
        _ => {
            let input: ChooseRequest = match parse(body) {
                Ok(input) => input,
                Err(response) => return response,
            };
            let keep = match input.keep.as_str() {
                "local" => PasswordChoice::Local,
                "copy" => PasswordChoice::Copy,
                _ => return bad_request(),
            };
            state
                .service
                .choose_password(name, &peer_ref, keep, input.password)
        }
    };
    match result {
        Ok(_) => json(200, &Merged { merged: true }, 32),
        Err(e) => error(e),
    }
}

fn networking_off() -> Response {
    let mut body = Zeroizing::new(Vec::with_capacity(96));
    let _ = serde_json::to_writer(
        &mut *body,
        &serde_json::json!({"error": "networking_off", "message": "networking is off"}),
    );
    Response::owned(409, super::response::JSON, body)
}

fn overview(state: &AppState) -> Response {
    let active = state.sync.active();
    let peers = state
        .net
        .snapshot()
        .map(|snap| {
            snap.paired
                .iter()
                .map(|p| {
                    let (last_round_at, last_outcome) = state.sync.peer_round(&p.id);
                    PeerItem {
                        device_id: p.id.to_hex(),
                        fingerprint: p.id.fingerprint().to_string(),
                        name: p.name.as_str().to_string(),
                        sync: if state.net.is_legacy(&p.id) {
                            "unsupported"
                        } else {
                            "supported"
                        },
                        last_round_at,
                        last_outcome,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let warnings = if active {
        state
            .sync
            .warnings()
            .into_iter()
            .map(|w| WarningItem {
                id: w.id,
                kind: w.kind,
                wallet: w.wallet,
                peer: w.peer.map(|p| p.to_hex()),
                at: w.at,
            })
            .collect()
    } else {
        Vec::new()
    };
    let view = SyncOverview {
        enabled: active,
        interval_minutes: state.sync.interval_minutes(),
        running: state.sync.running().iter().map(|p| p.to_hex()).collect(),
        peers,
        warnings,
    };
    json(200, &view, 1024)
}

fn recovery(state: &AppState, name: &WalletName, action: &str, body: &[u8]) -> Response {
    match parse::<Confirm>(body) {
        Ok(Confirm { confirm: true }) => {}
        Ok(_) => return bad_request(),
        Err(response) => return response,
    }
    if !state.sync.active() {
        return networking_off();
    }
    let Some((wallet, current)) = state.service.sync_facts(name) else {
        return error(ServiceError::WalletLocked);
    };
    let done = if action == "reset" {
        state.sync.reset(name, wallet, &current)
    } else {
        state.sync.accept_older(name, wallet, &current)
    };
    if done {
        json(200, &Empty {}, 8)
    } else {
        error(ServiceError::WalletNotFound)
    }
}

/// Background: never touches idle timers; no credential content.
pub fn wallet_sync_view(state: &AppState, name: &WalletName) -> WalletSyncView {
    let conflicts = state.service.conflict_count(name).unwrap_or(0);
    let (sync, last, _) = state.sync.wallet_status(name, conflicts);
    WalletSyncView {
        state: sync.word(),
        reason: sync.reason(),
        conflicts,
        last_synced_at: last,
    }
}

fn wallet_detail(state: &AppState, name: &WalletName) -> Response {
    match state.service.list() {
        Ok(list) if list.iter().any(|w| &w.name == name) => {}
        Ok(_) => return error(ServiceError::WalletNotFound),
        Err(e) => return error(e),
    }
    let conflicts = state.service.conflict_count(name).unwrap_or(0);
    let (sync, _, record) = state.sync.wallet_status(name, conflicts);
    let names: std::collections::HashMap<String, String> = state
        .net
        .snapshot()
        .map(|s| {
            s.paired
                .iter()
                .map(|p| (p.id.to_hex(), p.name.as_str().to_string()))
                .collect()
        })
        .unwrap_or_default();
    let (pending, peers) = match &record {
        Some(r) => (
            r.pending
                .iter()
                .map(|(peer, p)| PendingItem {
                    peer: peer.to_hex(),
                    received_at: p.received_at,
                    status: p.status.word(),
                })
                .collect(),
            r.peers
                .iter()
                .map(|(peer, p)| {
                    let hex = peer.to_hex();
                    WalletPeerItem {
                        name: names
                            .get(&hex)
                            .cloned()
                            .unwrap_or_else(|| "unknown device".to_string()),
                        position: wallet_sync::status::peer_position(p, state.sync.connected(peer))
                            .word(),
                        last_round_at: p.last_round_at,
                        peer: hex,
                    }
                })
                .collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let view = WalletSyncDetail {
        state: sync.word(),
        reason: sync.reason(),
        pending,
        peers,
    };
    json(200, &view, 2048)
}

fn sync_now(state: &AppState, body: &[u8]) -> Response {
    let input: SyncNow = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    if let Some(wallet) = &input.wallet {
        let name = match WalletName::parse(wallet) {
            Ok(name) => name,
            Err(e) => return error(e.into()),
        };
        match state.service.list() {
            Ok(list) if list.iter().any(|w| w.name == name) => {}
            Ok(_) => return error(ServiceError::WalletNotFound),
            Err(e) => return error(e),
        }
    }
    // Peers holding a wallet cannot be known in advance (blinded tags): a round with every
    // connected peer.
    if !state.sync.sync_now() {
        return networking_off();
    }
    json(202, &Empty {}, 8)
}
