//! JSON API (contracts/http-api.md "JSON API"). Request DTOs reject unknown fields and keep
//! secrets in `Zeroizing` buffers; responses are serialized into pre-sized zeroizing buffers.

use serde::{Deserialize, Serialize};
use vault_core::{EntryFields, EntryId};
use wallet_service::{Field, ServiceError, UnlockOutcome, WalletName};
use zeroize::Zeroizing;

use super::AppState;
use super::request::{Method, Request};
use super::response::{JSON, Response};
use crate::log::{LockReason, LogEvent};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWallet {
    name: String,
    password: Zeroizing<String>,
    password_confirm: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldRequest {
    field: String,
}

#[derive(Serialize)]
struct ValueView<'a> {
    value: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryInput {
    #[serde(default)]
    title: Zeroizing<String>,
    #[serde(default)]
    username: Zeroizing<String>,
    #[serde(default)]
    password: Zeroizing<String>,
    #[serde(default)]
    url: Zeroizing<String>,
    #[serde(default)]
    notes: Zeroizing<String>,
    /// Update only: keep the stored password (merged server-side, FR-024). Must not be
    /// combined with a non-empty `password`.
    #[serde(default)]
    keep_password: bool,
}

impl EntryInput {
    /// Moves every field into `EntryFields` (wiped on drop) without copying.
    fn into_fields(mut self) -> EntryFields {
        EntryFields {
            title: std::mem::take(&mut *self.title),
            username: std::mem::take(&mut *self.username),
            password: std::mem::take(&mut *self.password),
            url: std::mem::take(&mut *self.url),
            notes: std::mem::take(&mut *self.notes),
        }
    }
}

#[derive(Serialize)]
struct SettingsView {
    port: u16,
    auto_lock_minutes: u64,
    clipboard_clear_seconds: u64,
}

#[derive(Serialize)]
struct WalletView<'a> {
    name: &'a str,
    unlocked: bool,
}

#[derive(Serialize)]
struct StateView<'a> {
    settings: SettingsView,
    wallets: Vec<WalletView<'a>>,
}

#[derive(Serialize)]
struct ErrorView {
    error: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct SummaryView<'a> {
    id: String,
    title: &'a str,
    username: &'a str,
    url: &'a str,
}

#[derive(Serialize)]
struct SearchView<'a> {
    entries: Vec<SummaryView<'a>>,
}

#[derive(Serialize)]
struct EntryDetails<'a> {
    id: String,
    title: &'a str,
    username: &'a str,
    url: &'a str,
    notes: &'a str,
    created_at: i64,
    modified_at: i64,
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct LockedView<'a> {
    locked: Vec<&'a str>,
}

/// JSON escaping can grow text up to 6x (`\uXXXX`); sizing for that means serde never
/// reallocates a buffer holding credential data.
fn capacity_for(texts: &[&str]) -> usize {
    texts.iter().map(|t| t.len() * 6 + 16).sum::<usize>() + 256
}

#[derive(Serialize)]
struct IdView {
    id: String,
}

fn status_of(error: ServiceError) -> u16 {
    match error {
        ServiceError::InvalidName
        | ServiceError::PasswordTooShort
        | ServiceError::PasswordMismatch
        | ServiceError::EmptyTitle
        | ServiceError::FieldTooLarge => 400,
        ServiceError::WalletNotFound | ServiceError::EntryNotFound => 404,
        ServiceError::WalletExists => 409,
        ServiceError::WalletLocked => 423,
        ServiceError::InvalidPasswordOrCorrupted
        | ServiceError::MalformedFile
        | ServiceError::UnsupportedVersion
        | ServiceError::UnsupportedKdf
        | ServiceError::KdfParamsOutOfRange
        | ServiceError::WalletTooLarge => 422,
        ServiceError::Storage | ServiceError::Internal => 500,
    }
}

/// Serializes into a buffer sized `capacity` up front, so serde does not reallocate and
/// strand unwiped copies (it grows only if the estimate was too small).
pub fn json<T: Serialize>(status: u16, value: &T, capacity: usize) -> Response {
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    if serde_json::to_writer(&mut *body, value).is_err() {
        return error(ServiceError::Internal);
    }
    Response::owned(status, JSON, body)
}

pub fn error(error: ServiceError) -> Response {
    let view = ErrorView {
        error: error.code(),
        message: error.message(),
    };
    let mut body = Zeroizing::new(Vec::with_capacity(256));
    let _ = serde_json::to_writer(&mut *body, &view);
    Response::owned(status_of(error), JSON, body)
}

fn bad_request() -> Response {
    let view = ErrorView {
        error: "bad_request",
        message: "malformed request body",
    };
    let mut body = Zeroizing::new(Vec::with_capacity(128));
    let _ = serde_json::to_writer(&mut *body, &view);
    Response::owned(400, JSON, body)
}

fn parse<'de, T: Deserialize<'de>>(body: &'de [u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|_| bad_request())
}

/// Decodes a percent-encoded path segment into a valid wallet name.
pub fn decode_name(segment: &str) -> Result<WalletName, ServiceError> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(ServiceError::InvalidName)?;
            let hex = std::str::from_utf8(hex).map_err(|_| ServiceError::InvalidName)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| ServiceError::InvalidName)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let text = String::from_utf8(out).map_err(|_| ServiceError::InvalidName)?;
    Ok(WalletName::parse(&text)?)
}

enum Route<'a> {
    State,
    LockAll,
    Wallets,
    Wallet(&'a str, &'a str),
    Entry(&'a str, &'a str, Option<&'a str>),
}

fn route(path: &str) -> Option<Route<'_>> {
    let parts: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    Some(match parts.as_slice() {
        ["state"] => Route::State,
        ["lock-all"] => Route::LockAll,
        ["wallets"] => Route::Wallets,
        ["wallets", name, action] => Route::Wallet(name, action),
        ["wallets", name, "entries", id] => Route::Entry(name, id, None),
        ["wallets", name, "entries", id, action] => Route::Entry(name, id, Some(action)),
        _ => return None,
    })
}

/// Dispatches an admitted `/api/*` request.
pub fn handle(state: &AppState, req: &Request, path: &str) -> Response {
    let Some(route) = route(path) else {
        return Response::not_found();
    };
    let method = req.method;
    match (route, method) {
        (Route::State, Method::Get) => get_state(state),
        (Route::Wallets, Method::Post) => create_wallet(state, &req.body),
        (Route::Wallet(name, "entries"), Method::Post) => {
            with_name(name, |name| add_entry(state, &name, &req.body))
        }
        (Route::Wallet(name, "unlock"), Method::Post) => {
            with_name(name, |name| unlock(state, &name, &req.body))
        }
        (Route::Wallet(name, "search"), Method::Post) => {
            with_name(name, |name| search(state, &name, &req.body))
        }
        (Route::Entry(name, id, None), Method::Get) => {
            with_entry(name, id, |name, id| get_entry(state, &name, id))
        }
        (Route::Entry(name, id, None), Method::Put) => with_entry(name, id, |name, id| {
            update_entry(state, &name, id, &req.body)
        }),
        (Route::Entry(name, id, None), Method::Delete) => {
            with_entry(name, id, |name, id| delete_entry(state, &name, id))
        }
        (Route::Entry(name, id, Some("field")), Method::Post) => {
            with_entry(name, id, |name, id| field(state, &name, id, &req.body))
        }
        (Route::Wallet(name, "lock"), Method::Post) => {
            with_name(name, |name| lock_wallet(state, &name))
        }
        (Route::LockAll, Method::Post) => lock_all(state),
        (
            Route::State
            | Route::Wallets
            | Route::LockAll
            | Route::Wallet(_, "entries" | "unlock" | "search" | "lock")
            | Route::Entry(_, _, None | Some("field")),
            _,
        ) => Response::method_not_allowed(),
        _ => Response::not_found(),
    }
}

fn with_name(segment: &str, action: impl FnOnce(WalletName) -> Response) -> Response {
    match decode_name(segment) {
        Ok(name) => action(name),
        Err(e) => error(e),
    }
}

/// Decodes the wallet name, then the entry id (32 hex digits, else `entry_not_found`).
fn with_entry(
    segment: &str,
    id: &str,
    action: impl FnOnce(WalletName, EntryId) -> Response,
) -> Response {
    with_name(segment, |name| match id.parse::<EntryId>() {
        Ok(id) => action(name, id),
        Err(_) => error(ServiceError::EntryNotFound),
    })
}

fn get_state(state: &AppState) -> Response {
    let wallets = match state.service.list() {
        Ok(wallets) => wallets,
        Err(e) => return error(e),
    };
    let view = StateView {
        settings: SettingsView {
            port: state.settings.port,
            auto_lock_minutes: state.settings.auto_lock.as_secs() / 60,
            clipboard_clear_seconds: state.settings.clipboard_clear.as_secs(),
        },
        wallets: wallets
            .iter()
            .map(|w| WalletView {
                name: w.name.as_str(),
                unlocked: w.unlocked,
            })
            .collect(),
    };
    json(200, &view, 128 + wallets.len() * 96)
}

fn create_wallet(state: &AppState, body: &[u8]) -> Response {
    let input: CreateWallet = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    match state
        .service
        .create(&input.name, input.password, input.password_confirm)
    {
        Ok(name) => {
            state.log.emit(&LogEvent::Unlocked { wallet: &name });
            json(
                201,
                &WalletView {
                    name: name.as_str(),
                    unlocked: true,
                },
                128,
            )
        }
        Err(e) => error(e),
    }
}

fn unlock(state: &AppState, name: &WalletName, body: &[u8]) -> Response {
    let input: Unlock = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    match state.service.unlock(name, input.password) {
        Ok(outcome) => {
            if outcome == UnlockOutcome::Unlocked {
                state.log.emit(&LogEvent::Unlocked { wallet: name });
            }
            json(
                200,
                &WalletView {
                    name: name.as_str(),
                    unlocked: true,
                },
                128,
            )
        }
        Err(e) => error(e),
    }
}

fn add_entry(state: &AppState, name: &WalletName, body: &[u8]) -> Response {
    let input: EntryInput = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    if input.keep_password {
        return bad_request();
    }
    match state.service.add_entry(name, input.into_fields()) {
        Ok(id) => json(201, &IdView { id: id.to_string() }, 64),
        Err(e) => error(e),
    }
}

fn search(state: &AppState, name: &WalletName, body: &[u8]) -> Response {
    let input: Search = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let found = match state.service.search(name, &input.query) {
        Ok(found) => found,
        Err(e) => return error(e),
    };
    let capacity = found
        .iter()
        .map(|e| capacity_for(&[&e.title, &e.username, &e.url]) + 64)
        .sum::<usize>()
        + 32;
    let view = SearchView {
        entries: found
            .iter()
            .map(|e| SummaryView {
                id: e.id.to_string(),
                title: &e.title,
                username: &e.username,
                url: &e.url,
            })
            .collect(),
    };
    json(200, &view, capacity)
}

fn get_entry(state: &AppState, name: &WalletName, id: EntryId) -> Response {
    match state.service.get_entry(name, id) {
        Ok(entry) => {
            let capacity = capacity_for(&[&entry.title, &entry.username, &entry.url, &entry.notes]);
            let view = EntryDetails {
                id: entry.id.to_string(),
                title: &entry.title,
                username: &entry.username,
                url: &entry.url,
                notes: &entry.notes,
                created_at: entry.created_at,
                modified_at: entry.modified_at,
            };
            json(200, &view, capacity)
        }
        Err(e) => error(e),
    }
}

fn update_entry(state: &AppState, name: &WalletName, id: EntryId, body: &[u8]) -> Response {
    let input: EntryInput = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let result = match (input.keep_password, input.password.is_empty()) {
        (true, false) => return bad_request(),
        (true, true) => state
            .service
            .update_entry_keeping_password(name, id, input.into_fields()),
        (false, _) => state.service.update_entry(name, id, input.into_fields()),
    };
    match result {
        Ok(()) => json(200, &Empty {}, 8),
        Err(e) => error(e),
    }
}

fn delete_entry(state: &AppState, name: &WalletName, id: EntryId) -> Response {
    match state.service.delete_entry(name, id) {
        Ok(()) => json(200, &Empty {}, 8),
        Err(e) => error(e),
    }
}

/// The only route that returns a password, one value at a time (FR-026).
fn field(state: &AppState, name: &WalletName, id: EntryId, body: &[u8]) -> Response {
    let input: FieldRequest = match parse(body) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let Some(which) = Field::parse(&input.field) else {
        return bad_request();
    };
    match state.service.field(name, id, which) {
        Ok(value) => json(200, &ValueView { value: &value }, capacity_for(&[&value])),
        Err(e) => error(e),
    }
}

fn locked_response(names: &[WalletName]) -> Response {
    let view = LockedView {
        locked: names.iter().map(WalletName::as_str).collect(),
    };
    json(200, &view, 32 + names.len() * 72)
}

fn lock_wallet(state: &AppState, name: &WalletName) -> Response {
    match state.service.lock(name) {
        Ok(true) => {
            state.log.emit(&LogEvent::Locked {
                wallet: name,
                reason: LockReason::Manual,
            });
            locked_response(std::slice::from_ref(name))
        }
        Ok(false) => locked_response(&[]),
        Err(e) => error(e),
    }
}

fn lock_all(state: &AppState) -> Response {
    let locked = state.service.lock_all();
    for wallet in &locked {
        state.log.emit(&LogEvent::Locked {
            wallet,
            reason: LockReason::All,
        });
    }
    locked_response(&locked)
}
