//! Launch exchange, the UI page and the static instruction pages.

use std::path::Path;

use wallet_service::Authenticated;
use zeroize::Zeroizing;

use super::AppState;
use super::response::{HTML, Response, TEXT};
use crate::assets;
use crate::hex;
use crate::log::{ErrorClass, LogEvent, Reason};
use crate::paths::write_private_atomic;

/// `http://127.0.0.1:<port>/launch/<64 hex>\n`
pub fn launch_url(port: u16, token: &[u8; 32]) -> Zeroizing<String> {
    let token = hex::encode_secret(token);
    let mut url = Zeroizing::new(String::with_capacity(96));
    url.push_str("http://127.0.0.1:");
    url.push_str(&port.to_string());
    url.push_str("/launch/");
    url.push_str(&token);
    url.push('\n');
    url
}

pub fn write_launch_file(path: &Path, port: u16, token: &[u8; 32]) -> std::io::Result<()> {
    write_private_atomic(path, launch_url(port, token).as_bytes())
}

/// `GET /launch/{token}`: a valid unused token becomes a session cookie; the launch file is
/// rewritten with a new token (FR-004).
pub fn launch(state: &AppState, token_hex: &str) -> Response {
    let grant =
        hex::decode32(token_hex).and_then(|token| state.sessions().exchange(token.as_ref()));
    let Some(grant) = grant else {
        state.rejections.count(Reason::Session);
        return Response::fixed(403, HTML, assets::LAUNCH_INVALID_HTML);
    };
    if write_launch_file(&state.launch_file, state.port, &grant.next_launch).is_err() {
        state.log.emit(&LogEvent::Error {
            class: ErrorClass::Io,
        });
    }
    let mut cookie = Zeroizing::new(String::with_capacity(128));
    cookie.push_str("pws_session=");
    cookie.push_str(&hex::encode_secret(grant.session_id.as_ref()));
    cookie.push_str("; Path=/; HttpOnly; SameSite=Strict");
    Response::fixed(303, TEXT, b"")
        .with_header("Location", Zeroizing::new("/".to_owned()))
        .with_header("Set-Cookie", cookie)
}

/// `GET /`: the UI with the session's CSRF token, or how to open the launch address.
pub fn index(session: Option<Authenticated>) -> Response {
    let Some(session) = session else {
        return Response::fixed(200, HTML, assets::INSTRUCTIONS_HTML);
    };
    let template = std::str::from_utf8(assets::INDEX_HTML).unwrap_or_default();
    let csrf = hex::encode_secret(session.csrf().as_ref());
    let mut page = Zeroizing::new(Vec::with_capacity(template.len() + csrf.len()));
    match template.split_once(assets::CSRF_PLACEHOLDER) {
        Some((before, after)) => {
            page.extend_from_slice(before.as_bytes());
            page.extend_from_slice(csrf.as_bytes());
            page.extend_from_slice(after.as_bytes());
        }
        None => page.extend_from_slice(template.as_bytes()),
    }
    Response::owned(200, HTML, page)
}
