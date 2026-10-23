//! The request protection pipeline (contracts/http-api.md "Transport rules", research R7):
//! Host → method → route → session → CSRF → Origin. Each refusal is counted by reason and
//! answered with a fixed body.

use wallet_service::{Authenticated, Sessions};

use super::AppState;
use super::request::{Method, Request};
use super::response::Response;
use crate::assets;
use crate::hex;
use crate::log::Reason;

/// A request that passed every check that applies to its route.
pub enum Admitted<'a> {
    Launch {
        token: &'a str,
    },
    Index {
        session: Option<Authenticated>,
    },
    Static {
        content_type: &'static str,
        bytes: &'static [u8],
    },
    Api {
        session: Authenticated,
        path: &'a str,
    },
    NotFound,
}

fn reject(state: &AppState, reason: Reason, response: Response) -> Response {
    state.rejections.count(reason);
    response
}

pub fn authenticate(state: &AppState, req: &Request) -> Option<Authenticated> {
    let cookie = req.session_cookie.as_ref()?;
    let id = hex::decode32(cookie)?;
    state.sessions().authenticate(id.as_ref())
}

pub fn admit<'a>(state: &AppState, req: &'a Request) -> Result<Admitted<'a>, Response> {
    // DNS rebinding defence: before routing (FR-007).
    if req.host.as_deref() != Some(state.host().as_str()) {
        return Err(reject(state, Reason::Host, Response::forbidden()));
    }
    if req.method == Method::Other {
        return Err(Response::method_not_allowed());
    }
    let path = req.path.as_str();
    let get_only = || {
        if req.method == Method::Get {
            Ok(())
        } else {
            Err(Response::method_not_allowed())
        }
    };
    if let Some(token) = path.strip_prefix("/launch/") {
        get_only()?;
        return Ok(Admitted::Launch { token });
    }
    if path == "/" {
        get_only()?;
        return Ok(Admitted::Index {
            session: authenticate(state, req),
        });
    }
    if path.starts_with("/static/") {
        get_only()?;
        return Ok(match assets::static_asset(path) {
            Some((content_type, bytes)) => Admitted::Static {
                content_type,
                bytes,
            },
            None => Admitted::NotFound,
        });
    }
    let Some(api_path) = path
        .strip_prefix("/api")
        .filter(|p| p.is_empty() || p.starts_with('/'))
    else {
        return Ok(Admitted::NotFound);
    };
    let Some(session) = authenticate(state, req) else {
        return Err(reject(state, Reason::Session, Response::unauthorized()));
    };
    let csrf_ok = req
        .csrf
        .as_ref()
        .and_then(|header| hex::decode32(header))
        .is_some_and(|token| Sessions::check_csrf(&session, token.as_ref()));
    if !csrf_ok {
        return Err(reject(state, Reason::Csrf, Response::forbidden()));
    }
    if req.method != Method::Get && req.origin.as_deref() != Some(state.origin().as_str()) {
        return Err(reject(state, Reason::Origin, Response::forbidden()));
    }
    Ok(Admitted::Api {
        session,
        path: api_path,
    })
}
