//! Launch token and browser sessions (research R6). All token material is held in
//! `Zeroizing` buffers and compared in constant time; hex encoding happens only at the HTTP
//! boundary.

use std::fmt;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::ServiceError;

pub type Token = Zeroizing<[u8; 32]>;

const MAX_SESSIONS: usize = 32;

fn random_token() -> Result<Token, ServiceError> {
    let mut token = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(token.as_mut())
        .map_err(|_| ServiceError::Internal)?;
    Ok(token)
}

fn token_eq(token: &[u8; 32], presented: &[u8]) -> bool {
    presented.len() == token.len() && bool::from(token.ct_eq(presented))
}

/// Single-use secret in the launch address.
pub struct LaunchToken(Token);

impl LaunchToken {
    pub fn generate() -> Result<Self, ServiceError> {
        random_token().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn matches(&self, presented: &[u8]) -> bool {
        token_eq(&self.0, presented)
    }
}

/// One browser's session: the cookie value and its independent CSRF token.
pub struct BrowserSession {
    id: Token,
    csrf: Token,
}

/// What a successful launch exchange hands back to the HTTP adapter.
pub struct Grant {
    pub session_id: Token,
    pub csrf: Token,
    /// The replacement launch token, to be written to the launch file.
    pub next_launch: Token,
}

/// A request's authenticated session (a copy of its CSRF token, wiped on drop).
pub struct Authenticated {
    csrf: Token,
}

impl Authenticated {
    pub fn csrf(&self) -> &Token {
        &self.csrf
    }
}

/// In-memory sessions of this run: a fresh launch token, at most 32 browser sessions
/// (oldest evicted). Nothing survives a restart.
pub struct Sessions {
    launch: LaunchToken,
    list: Vec<BrowserSession>,
}

impl Sessions {
    pub fn new() -> Result<Self, ServiceError> {
        Ok(Self {
            launch: LaunchToken::generate()?,
            list: Vec::with_capacity(MAX_SESSIONS),
        })
    }

    pub fn launch_token(&self) -> &[u8; 32] {
        self.launch.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Spends a valid launch token: creates a session and rotates the launch token.
    pub fn exchange(&mut self, presented: &[u8]) -> Option<Grant> {
        if !self.launch.matches(presented) {
            return None;
        }
        let next = LaunchToken::generate().ok()?;
        let session = BrowserSession {
            id: random_token().ok()?,
            csrf: random_token().ok()?,
        };
        let grant = Grant {
            session_id: Zeroizing::new(*session.id),
            csrf: Zeroizing::new(*session.csrf),
            next_launch: Zeroizing::new(*next.as_bytes()),
        };
        self.launch = next;
        if self.list.len() == MAX_SESSIONS {
            self.list.remove(0);
        }
        self.list.push(session);
        Some(grant)
    }

    /// Finds the session for a cookie value. Every stored id is compared (constant time per
    /// comparison, no early exit), so timing does not reveal which one matched.
    pub fn authenticate(&self, cookie: &[u8]) -> Option<Authenticated> {
        let mut found = None;
        for session in &self.list {
            if token_eq(&session.id, cookie) {
                found = Some(Authenticated {
                    csrf: Zeroizing::new(*session.csrf),
                });
            }
        }
        found
    }

    /// Constant-time check of the `X-CSRF-Token` value against the session's token.
    pub fn check_csrf(session: &Authenticated, header: &[u8]) -> bool {
        token_eq(&session.csrf, header)
    }
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("sessions", &self.list.len())
            .finish_non_exhaustive()
    }
}
