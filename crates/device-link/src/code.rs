//! One-time pairing code and its rate limit (research R5).

use std::time::Duration;

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

pub const CODE_VALIDITY: Duration = Duration::from_secs(300);
pub const CODES_PER_WINDOW: usize = 5;
pub const CODE_WINDOW: Duration = Duration::from_secs(600);

/// Largest multiple of 10^8 that fits in `u32` range: values at or above it are redrawn.
const UNBIASED_LIMIT: u32 = 4_200_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeState {
    Active,
    Consumed,
    Accepted,
    Failed,
    Expired,
    Cancelled,
    Replaced,
}

/// 8 ASCII digits, held only in wiped memory; never stored or logged. Not `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingCode {
    digits: [u8; 8],
    #[zeroize(skip)]
    expires_at: Duration,
    #[zeroize(skip)]
    state: CodeState,
}

impl PairingCode {
    /// Uniform over 00000000..=99999999 by rejection sampling.
    pub fn generate(rng: &mut impl CryptoRngCore, now: Duration) -> Result<Self, Error> {
        let mut value = loop {
            let mut bytes = Zeroizing::new([0u8; 4]);
            rng.try_fill_bytes(bytes.as_mut())
                .map_err(|_| Error::Random)?;
            let candidate = u32::from_be_bytes(*bytes);
            if candidate < UNBIASED_LIMIT {
                break candidate % 100_000_000;
            }
        };
        let mut digits = [b'0'; 8];
        for slot in digits.iter_mut().rev() {
            *slot = b'0' + (value % 10) as u8;
            value /= 10;
        }
        Ok(Self {
            digits,
            expires_at: now + CODE_VALIDITY,
            state: CodeState::Active,
        })
    }

    pub fn digits(&self) -> &str {
        std::str::from_utf8(&self.digits).unwrap_or_default()
    }

    /// Display form `1234 5678`.
    pub fn grouped(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(9));
        out.push_str(&self.digits()[..4]);
        out.push(' ');
        out.push_str(&self.digits()[4..]);
        out
    }

    pub fn state(&self, now: Duration) -> CodeState {
        if self.state == CodeState::Active && now >= self.expires_at {
            CodeState::Expired
        } else {
            self.state
        }
    }

    pub fn is_active(&self, now: Duration) -> bool {
        self.state(now) == CodeState::Active
    }

    pub fn seconds_left(&self, now: Duration) -> u64 {
        self.expires_at.saturating_sub(now).as_secs()
    }

    pub fn expires_at(&self) -> Duration {
        self.expires_at
    }

    /// Constant-time comparison against `candidate`, only while active.
    pub fn matches_active(&self, candidate: &str, now: Duration) -> bool {
        use subtle::ConstantTimeEq;
        self.is_active(now) && bool::from(self.digits[..].ct_eq(candidate.as_bytes()))
    }

    /// The first well-formed attempt uses the code up (one attempt per code, FR-021).
    pub fn consume(&mut self, now: Duration) -> Result<(), Error> {
        if !self.is_active(now) {
            if self.state == CodeState::Active {
                self.state = CodeState::Expired;
            }
            return Err(Error::InvalidCode);
        }
        self.state = CodeState::Consumed;
        Ok(())
    }

    pub fn accept(&mut self) {
        self.state = CodeState::Accepted;
    }

    pub fn fail(&mut self) {
        self.state = CodeState::Failed;
    }

    pub fn cancel(&mut self) {
        self.state = CodeState::Cancelled;
    }

    pub fn replace(&mut self) {
        self.state = CodeState::Replaced;
    }
}

/// At most 5 codes per sliding 600 s (monotonic clock).
#[derive(Default, Debug)]
pub struct CodeRateLimiter {
    created: Vec<Duration>,
}

impl CodeRateLimiter {
    pub fn try_create(&mut self, now: Duration) -> bool {
        self.created
            .retain(|at| now.saturating_sub(*at) < CODE_WINDOW);
        if self.created.len() >= CODES_PER_WINDOW {
            return false;
        }
        self.created.push(now);
        true
    }
}

/// Typed input to 8 digits: spaces and dashes are removed, nothing else is accepted.
pub fn normalize_code(input: &str) -> Result<Zeroizing<String>, Error> {
    let mut out = Zeroizing::new(String::with_capacity(8));
    for c in input.chars() {
        match c {
            ' ' | '-' => {}
            '0'..='9' if out.len() < 8 => out.push(c),
            _ => return Err(Error::InvalidCode),
        }
    }
    if out.len() == 8 {
        Ok(out)
    } else {
        Err(Error::InvalidCode)
    }
}
