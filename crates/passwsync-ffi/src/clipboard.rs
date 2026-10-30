#![forbid(unsafe_code)]
//! Clipboard deadlines and reveals (data-model.md section 5; FR-021 to FR-024).
//!
//! A copy goes to the foreign `Clipboard` port (marked sensitive there) and never back; the
//! `clipboard-pending` marker holds only the deadline and the clip timestamp, so a restarted
//! process can clear a clip it left behind. Deadlines are on boot time: they keep counting
//! while the phone sleeps. Every lock, screen off and shutdown clears at once.

use std::fs;
use std::time::Duration;

use host_runtime::files::{read_private_file, write_private_atomic};
use host_runtime::log::LogEvent;
use vault_core::EntryId;
use wallet_service::WalletName;
use zeroize::Zeroizing;

use crate::api::{Inner, lock};
use crate::error::CoreError;
use crate::records::{CopyTicket, CoreEvent, RevealTicket};

/// Larger marker files are unreadable (and cleared unconditionally).
const MARKER_LIMIT: u64 = 256;

/// Whether a copied value may still be on the clipboard.
pub enum ClipboardState {
    Idle,
    Pending {
        /// Boot-time deadline: counts while the phone sleeps.
        deadline: Duration,
        clip_timestamp: i64,
        wallet: WalletName,
    },
}

/// One revealed password, hidden at `deadline` (boot time).
pub struct Reveal {
    pub wallet: WalletName,
    pub id: EntryId,
    pub deadline: Duration,
}

/// Moves the text out of its wrapper as bytes, without a copy.
fn into_bytes(mut text: Zeroizing<String>) -> Vec<u8> {
    std::mem::take(&mut *text).into_bytes()
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `clip_timestamp` of a marker, if the whole marker is well formed.
fn marker_timestamp(bytes: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    lines
        .next()?
        .strip_prefix("deadline_boottime_s=")?
        .parse::<u64>()
        .ok()?;
    let timestamp = lines
        .next()?
        .strip_prefix("clip_timestamp=")?
        .parse()
        .ok()?;
    lines.next().is_none().then_some(timestamp)
}

impl Inner {
    fn timeout(&self) -> Duration {
        self.running.clipboard_clear
    }

    /// Puts `value` on the clipboard and starts the countdown (FR-021, FR-022).
    pub(crate) fn copy(
        &self,
        wallet: &WalletName,
        value: Zeroizing<String>,
    ) -> Result<CopyTicket, CoreError> {
        let timestamp = self.clipboard_port.set_sensitive(into_bytes(value))?;
        let deadline = self.elapsed.boottime() + self.timeout();
        let marker = format!(
            "deadline_boottime_s={}\nclip_timestamp={timestamp}\n",
            deadline.as_secs()
        );
        *lock(&self.clipboard) = ClipboardState::Pending {
            deadline,
            clip_timestamp: timestamp,
            wallet: wallet.clone(),
        };
        if write_private_atomic(&self.dirs.clipboard_marker(), marker.as_bytes()).is_err() {
            // Without a marker a crash could leave the value behind: never keep it.
            self.clear_clipboard();
            return Err(CoreError::Storage);
        }
        Ok(CopyTicket {
            clear_in_ms: ms(self.timeout()),
        })
    }

    /// Clears when the deadline has passed.
    pub(crate) fn clipboard_deadline(&self) {
        let due = matches!(
            &*lock(&self.clipboard),
            ClipboardState::Pending { deadline, .. } if self.elapsed.boottime() >= *deadline
        );
        if due {
            self.clear_clipboard();
        }
    }

    /// Clears our clip now (kept if another app replaced it) and removes the marker.
    pub(crate) fn clear_clipboard(&self) {
        let previous = std::mem::replace(&mut *lock(&self.clipboard), ClipboardState::Idle);
        let ClipboardState::Pending { clip_timestamp, .. } = previous else {
            return;
        };
        let cleared = self.clipboard_port.clear_if_ours(clip_timestamp);
        let _ = fs::remove_file(self.dirs.clipboard_marker());
        if cleared {
            self.cleared();
        }
    }

    fn cleared(&self) {
        self.log.emit(&LogEvent::ClipboardCleared);
        self.notify(CoreEvent::ClipboardCleared);
    }

    /// Time left until the clipboard is cleared.
    pub(crate) fn clipboard_remaining(&self) -> Option<Duration> {
        match &*lock(&self.clipboard) {
            ClipboardState::Pending { deadline, .. } => {
                Some(deadline.saturating_sub(self.elapsed.boottime()))
            }
            ClipboardState::Idle => None,
        }
    }

    /// The wallet the pending clip came from.
    pub(crate) fn clipboard_source(&self) -> Option<WalletName> {
        match &*lock(&self.clipboard) {
            ClipboardState::Pending { wallet, .. } => Some(wallet.clone()),
            ClipboardState::Idle => None,
        }
    }

    /// A marker left by an earlier process: clear its clip (unconditionally when the marker
    /// cannot be read), then remove the marker (FR-023).
    pub(crate) fn clear_pending_marker_at_start(&self) {
        let path = self.dirs.clipboard_marker();
        let timestamp = match read_private_file(&path, MARKER_LIMIT) {
            Ok(None) => return,
            Ok(Some(bytes)) => marker_timestamp(&bytes),
            Err(_) if path.symlink_metadata().is_err() => return,
            Err(_) => None,
        };
        let cleared = match timestamp {
            Some(timestamp) => self.clipboard_port.clear_if_ours(timestamp),
            // Unreadable: overwrite with an empty clip of ours, then clear that one.
            None => match self.clipboard_port.set_sensitive(Vec::new()) {
                Ok(ours) => self.clipboard_port.clear_if_ours(ours),
                Err(_) => false,
            },
        };
        let _ = fs::remove_file(&path);
        if cleared {
            self.cleared();
        }
    }

    /// Records a reveal and hands out the password (FR-024).
    pub(crate) fn reveal(
        &self,
        wallet: &WalletName,
        id: EntryId,
        revealed: Zeroizing<String>,
    ) -> RevealTicket {
        let deadline = self.elapsed.boottime() + self.timeout();
        let mut reveals = lock(&self.reveals);
        reveals.retain(|r| !(r.wallet == *wallet && r.id == id));
        reveals.push(Reveal {
            wallet: wallet.clone(),
            id,
            deadline,
        });
        drop(reveals);
        RevealTicket {
            password: into_bytes(revealed),
            hide_in_ms: ms(self.timeout()),
        }
    }

    /// Ends the reveals whose deadline passed.
    pub(crate) fn reveal_deadlines(&self) {
        let now = self.elapsed.boottime();
        self.end_reveals_where(|r| r.deadline <= now);
    }

    /// Ends the reveals of `wallet`, or all of them.
    pub(crate) fn end_reveals(&self, wallet: Option<&WalletName>) {
        self.end_reveals_where(|r| wallet.is_none_or(|w| r.wallet == *w));
    }

    fn end_reveals_where(&self, ends: impl Fn(&Reveal) -> bool) {
        let mut reveals = lock(&self.reveals);
        let before = reveals.len();
        reveals.retain(|r| !ends(r));
        let ended = reveals.len() != before;
        drop(reveals);
        if ended {
            self.notify(CoreEvent::RevealExpired);
        }
    }

    /// Time left until the first reveal hides.
    pub(crate) fn reveal_remaining(&self) -> Option<Duration> {
        let now = self.elapsed.boottime();
        lock(&self.reveals)
            .iter()
            .map(|r| r.deadline.saturating_sub(now))
            .min()
    }
}
