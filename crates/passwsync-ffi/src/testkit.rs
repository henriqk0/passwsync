#![forbid(unsafe_code)]
//! Fakes of the four foreign ports (feature `testkit`, contracts/ffi-api.md section 3).
//! `FakeSealer` is NOT cryptography: it wraps the plaintext in a label-checked envelope and
//! accepts only envelopes it issued since the last reset. Confidentiality and authenticity
//! come from the real Keystore and are device-checked. The fakes record secrets on purpose so
//! tests can assert what reached a port; they exist only in test builds.

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::ports::{Clipboard, KeySealer, LogSink, PlatformError, UiNotifier};
use crate::records::CoreEvent;

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Behaviour of every following sealer call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealerMode {
    Normal,
    /// The Keystore key was invalidated (e.g. lock screen removed).
    Invalidated,
    /// The Keystore cannot be reached.
    Unavailable,
}

/// One recorded sealer call. `Open.plaintext` is what was returned, `None` on failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealCall {
    Seal {
        label: String,
        plaintext: Vec<u8>,
    },
    Open {
        label: String,
        plaintext: Option<Vec<u8>>,
    },
    Reset,
}

#[derive(Default)]
struct SealerState {
    mode: Option<SealerMode>,
    /// Envelopes issued under the current key generation.
    issued: Vec<Vec<u8>>,
    calls: Vec<SealCall>,
    resets: usize,
}

/// Label-checked envelope store; see the module comment.
#[derive(Default)]
pub struct FakeSealer {
    state: Mutex<SealerState>,
}

const MAGIC: &[u8; 4] = b"FKSL";

impl FakeSealer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_mode(&self, mode: SealerMode) {
        guard(&self.state).mode = Some(mode);
    }

    /// Changes one byte of an envelope, as an attacker editing the file would.
    pub fn tamper(sealed: &mut [u8]) {
        if let Some(last) = sealed.last_mut() {
            *last ^= 0x5a;
        }
    }

    pub fn calls(&self) -> Vec<SealCall> {
        guard(&self.state).calls.clone()
    }

    /// Every label passed to `seal` or `open`, in order.
    pub fn labels(&self) -> Vec<String> {
        guard(&self.state)
            .calls
            .iter()
            .filter_map(|call| match call {
                SealCall::Seal { label, .. } | SealCall::Open { label, .. } => Some(label.clone()),
                SealCall::Reset => None,
            })
            .collect()
    }

    /// Every plaintext passed to `seal`, in order.
    pub fn plaintexts(&self) -> Vec<Vec<u8>> {
        guard(&self.state)
            .calls
            .iter()
            .filter_map(|call| match call {
                SealCall::Seal { plaintext, .. } => Some(plaintext.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn resets(&self) -> usize {
        guard(&self.state).resets
    }

    fn failure(state: &SealerState) -> Option<PlatformError> {
        match state.mode.unwrap_or(SealerMode::Normal) {
            SealerMode::Normal => None,
            SealerMode::Invalidated => Some(PlatformError::Invalidated),
            SealerMode::Unavailable => Some(PlatformError::Unavailable),
        }
    }

    fn envelope(label: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + label.len() + plaintext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(label.len() as u32).to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(plaintext);
        out
    }

    fn unwrap_envelope<'a>(label: &str, sealed: &'a [u8]) -> Option<&'a [u8]> {
        let rest = sealed.strip_prefix(MAGIC.as_slice())?;
        let (len, rest) = rest.split_at_checked(4)?;
        let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
        let (stored, plaintext) = rest.split_at_checked(len)?;
        (stored == label.as_bytes()).then_some(plaintext)
    }
}

impl KeySealer for FakeSealer {
    fn seal(&self, label: String, plaintext: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        let mut state = guard(&self.state);
        let envelope = Self::envelope(&label, &plaintext);
        state.calls.push(SealCall::Seal { label, plaintext });
        if let Some(error) = Self::failure(&state) {
            return Err(error);
        }
        state.issued.push(envelope.clone());
        Ok(envelope)
    }

    fn open(&self, label: String, sealed: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        let mut state = guard(&self.state);
        let result = match Self::failure(&state) {
            Some(error) => Err(error),
            None if !state.issued.contains(&sealed) => Err(PlatformError::Failed),
            None => Self::unwrap_envelope(&label, &sealed)
                .map(<[u8]>::to_vec)
                .ok_or(PlatformError::Failed),
        };
        state.calls.push(SealCall::Open {
            label,
            plaintext: result.as_ref().ok().cloned(),
        });
        result
    }

    fn reset(&self) -> Result<(), PlatformError> {
        let mut state = guard(&self.state);
        state.calls.push(SealCall::Reset);
        state.resets += 1;
        state.issued.clear();
        state.mode = Some(SealerMode::Normal);
        Ok(())
    }
}

/// One recorded clipboard action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipEvent {
    Set {
        value: Vec<u8>,
        timestamp: i64,
    },
    /// `clear_if_ours` cleared the clip.
    Cleared {
        timestamp: i64,
    },
    /// `clear_if_ours` left the clip in place (not ours).
    Kept {
        timestamp: i64,
    },
}

struct Clip {
    value: Vec<u8>,
    timestamp: i64,
}

#[derive(Default)]
struct ClipState {
    current: Option<Clip>,
    next_timestamp: i64,
    cannot_inspect: bool,
    failing: bool,
    events: Vec<ClipEvent>,
}

/// In-memory clipboard; timestamps increase by one per set (also for another app's set).
#[derive(Default)]
pub struct FakeClipboard {
    state: Mutex<ClipState>,
}

impl FakeClipboard {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ClipState {
                next_timestamp: 1_000,
                ..ClipState::default()
            }),
        }
    }

    pub fn current(&self) -> Option<Vec<u8>> {
        guard(&self.state).current.as_ref().map(|c| c.value.clone())
    }

    pub fn events(&self) -> Vec<ClipEvent> {
        guard(&self.state).events.clone()
    }

    /// The clip metadata cannot be read (e.g. restricted while in background).
    pub fn set_cannot_inspect(&self, cannot: bool) {
        guard(&self.state).cannot_inspect = cannot;
    }

    pub fn set_failing(&self, failing: bool) {
        guard(&self.state).failing = failing;
    }

    /// Another app copies something; not recorded as our event.
    pub fn replace_by_other_app(&self, value: Vec<u8>) {
        let mut state = guard(&self.state);
        state.next_timestamp += 1;
        let timestamp = state.next_timestamp;
        state.current = Some(Clip { value, timestamp });
    }
}

impl Clipboard for FakeClipboard {
    fn set_sensitive(&self, value: Vec<u8>) -> Result<i64, PlatformError> {
        let mut state = guard(&self.state);
        if state.failing {
            return Err(PlatformError::Unavailable);
        }
        state.next_timestamp += 1;
        let timestamp = state.next_timestamp;
        state.events.push(ClipEvent::Set {
            value: value.clone(),
            timestamp,
        });
        state.current = Some(Clip { value, timestamp });
        Ok(timestamp)
    }

    fn clear_if_ours(&self, timestamp: i64) -> bool {
        let mut state = guard(&self.state);
        let ours = state.cannot_inspect
            || state
                .current
                .as_ref()
                .is_some_and(|c| c.timestamp == timestamp);
        if ours {
            state.current = None;
            state.events.push(ClipEvent::Cleared { timestamp });
        } else {
            state.events.push(ClipEvent::Kept { timestamp });
        }
        ours
    }
}

/// Records every log line in order.
#[derive(Default)]
pub struct RecordingLog {
    lines: Mutex<Vec<String>>,
}

impl RecordingLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lines(&self) -> Vec<String> {
        guard(&self.lines).clone()
    }
}

impl LogSink for RecordingLog {
    fn line(&self, text: String) {
        guard(&self.lines).push(text);
    }
}

/// Records every UI event in order.
#[derive(Default)]
pub struct RecordingNotifier {
    events: Mutex<Vec<CoreEvent>>,
}

impl RecordingNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<CoreEvent> {
        guard(&self.events).clone()
    }
}

impl UiNotifier for RecordingNotifier {
    fn changed(&self, event: CoreEvent) {
        guard(&self.events).push(event);
    }
}

/// Scripted process controls (data-model.md section 2): every protection works, the memlock
/// limit is unlimited and `mlockall` succeeds unless configured otherwise. Records the calls.
pub struct FakeProcess {
    core_dumps: bool,
    non_dumpable: bool,
    limit: Option<u64>,
    mlockall: bool,
    page_lock: bool,
    calls: Mutex<Vec<&'static str>>,
}

impl Default for FakeProcess {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeProcess {
    pub fn new() -> Self {
        Self {
            core_dumps: true,
            non_dumpable: true,
            limit: None,
            mlockall: true,
            page_lock: true,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Makes one protection fail.
    pub fn fail(mut self, which: crate::error::Protection) -> Self {
        match which {
            crate::error::Protection::CoreDumps => self.core_dumps = false,
            crate::error::Protection::NonDumpable => self.non_dumpable = false,
        }
        self
    }

    pub fn memlock_limit(mut self, limit: Option<u64>) -> Self {
        self.limit = limit;
        self
    }

    pub fn mlockall_ok(mut self, ok: bool) -> Self {
        self.mlockall = ok;
        self
    }

    pub fn page_lock_ok(mut self, ok: bool) -> Self {
        self.page_lock = ok;
        self
    }

    pub fn calls(&self) -> Vec<&'static str> {
        guard(&self.calls).clone()
    }

    fn record(&self, call: &'static str, result: bool) -> bool {
        guard(&self.calls).push(call);
        result
    }
}

impl crate::protect::ProcessControls for FakeProcess {
    fn disable_core_dumps(&self) -> bool {
        self.record("core_dumps", self.core_dumps)
    }

    fn set_non_dumpable(&self) -> bool {
        self.record("non_dumpable", self.non_dumpable)
    }

    fn memlock_limit(&self) -> Option<u64> {
        guard(&self.calls).push("memlock_limit");
        self.limit
    }

    fn lock_all(&self) -> bool {
        self.record("mlockall", self.mlockall)
    }

    fn probe_page_lock(&self) -> bool {
        self.record("page_lock", self.page_lock)
    }
}
