//! FR-008, FR-057: the seven Android app lifecycle events render fixed text with only
//! non-secret fields (level name, on/off, counts, durations).

use std::io::Write;
use std::sync::{Arc, Mutex};

use host_runtime::log::{Log, LogEvent, MemoryProtection};

struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn app_events_have_fixed_texts() {
    let cases: Vec<(LogEvent<'static>, &str)> = vec![
        (
            LogEvent::ProtectionLevel {
                level: MemoryProtection::Full,
            },
            "protection level full",
        ),
        (
            LogEvent::ProtectionLevel {
                level: MemoryProtection::SecretsOnly,
            },
            "protection level secrets-only",
        ),
        (
            LogEvent::ProtectionLevel {
                level: MemoryProtection::None,
            },
            "protection level none",
        ),
        (
            LogEvent::NetworkSwitched { on: true },
            "network switched on",
        ),
        (
            LogEvent::NetworkSwitched { on: false },
            "network switched off",
        ),
        (LogEvent::WindowStarted, "sync window started"),
        (
            LogEvent::WindowEnded {
                rounds: 3,
                seconds: 42,
            },
            "sync window ended rounds=3 seconds=42",
        ),
        (LogEvent::ClipboardCleared, "clipboard cleared"),
        (LogEvent::IdentityReset, "device identity reset"),
        (LogEvent::SettingsReset, "settings reset to defaults"),
    ];
    for (event, text) in cases {
        assert_eq!(event.to_string(), text);
    }
}

#[test]
fn app_events_go_through_the_passwsync_prefix() {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let log = Log::with_sink("passwsync", Arc::new(Mutex::new(Buf(Arc::clone(&buffer)))));
    log.emit(&LogEvent::ClipboardCleared);
    assert_eq!(
        String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
        "passwsync: clipboard cleared\n"
    );
}

#[test]
fn app_event_fields_are_typed_and_never_text() {
    let source = include_str!("../src/log.rs");
    let start = source.find("// --- 007 app events").expect("marker");
    let end = source[start..].find("\n}\n").unwrap() + start;
    let block = &source[start..end];
    for forbidden in [
        "String",
        "&'a str",
        "[u8",
        "Vec<",
        "WalletName",
        "password",
        "code",
        "secret",
    ] {
        assert!(!block.contains(forbidden), "{forbidden} in the 007 events");
    }
}
