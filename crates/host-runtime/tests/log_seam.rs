//! Log prefix seam (contracts/shared-runtime-extraction.md section 3.2).

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use host_runtime::log::{Log, LogEvent};

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

fn sink_log(prefix: &'static str) -> (Log, Arc<Mutex<Vec<u8>>>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let log = Log::with_sink(prefix, Arc::new(Mutex::new(Buf(Arc::clone(&buffer)))));
    (log, buffer)
}

fn text(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
}

#[test]
fn with_sink_prefixes_every_emitted_line() {
    let (log, buffer) = sink_log("x");
    log.emit(&LogEvent::ProtectionsApplied);
    log.emit(&LogEvent::Stopping);
    assert_eq!(text(&buffer), "x: protections applied\nx: stopping\n");
}

#[test]
fn to_buffer_keeps_the_passwsyncd_prefix() {
    let (log, buffer) = Log::to_buffer();
    log.emit(&LogEvent::SuspendDetected);
    assert_eq!(text(&buffer), "passwsyncd: suspend detected\n");
}

#[test]
fn line_writes_one_prefixed_line() {
    let (log, buffer) = sink_log("passwsync");
    log.line(&"invalid configuration: key auto_lock_minutes");
    assert_eq!(
        text(&buffer),
        "passwsync: invalid configuration: key auto_lock_minutes\n"
    );
}

#[test]
fn stderr_log_can_be_built_and_cloned() {
    let log = Log::stderr();
    let _copy = log.clone();
}

#[test]
fn existing_event_texts_are_unchanged() {
    // Copied from crates/passwsyncd/tests/log.rs.
    let addr: SocketAddr = "127.0.0.1:27471".parse().unwrap();
    assert_eq!(
        LogEvent::Started { addr }.to_string(),
        "started 127.0.0.1:27471"
    );
    assert_eq!(
        LogEvent::ProtectionsApplied.to_string(),
        "protections applied"
    );
    assert_eq!(LogEvent::Stopping.to_string(), "stopping");
}
