//! 008 audit findings (FR-017, SC-004): one regression test per finding, minimal reproducer as
//! a literal, written failing before its fix. Findings whose owner is `passwsyncd` live here
//! because `crates/passwsyncd/tests` stays unchanged in this feature (gate rule); `hardening`
//! dev-depends on `passwsyncd`, so the test reaches the same public entry point.

use std::io::Read;

use passwsyncd::http::request::{RequestError, read_request};

/// Delivers the bytes, then EOF.
struct Bytes<'a>(&'a [u8]);

impl Read for Bytes<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

fn read(bytes: &[u8]) -> Result<(), RequestError> {
    read_request(&mut Bytes(bytes)).map(|_| ())
}

/// F-001 (fuzz target `http_request`, seed 0x505753594e430008, iteration 3439): a bare LF
/// ended a header line and the request was accepted. FR-016 requires CRLF line endings.
#[test]
fn f_001_bare_lf_in_the_request_head_is_rejected() {
    // Bare LF after a header value.
    assert_eq!(
        read(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\nX-A: b\r\n\r\n"),
        Err(RequestError::BadRequest)
    );
    // Bare LF ending the request line.
    assert_eq!(
        read(b"GET / HTTP/1.1\nHost: 127.0.0.1:1\r\n\r\n"),
        Err(RequestError::BadRequest)
    );
    // Head terminated by two bare LFs.
    assert_eq!(
        read(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\n\n"),
        Err(RequestError::BadRequest)
    );
    // The CRLF form is still accepted, and an LF inside the body is not the head's business.
    assert!(read(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n").is_ok());
    assert!(read(b"POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na\nb").is_ok());
}
