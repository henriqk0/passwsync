//! Responses. Every response carries the mandatory security headers (contracts/http-api.md);
//! rejection bodies are fixed text that never echoes the request.

use std::io::{self, Write};

use zeroize::Zeroizing;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const SECURITY_HEADERS: &str = concat!(
    "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cache-Control: no-store\r\n",
    "X-Frame-Options: DENY\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Connection: close\r\n",
);

pub const TEXT: &str = "text/plain; charset=utf-8";
pub const HTML: &str = "text/html; charset=utf-8";
pub const JSON: &str = "application/json; charset=utf-8";

pub enum Body {
    Static(&'static [u8]),
    /// May hold credential data; wiped on drop.
    Owned(Zeroizing<Vec<u8>>),
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    /// Extra headers (`Location`, `Set-Cookie`); values may be secret and are wiped.
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    pub body: Body,
}

impl Response {
    pub fn fixed(status: u16, content_type: &'static str, body: &'static [u8]) -> Self {
        Self {
            status,
            content_type,
            headers: Vec::new(),
            body: Body::Static(body),
        }
    }

    pub fn owned(status: u16, content_type: &'static str, body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            headers: Vec::new(),
            body: Body::Owned(body),
        }
    }

    pub fn with_header(mut self, name: &'static str, value: Zeroizing<String>) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn bad_request() -> Self {
        Self::fixed(400, TEXT, b"bad request")
    }

    pub fn unauthorized() -> Self {
        Self::fixed(401, TEXT, b"unauthorized")
    }

    pub fn forbidden() -> Self {
        Self::fixed(403, TEXT, b"forbidden")
    }

    pub fn not_found() -> Self {
        Self::fixed(404, TEXT, b"not found")
    }

    pub fn method_not_allowed() -> Self {
        Self::fixed(405, TEXT, b"method not allowed")
    }

    pub fn payload_too_large() -> Self {
        Self::fixed(413, TEXT, b"too large")
    }

    pub fn headers_too_large() -> Self {
        Self::fixed(431, TEXT, b"too large")
    }

    fn body_bytes(&self) -> &[u8] {
        match &self.body {
            Body::Static(bytes) => bytes,
            Body::Owned(bytes) => bytes,
        }
    }

    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        let body = self.body_bytes();
        let mut head = Zeroizing::new(String::with_capacity(1024));
        head.push_str("HTTP/1.1 ");
        head.push_str(&self.status.to_string());
        head.push(' ');
        head.push_str(reason(self.status));
        head.push_str("\r\n");
        head.push_str(SECURITY_HEADERS);
        head.push_str("Content-Type: ");
        head.push_str(self.content_type);
        head.push_str("\r\nContent-Length: ");
        head.push_str(&body.len().to_string());
        head.push_str("\r\n");
        for (name, value) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        out.write_all(head.as_bytes())?;
        out.write_all(body)?;
        out.flush()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        423 => "Locked",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}
