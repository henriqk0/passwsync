//! Bounded HTTP/1.1 request reading on top of `httparse` (research R2, FR-013). One request
//! per connection; no chunked bodies; every buffer that may hold secrets is zeroized.

use std::io::{self, Read};
use std::time::Duration;

use zeroize::Zeroizing;

pub const MAX_HEAD_BYTES: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 48;
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Other,
}

/// The parts of a request the service uses. Header values that can carry secrets are
/// zeroized on drop.
pub struct Request {
    pub method: Method,
    /// Request target without the query string.
    pub path: String,
    /// `Some` only if exactly one `Host` header was sent.
    pub host: Option<String>,
    /// `Some` only if exactly one `Origin` header was sent.
    pub origin: Option<String>,
    /// The `pws_session` cookie value, if present exactly once.
    pub session_cookie: Option<Zeroizing<String>>,
    /// `X-CSRF-Token`, if present exactly once.
    pub csrf: Option<Zeroizing<String>>,
    pub body: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// 431: request line and headers over 16 KiB or more than 48 headers.
    HeadTooLarge,
    /// 413: `Content-Length` above 8 MiB.
    BodyTooLarge,
    /// 400: `Transfer-Encoding` present.
    TransferEncoding,
    /// 400: not a well-formed HTTP/1.x request.
    BadRequest,
    /// The read timed out; the connection is closed.
    Timeout,
    /// The peer closed the connection early; nothing to answer.
    Closed,
}

fn read_error(error: &io::Error) -> RequestError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => RequestError::Timeout,
        _ => RequestError::Closed,
    }
}

pub fn read_request(stream: &mut impl Read) -> Result<Request, RequestError> {
    // Fixed size, so it never reallocates and strands unwiped copies.
    let mut head = Zeroizing::new(vec![0u8; MAX_HEAD_BYTES]);
    let mut filled = 0;
    loop {
        let n = match stream.read(&mut head[filled..]) {
            Ok(0) => return Err(RequestError::Closed),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(read_error(&error)),
        };
        filled += n;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut headers);
        match parsed.parse(&head[..filled]) {
            Ok(httparse::Status::Complete(head_len)) => {
                return finish(&parsed, &head[head_len..filled], stream);
            }
            Ok(httparse::Status::Partial) if filled == MAX_HEAD_BYTES => {
                return Err(RequestError::HeadTooLarge);
            }
            Ok(httparse::Status::Partial) => {}
            Err(httparse::Error::TooManyHeaders) => return Err(RequestError::HeadTooLarge),
            Err(_) => return Err(RequestError::BadRequest),
        }
    }
}

fn finish(
    parsed: &httparse::Request<'_, '_>,
    leftover: &[u8],
    stream: &mut impl Read,
) -> Result<Request, RequestError> {
    let method = match parsed.method.unwrap_or_default() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        _ => Method::Other,
    };
    let target = parsed.path.unwrap_or_default();
    if !target.starts_with('/') {
        return Err(RequestError::BadRequest);
    }
    let path = target.split_once('?').map_or(target, |(p, _)| p).to_owned();

    let mut host = Vec::new();
    let mut origin = Vec::new();
    let mut csrf = Vec::new();
    let mut cookies = Vec::new();
    let mut content_length = Vec::new();
    for header in parsed.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RequestError::TransferEncoding);
        } else if name.eq_ignore_ascii_case("host") {
            host.push(header.value);
        } else if name.eq_ignore_ascii_case("origin") {
            origin.push(header.value);
        } else if name.eq_ignore_ascii_case("x-csrf-token") {
            csrf.push(header.value);
        } else if name.eq_ignore_ascii_case("cookie") {
            cookies.push(header.value);
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length.push(header.value);
        }
    }
    let single = |values: &[&[u8]]| match values {
        [value] => std::str::from_utf8(value).ok().map(str::to_owned),
        _ => None,
    };
    let length = match content_length.as_slice() {
        [] => 0,
        [value] => parse_length(value)?,
        _ => return Err(RequestError::BadRequest),
    };
    let body = read_body(length, leftover, stream)?;
    Ok(Request {
        method,
        path,
        host: single(&host),
        origin: single(&origin),
        session_cookie: session_cookie(&cookies),
        csrf: single(&csrf).map(Zeroizing::new),
        body,
    })
}

fn parse_length(value: &[u8]) -> Result<usize, RequestError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(RequestError::BadRequest);
    }
    if value.len() > 9 {
        return Err(RequestError::BodyTooLarge);
    }
    let length: usize = std::str::from_utf8(value)
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or(RequestError::BadRequest)?;
    if length > MAX_BODY_BYTES {
        return Err(RequestError::BodyTooLarge);
    }
    Ok(length)
}

/// Reads exactly `length` body bytes into a buffer sized up front.
fn read_body(
    length: usize,
    leftover: &[u8],
    stream: &mut impl Read,
) -> Result<Zeroizing<Vec<u8>>, RequestError> {
    let mut body = Zeroizing::new(vec![0u8; length]);
    let already = leftover.len().min(length);
    body[..already].copy_from_slice(&leftover[..already]);
    if already < length {
        stream.read_exact(&mut body[already..]).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                RequestError::Closed
            } else {
                read_error(&error)
            }
        })?;
    }
    Ok(body)
}

/// The `pws_session` value across all `Cookie` headers; ambiguous (repeated) means none.
fn session_cookie(headers: &[&[u8]]) -> Option<Zeroizing<String>> {
    let mut found: Option<&str> = None;
    let mut count = 0;
    for header in headers {
        let Ok(text) = std::str::from_utf8(header) else {
            continue;
        };
        for pair in text.split(';') {
            if let Some(value) = pair.trim().strip_prefix("pws_session=") {
                found = Some(value);
                count += 1;
            }
        }
    }
    match (found, count) {
        (Some(value), 1) => Some(Zeroizing::new(value.to_owned())),
        _ => None,
    }
}
