//! Length-framed reads and writes on a `TcpStream` with a per-step deadline (R7, FR-030).
//! The length is checked before any body byte is read or any buffer sized.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use device_link::wire::{MAX_FRAME, encode_frame};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Timeout,
    Closed,
    /// Length above the limit.
    Oversized,
    /// Zero length.
    Malformed,
    Io,
}

fn read_exact_by(stream: &TcpStream, buf: &mut [u8], deadline: Instant) -> Result<(), FrameError> {
    let mut filled = 0;
    let mut reader = stream;
    while filled < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FrameError::Timeout);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|_| FrameError::Io)?;
        match reader.read(&mut buf[filled..]) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameError::Timeout);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Err(FrameError::Closed);
            }
            Err(_) => return Err(FrameError::Io),
        }
    }
    Ok(())
}

/// Reads one frame within `timeout`. The body is returned in a wiped buffer.
pub fn read_frame(stream: &TcpStream, timeout: Duration) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let deadline = Instant::now() + timeout;
    let mut header = [0u8; 2];
    read_exact_by(stream, &mut header, deadline)?;
    let len = usize::from(u16::from_be_bytes(header));
    if len == 0 {
        return Err(FrameError::Malformed);
    }
    if len > MAX_FRAME {
        return Err(FrameError::Oversized);
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    read_exact_by(stream, &mut body, deadline)?;
    Ok(body)
}

pub fn write_frame(stream: &TcpStream, body: &[u8]) -> io::Result<()> {
    let framed = encode_frame(body).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut writer = stream;
    writer.write_all(&framed)?;
    writer.flush()
}
