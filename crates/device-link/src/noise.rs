//! Thin helpers over `snow` (no cryptography of our own): building handshakes and sealing /
//! opening payloads with fixed-size, wiped buffers.

use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::wire::{MAX_FRAME, Payload};

pub(crate) fn builder<'a>(
    pattern: &str,
    private: &'a [u8; 32],
    prologue: &'a [u8],
) -> Result<snow::Builder<'a>, Error> {
    let params = pattern.parse().map_err(|_| Error::Crypto)?;
    snow::Builder::new(params)
        .local_private_key(private)
        .and_then(|b| b.prologue(prologue))
        .map_err(|_| Error::Crypto)
}

/// Writes one handshake message; the result always fits a frame.
pub(crate) fn write_handshake(hs: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = [0u8; MAX_FRAME];
    let n = hs
        .write_message(payload, &mut buf)
        .map_err(|_| Error::Crypto)?;
    Ok(buf[..n].to_vec())
}

/// Reads one handshake message; returns the decrypted payload.
pub(crate) fn read_handshake(
    hs: &mut HandshakeState,
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new([0u8; MAX_FRAME]);
    let n = hs
        .read_message(message, buf.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(Zeroizing::new(buf[..n].to_vec()))
}

pub(crate) fn remote_static(hs: &HandshakeState) -> Result<[u8; 32], Error> {
    hs.get_remote_static()
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
        .ok_or(Error::Protocol)
}

pub(crate) fn seal(ts: &mut TransportState, payload: &Payload) -> Result<Vec<u8>, Error> {
    let plain = Zeroizing::new(payload.encode());
    let mut buf = [0u8; MAX_FRAME];
    let n = ts
        .write_message(&plain, &mut buf)
        .map_err(|_| Error::Crypto)?;
    Ok(buf[..n].to_vec())
}

/// Any AEAD failure (tamper, replay, reorder) is `Crypto`; a bad payload is `Protocol`.
pub(crate) fn open(ts: &mut TransportState, frame: &[u8]) -> Result<Payload, Error> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(Error::Protocol);
    }
    let mut buf = Zeroizing::new([0u8; MAX_FRAME]);
    let n = ts
        .read_message(frame, buf.as_mut())
        .map_err(|_| Error::Crypto)?;
    Payload::decode(&buf[..n])
}
