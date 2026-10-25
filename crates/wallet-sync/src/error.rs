//! Closed error types; no variant carries data from the peer.

use std::fmt;

/// A peer broke the sync protocol: the round fails and the channel is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolError;

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sync protocol error")
    }
}

impl std::error::Error for ProtocolError {}
