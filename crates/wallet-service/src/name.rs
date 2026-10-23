use std::fmt;

/// The name was not 1-64 chars of `[A-Za-z0-9 _.-]`, or started with `.`, or ended with a
/// space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidName;

/// A validated wallet name, which is also its file stem. Only safe characters are allowed,
/// so path traversal is unrepresentable. Ordered by bytes. Not secret.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletName(String);

impl WalletName {
    pub const MAX_LEN: usize = 64;

    pub fn parse(name: &str) -> Result<Self, InvalidName> {
        let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'_' | b'.' | b'-');
        let valid = (1..=Self::MAX_LEN).contains(&name.len())
            && name.bytes().all(allowed)
            && !name.starts_with('.')
            && !name.ends_with(' ');
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WalletName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
