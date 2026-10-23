//! The optional `key = integer` settings file (contracts/host-runtime.md).

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

/// Settings read once at start-up. Not secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub port: u16,
    pub auto_lock: Duration,
    pub clipboard_clear: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 27471,
            auto_lock: Duration::from_secs(15 * 60),
            clipboard_clear: Duration::from_secs(30),
        }
    }
}

/// `config: <key, line or path>: <problem>`; start-up exits with code 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    place: String,
    problem: &'static str,
}

impl ConfigError {
    fn new(place: impl Into<String>, problem: &'static str) -> Self {
        Self {
            place: place.into(),
            problem,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config: {}: {}", self.place, self.problem)
    }
}

impl std::error::Error for ConfigError {}

/// Reads the file at `path`; a missing file means defaults. The file must be owned by the
/// current user and carry no group/other permission bits.
pub fn load(path: &Path) -> Result<Settings, ConfigError> {
    let place = || path.display().to_string();
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(_) => return Err(ConfigError::new(place(), "cannot be read")),
    };
    if !metadata.is_file() {
        return Err(ConfigError::new(place(), "not a regular file"));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ConfigError::new(place(), "not owned by the current user"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ConfigError::new(
            place(),
            "must not be accessible by group or others (use mode 0600)",
        ));
    }
    let text = fs::read_to_string(path).map_err(|_| ConfigError::new(place(), "cannot be read"))?;
    parse(&text)
}

/// Parses the settings text. Unknown or duplicate keys, other syntax, and out-of-range
/// values are errors.
pub fn parse(text: &str) -> Result<Settings, ConfigError> {
    let mut settings = Settings::default();
    let mut seen: Vec<&str> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split_once('#').map_or(raw, |(before, _)| before).trim();
        if line.is_empty() {
            continue;
        }
        let syntax = || ConfigError::new(format!("line {}", index + 1), "expected `key = integer`");
        let (key, value) = line.split_once('=').ok_or_else(syntax)?;
        let (key, value) = (key.trim(), value.trim());
        let key_ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        if !key_ok {
            return Err(syntax());
        }
        let (min, max, problem) = match key {
            "port" => (1024, 65535, "must be 1024..=65535"),
            "auto_lock_minutes" => (1, 240, "must be 1..=240"),
            "clipboard_clear_seconds" => (5, 300, "must be 5..=300"),
            _ => return Err(ConfigError::new(key, "unknown key")),
        };
        if seen.contains(&key) {
            return Err(ConfigError::new(key, "duplicate key"));
        }
        seen.push(key);
        let number = parse_decimal(value)
            .ok_or_else(|| ConfigError::new(key, "not a decimal integer"))?
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| ConfigError::new(key, problem))?;
        match key {
            "port" => settings.port = u16::try_from(number).expect("range checked"),
            "auto_lock_minutes" => settings.auto_lock = Duration::from_secs(number * 60),
            _ => settings.clipboard_clear = Duration::from_secs(number),
        }
    }
    Ok(settings)
}

/// `None`: not digits. `Some(None)`: digits, but too large for `u64`.
fn parse_decimal(value: &str) -> Option<Option<u64>> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(value.parse().ok())
}
