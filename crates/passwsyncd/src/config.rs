//! The optional `key = value` settings file (contracts/host-runtime.md, extended by
//! 003 contracts/host-runtime-network.md).

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use device_link::name::DeviceName;

/// Settings read once at start-up. Not secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub port: u16,
    pub auto_lock: Duration,
    pub clipboard_clear: Duration,
    pub network: NetworkSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 27471,
            auto_lock: Duration::from_secs(15 * 60),
            clipboard_clear: Duration::from_secs(30),
            network: NetworkSettings::default(),
        }
    }
}

/// Device networking settings (003, data-model.md "NetworkSettings"). Read-only in the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSettings {
    pub enabled: bool,
    pub peer_port: u16,
    pub discovery_port: u16,
    /// `None`: the default `passwsync device XXXX` name.
    pub device_name: Option<DeviceName>,
    /// `None`: every eligible interface.
    pub interface: Option<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            peer_port: 27472,
            discovery_port: 27473,
            device_name: None,
            interface: None,
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

enum Value<'a> {
    Bare(&'a str),
    Quoted(&'a str),
}

/// Splits the value part of a line: a `"string"` (no escapes, no inner `"`) or a bare word,
/// each optionally followed by a `#` comment. `Err(())`: an unterminated or malformed string.
fn split_value(raw: &str) -> Result<Value<'_>, ()> {
    let trimmed = raw.trim_start();
    if let Some(rest) = trimmed.strip_prefix('"') {
        let close = rest.find('"').ok_or(())?;
        let (inner, after) = (&rest[..close], rest[close + 1..].trim_start());
        if !(after.is_empty() || after.starts_with('#')) || inner.contains('\\') {
            return Err(());
        }
        return Ok(Value::Quoted(inner));
    }
    let bare = trimmed
        .split_once('#')
        .map_or(trimmed, |(before, _)| before);
    Ok(Value::Bare(bare.trim()))
}

fn is_interface_name(text: &str) -> bool {
    (1..=15).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parses the settings text. Unknown or duplicate keys, other syntax, and out-of-range
/// values are errors.
pub fn parse(text: &str) -> Result<Settings, ConfigError> {
    let mut settings = Settings::default();
    let mut seen: Vec<&str> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let syntax = || ConfigError::new(format!("line {}", index + 1), "expected `key = integer`");
        let (key, value) = raw.split_once('=').ok_or_else(syntax)?;
        let key = key.trim();
        let key_ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        if !key_ok {
            return Err(syntax());
        }
        let value = split_value(value);
        let range = match key {
            "port" | "peer_port" | "discovery_port" => Some((1024, 65535, "must be 1024..=65535")),
            "auto_lock_minutes" => Some((1, 240, "must be 1..=240")),
            "clipboard_clear_seconds" => Some((5, 300, "must be 5..=300")),
            "network" | "device_name" | "network_interface" => None,
            _ => return Err(ConfigError::new(key, "unknown key")),
        };
        if seen.contains(&key) {
            return Err(ConfigError::new(key, "duplicate key"));
        }
        seen.push(key);
        if let Some((min, max, problem)) = range {
            let digits = match value {
                Ok(Value::Bare(word)) => word,
                _ => "",
            };
            let number = parse_decimal(digits)
                .ok_or_else(|| ConfigError::new(key, "not a decimal integer"))?
                .filter(|n| (min..=max).contains(n))
                .ok_or_else(|| ConfigError::new(key, problem))?;
            let port = || u16::try_from(number).expect("range checked");
            match key {
                "port" => settings.port = port(),
                "peer_port" => settings.network.peer_port = port(),
                "discovery_port" => settings.network.discovery_port = port(),
                "auto_lock_minutes" => settings.auto_lock = Duration::from_secs(number * 60),
                _ => settings.clipboard_clear = Duration::from_secs(number),
            }
            continue;
        }
        let quoted = || match value {
            Ok(Value::Quoted(inner)) => Ok(inner),
            _ => Err(ConfigError::new(key, "not a quoted string")),
        };
        match key {
            "network" => {
                settings.network.enabled = match value {
                    Ok(Value::Bare("on")) => true,
                    Ok(Value::Bare("off")) => false,
                    _ => return Err(ConfigError::new(key, "must be on or off")),
                }
            }
            "device_name" => {
                let name = DeviceName::parse(quoted()?).map_err(|_| {
                    ConfigError::new(
                        key,
                        "must be 1..64 characters without control characters or quotes",
                    )
                })?;
                settings.network.device_name = Some(name);
            }
            _ => {
                let name = quoted()?;
                if !is_interface_name(name) {
                    return Err(ConfigError::new(key, "must be 1..15 of [A-Za-z0-9._-]"));
                }
                settings.network.interface = Some(name.to_owned());
            }
        }
    }
    let net = &settings.network;
    // A clash between the two network ports names the key the file set (discovery_port when
    // both were set).
    let blame_peer = !seen.contains(&"discovery_port");
    if net.peer_port == settings.port || (net.peer_port == net.discovery_port && blame_peer) {
        return Err(ConfigError::new(
            "peer_port",
            "must differ from port and discovery_port",
        ));
    }
    if net.discovery_port == settings.port || net.discovery_port == net.peer_port {
        return Err(ConfigError::new(
            "discovery_port",
            "must differ from port and peer_port",
        ));
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
