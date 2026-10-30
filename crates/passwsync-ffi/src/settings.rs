#![forbid(unsafe_code)]
//! Settings of the app (data-model.md section 9, FR-033): the desktop `key = value` grammar of
//! `host_runtime::config`. An unusable file never stops the app: the defaults apply (networking
//! off), the UI shows a notice and one `SettingsReset` line is logged.

use std::path::Path;

use device_link::identity::Fingerprint;
use device_link::name::DeviceName;
use host_runtime::config::{self, Settings};
use host_runtime::files::read_private_file;
use host_runtime::log::{Log, LogEvent};

use crate::records::SettingsView;

pub const SETTINGS_FILE: &str = "settings";
/// Larger files are unusable.
const LIMIT: u64 = 64 * 1024;

/// The settings in force for this process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSettings {
    pub settings: Settings,
    /// The file was unusable and the defaults apply.
    pub reset_notice: bool,
}

/// Reads `<data_dir>/settings`. Missing: defaults, no notice. Not a private regular file, too
/// large, not UTF-8 or not valid: defaults with a notice and one log line.
pub fn load(data_dir: &Path, log: &Log) -> LoadedSettings {
    match read_private_file(&data_dir.join(SETTINGS_FILE), LIMIT) {
        Ok(None) => LoadedSettings {
            settings: Settings::default(),
            reset_notice: false,
        },
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| config::parse(&without_port(text)).ok())
        {
            Some(settings) => LoadedSettings {
                settings,
                reset_notice: false,
            },
            None => reset(log),
        },
        Err(_) => reset(log),
    }
}

fn reset(log: &Log) -> LoadedSettings {
    log.emit(&LogEvent::SettingsReset);
    LoadedSettings {
        settings: Settings::default(),
        reset_notice: true,
    }
}

/// The desktop HTTP `port` key means nothing here: its lines are dropped before parsing, so
/// it can neither be used nor make the file invalid.
fn without_port(text: &str) -> String {
    text.lines()
        .filter(|line| {
            line.split_once('=')
                .is_none_or(|(key, _)| key.trim() != "port")
        })
        .map(|line| format!("{line}\n"))
        .collect()
}

/// The settings screen. `fingerprint`: this device's, for the default name (never an
/// OS-provided name; FR-036).
pub fn view(
    loaded: &LoadedSettings,
    fingerprint: Option<&Fingerprint>,
    restart_required: bool,
) -> SettingsView {
    let s = &loaded.settings;
    let device_name = match (&s.network.device_name, fingerprint) {
        (Some(name), _) => name.as_str().to_owned(),
        (None, Some(fp)) => DeviceName::default_for(fp).as_str().to_owned(),
        (None, None) => "passwsync device".to_owned(),
    };
    SettingsView {
        auto_lock_minutes: minutes(s.auto_lock.as_secs()),
        clipboard_clear_seconds: u32::try_from(s.clipboard_clear.as_secs()).unwrap_or(u32::MAX),
        networking: s.network.enabled,
        device_name,
        sync_interval_minutes: minutes(s.sync_interval.as_secs()),
        network_interface: s.network.interface.clone(),
        reset_notice: loaded.reset_notice,
        restart_required,
    }
}

fn minutes(seconds: u64) -> u32 {
    u32::try_from(seconds / 60).unwrap_or(u32::MAX)
}
