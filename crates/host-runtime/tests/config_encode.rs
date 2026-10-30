//! X7: `config::encode` round-trips every valid `Settings` through the unchanged `parse`.

use std::time::Duration;

use device_link::name::DeviceName;
use host_runtime::config::{NetworkSettings, Settings, encode, parse};

#[test]
fn encode_round_trips_over_range_edges_and_midpoints() {
    let mut count = 0;
    for auto_lock in [1u64, 120, 240] {
        for clip in [5u64, 150, 300] {
            for interval in [15u64, 700, 1440] {
                for (peer, discovery) in [(1024u16, 65535u16), (27472, 27473), (40000, 1025)] {
                    for enabled in [false, true] {
                        for interface in [None, Some("wlan0".to_string())] {
                            for name in [None, Some("passwsync device AB12"), Some("Phone é")] {
                                let s = Settings {
                                    port: Settings::default().port,
                                    auto_lock: Duration::from_secs(auto_lock * 60),
                                    clipboard_clear: Duration::from_secs(clip),
                                    sync_interval: Duration::from_secs(interval * 60),
                                    network: NetworkSettings {
                                        enabled,
                                        peer_port: peer,
                                        discovery_port: discovery,
                                        device_name: name.map(|n| DeviceName::parse(n).unwrap()),
                                        interface: interface.clone(),
                                    },
                                };
                                let text = encode(&s);
                                assert!(text.ends_with('\n'), "{text}");
                                assert!(
                                    !text.lines().any(|l| l.starts_with("port ")),
                                    "encode never writes port: {text}"
                                );
                                for line in text.lines() {
                                    assert!(line.contains(" = "), "{line}");
                                }
                                assert_eq!(parse(&text).unwrap(), s, "{text}");
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 3 * 3 * 3 * 3 * 2 * 2 * 3);
}

#[test]
fn encoding_the_defaults_parses_to_the_defaults() {
    assert_eq!(
        parse(&encode(&Settings::default())).unwrap(),
        Settings::default()
    );
}
