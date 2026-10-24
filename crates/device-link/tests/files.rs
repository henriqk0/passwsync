use std::net::SocketAddrV4;

use device_link::error::Error;
use device_link::files::{decode_device_key, decode_peers, encode_device_key, encode_peers};
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::policy::AddressPolicy;
use device_link::registry::PeerPin;

const PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const OWN_PUB: [u8; 32] = [0xee; 32];

fn key_text(hex: &str) -> String {
    format!("passwsync-device-key-v1\n{hex}\n")
}

#[test]
fn device_key_encodes_exactly_and_round_trips() {
    let key = decode_device_key(key_text(PRIV).as_bytes()).unwrap();
    assert_eq!(*encode_device_key(&key), key_text(PRIV));
    let again = decode_device_key(encode_device_key(&key).as_bytes()).unwrap();
    assert_eq!(again.public(), key.public());
}

#[test]
fn device_key_decode_is_strict() {
    let bad = [
        String::new(),
        format!("passwsync-device-key-v2\n{PRIV}\n"),
        format!("passwsync-device-key-v1\n{}\n", PRIV.to_uppercase()),
        format!("passwsync-device-key-v1\n{}\n", &PRIV[..62]),
        format!("passwsync-device-key-v1\n{PRIV}"),
        format!("passwsync-device-key-v1\n{PRIV}\n\n"),
        format!("passwsync-device-key-v1\n{PRIV}\ngarbage\n"),
        format!("passwsync-device-key-v1 \n{PRIV}\n"),
        format!("passwsync-device-key-v1\r\n{PRIV}\n"),
    ];
    for text in bad {
        assert_eq!(
            decode_device_key(text.as_bytes()).err(),
            Some(Error::Malformed),
            "{text:?}"
        );
    }
    let mut bytes = key_text(PRIV).into_bytes();
    bytes[30] = 0xff;
    assert!(decode_device_key(&bytes).is_err(), "invalid utf-8");
}

fn pin(byte: u8, last: Option<(u64, &str)>) -> PeerPin {
    PeerPin {
        public: [byte; 32],
        name: DeviceName::parse("Phone é").unwrap(),
        paired_at: 1_761_200_000,
        last_seen: last.map(|(t, _)| t),
        last_addr: last.map(|(_, a)| a.parse::<SocketAddrV4>().unwrap()),
    }
}

fn line(byte: u8, rest: &str) -> String {
    format!("{} {rest}\n", format!("{byte:02x}").repeat(32))
}

const NAME_HEX: &str = "50686f6e6520c3a9"; // "Phone é"

#[test]
fn peers_encode_exact_lines_and_round_trip() {
    let pins = vec![
        pin(1, None),
        pin(2, Some((1_761_200_300, "192.168.1.7:27472"))),
    ];
    let text = encode_peers(&pins);
    let expected = format!(
        "passwsync-peers-v1\n{}{}",
        line(1, &format!("1761200000 - - {NAME_HEX}")),
        line(
            2,
            &format!("1761200000 1761200300 192.168.1.7:27472 {NAME_HEX}")
        )
    );
    assert_eq!(text, expected);
    let back = decode_peers(&text, &OWN_PUB, AddressPolicy::lan()).unwrap();
    assert_eq!(back, pins);
    assert_eq!(
        decode_peers("passwsync-peers-v1\n", &OWN_PUB, AddressPolicy::lan()).unwrap(),
        vec![]
    );
}

#[test]
fn peers_decode_rejects_every_corruption_class() {
    let header = "passwsync-peers-v1\n";
    let ok = line(1, &format!("1761200000 - - {NAME_HEX}"));
    let mut bad = vec![
        String::new(),
        format!("passwsync-peers-v2\n{ok}"),
        format!("{header}{}", ok.to_uppercase()),
        format!("{header}{}", line(1, &format!("1761200000 - {NAME_HEX}"))),
        format!(
            "{header}{}",
            line(1, &format!("1761200000 - - {NAME_HEX} extra"))
        ),
        format!("{header}{ok}{ok}"),
        format!(
            "{header}{}",
            line(0xee, &format!("1761200000 - - {NAME_HEX}"))
        ),
        format!("{header}{}", line(1, "1761200000 - - ")),
        format!("{header}{}", line(1, "1761200000 - - 41220a")),
        format!("{header}{}", line(1, "1761200000 - - 4")),
        format!("{header}{}", line(1, "1761200000 - - 4G")),
        format!(
            "{header}{}",
            line(1, &format!("1761200000 - 8.8.8.8:27472 {NAME_HEX}"))
        ),
        format!(
            "{header}{}",
            line(1, &format!("1761200000 - 127.0.0.1:27472 {NAME_HEX}"))
        ),
        format!(
            "{header}{}",
            line(1, &format!("1761200000 - host:27472 {NAME_HEX}"))
        ),
        format!("{header}{}", line(1, &format!("x - - {NAME_HEX}"))),
        format!("{header}{}", line(1, &format!("1761200000 y - {NAME_HEX}"))),
        format!("{header}{ok}trailing garbage"),
        format!("{header}{ok}\n"),
        format!("{header}{}", ok.trim_end()),
    ];
    let mut many = header.to_string();
    for byte in 1..=33u8 {
        many.push_str(&line(byte, &format!("1761200000 - - {NAME_HEX}")));
    }
    bad.push(many);
    for text in bad {
        assert_eq!(
            decode_peers(&text, &OWN_PUB, AddressPolicy::lan()).err(),
            Some(Error::Malformed),
            "{text:?}"
        );
    }
}

#[test]
fn thirty_two_peers_are_accepted() {
    let mut text = "passwsync-peers-v1\n".to_string();
    for byte in 1..=32u8 {
        text.push_str(&line(byte, &format!("1761200000 - - {NAME_HEX}")));
    }
    assert_eq!(
        decode_peers(&text, &OWN_PUB, AddressPolicy::lan())
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn testkit_policy_admits_loopback_addresses() {
    let text = format!(
        "passwsync-peers-v1\n{}",
        line(1, &format!("1761200000 5 127.0.0.1:27472 {NAME_HEX}"))
    );
    assert!(decode_peers(&text, &OWN_PUB, AddressPolicy::testkit()).is_ok());
}

#[test]
fn generated_key_round_trips() {
    let key = DeviceKey::generate(&mut rand_core::OsRng).unwrap();
    let back = decode_device_key(encode_device_key(&key).as_bytes()).unwrap();
    assert_eq!(back.public(), key.public());
}
