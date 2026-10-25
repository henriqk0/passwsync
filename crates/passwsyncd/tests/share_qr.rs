//! 005 T032: invitation code and QR (FR-005, FR-006, R5, R11).

use std::collections::HashSet;

use passwsyncd::qr::{group_code, new_invite_code, parse_share_text, share_text, svg_path};

fn id() -> String {
    "ab".repeat(32)
}

#[test]
fn invite_codes_are_8_csprng_digits_from_the_pairing_code_generator() {
    let mut seen = HashSet::new();
    for _ in 0..200 {
        let code = new_invite_code().unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        seen.insert(code.to_string());
    }
    assert!(seen.len() > 190, "random: {} distinct of 200", seen.len());
    // Reuses the reviewed 003 generator (uniform rejection sampling, Zeroizing).
    let source = include_str!("../src/qr.rs");
    assert!(source.contains("PairingCode::generate"));
}

#[test]
fn codes_are_shown_in_groups_of_four() {
    assert_eq!(group_code("12345678"), "1234 5678");
}

#[test]
fn the_share_text_has_the_contract_format() {
    assert_eq!(
        share_text("12345678", &id(), "192.168.1.5:27472".parse().unwrap()),
        format!(
            "passwsync://share?v=1&code=12345678&id={}&addr=192.168.1.5:27472",
            id()
        )
    );
}

#[test]
fn the_share_text_parses_back() {
    let text = share_text("00012345", &id(), "169.254.3.4:1".parse().unwrap());
    let parsed = parse_share_text(&text).unwrap();
    assert_eq!(parsed.code.as_str(), "00012345");
    assert_eq!(parsed.device_id, id());
    assert_eq!(parsed.addr, "169.254.3.4:1".parse().unwrap());
}

#[test]
fn malformed_or_oversized_share_texts_are_rejected() {
    let good = share_text("12345678", &id(), "192.168.1.5:27472".parse().unwrap());
    let bad = [
        good.replace("passwsync://share", "passwsync://pair"),
        good.replace("https", "x").replace("passwsync:", "http:"),
        good.replace("v=1", "v=2"),
        good.replace("12345678", "1234567"),
        good.replace("12345678", "1234567a"),
        good.replace("12345678", "123456789"),
        good.replace(&id(), &"AB".repeat(32)),
        good.replace(&id(), &"ab".repeat(31)),
        good.replace("192.168.1.5:27472", "192.168.1.5"),
        good.replace("192.168.1.5:27472", "host.example:1"),
        good.replace("192.168.1.5:27472", "192.168.1.5:0"),
        format!("{good}&x=1"),
        good.replace("&addr=192.168.1.5:27472", ""),
        format!("{good}{}", " ".repeat(300)),
        String::new(),
    ];
    for text in bad {
        assert!(parse_share_text(&text).is_none(), "accepted: {text}");
    }
}

#[test]
fn the_qr_is_generated_locally_as_a_path() {
    let text = share_text(
        "12345678",
        &"0f".repeat(32),
        "10.0.0.2:27472".parse().unwrap(),
    );
    let qr = svg_path(&text).unwrap();
    assert!(qr.size > 29);
    assert!(
        qr.path
            .bytes()
            .all(|b| b.is_ascii_digit() || b"Mhvz -".contains(&b))
    );
}
