//! 003 FR-038: the QR is generated locally and returned as an SVG path of 1x1 modules.

use std::collections::HashSet;

use passwsyncd::qr::{QrSvg, pair_text, svg_path};

fn modules(qr: &QrSvg) -> HashSet<(usize, usize)> {
    let mut out = HashSet::new();
    for part in qr.path.split('z').filter(|p| !p.is_empty()) {
        let rest = part.strip_prefix('M').expect("each module starts with M");
        let (coords, tail) = rest.split_once('h').expect("h1v1h-1");
        assert_eq!(tail, "1v1h-1", "every module is a 1x1 square: {part}");
        let (x, y) = coords.split_once(' ').unwrap();
        out.insert((x.parse().unwrap(), y.parse().unwrap()));
    }
    out
}

#[test]
fn pairing_text_has_the_contract_format() {
    let id = "ab".repeat(32);
    assert_eq!(
        pair_text("12345678", &id, "192.168.1.5:27472".parse().unwrap()),
        format!("passwsync://pair?v=1&code=12345678&id={id}&addr=192.168.1.5:27472")
    );
}

#[test]
fn path_draws_the_known_matrix_with_a_quiet_zone() {
    let qr = svg_path("HELLO").unwrap();
    // Version 1 is 21 modules; a 4-module quiet zone on each side.
    assert_eq!(qr.size, 29);
    let dark = modules(&qr);
    // The three finder patterns: dark 7x7 ring, light ring, dark 3x3 centre.
    for (ox, oy) in [(4, 4), (4 + 14, 4), (4, 4 + 14)] {
        for i in 0..7 {
            for (x, y) in [
                (ox + i, oy),
                (ox + i, oy + 6),
                (ox, oy + i),
                (ox + 6, oy + i),
            ] {
                assert!(dark.contains(&(x, y)), "finder ring at {x},{y}");
            }
        }
        for i in 1..6 {
            assert!(!dark.contains(&(ox + i, oy + 1)), "light ring");
        }
        for dx in 2..5 {
            for dy in 2..5 {
                assert!(dark.contains(&(ox + dx, oy + dy)), "finder centre");
            }
        }
    }
    // Nothing is drawn in the quiet zone.
    assert!(
        dark.iter()
            .all(|&(x, y)| (4..25).contains(&x) && (4..25).contains(&y))
    );
    // Timing pattern on row 6 alternates between the finders.
    for x in 8..13 {
        assert_eq!(dark.contains(&(4 + x, 4 + 6)), x % 2 == 0, "timing at {x}");
    }
}

#[test]
fn pairing_text_fits_and_only_path_characters_are_used() {
    let id = "0f".repeat(32);
    let text = pair_text("00000001", &id, "169.254.200.200:65535".parse().unwrap());
    let qr = svg_path(&text).unwrap();
    assert!(qr.size > 29 && qr.size <= 4 + 57 + 4);
    assert!(
        qr.path
            .bytes()
            .all(|b| b.is_ascii_digit() || b"Mhvz -".contains(&b))
    );
}
