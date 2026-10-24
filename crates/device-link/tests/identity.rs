use std::marker::PhantomData;

use device_link::identity::{DeviceId, DeviceKey, Fingerprint};
use rand_core::OsRng;

const RFC7748_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const RFC7748_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const EXPECTED_ID: &str = "eb201e73a1fca1c6db8ad80b69706df1787f1316348ddc819dcf6171eef14d0f";

fn unhex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Trait-absence probe (inherent associated consts win over the blanket trait const only when
/// the bound holds).
trait NoDebug {
    const IS_DEBUG: bool = false;
}
impl<T: ?Sized> NoDebug for T {}
struct ProbeDebug<T: ?Sized>(PhantomData<T>);
#[allow(dead_code)]
impl<T: ?Sized + std::fmt::Debug> ProbeDebug<T> {
    const IS_DEBUG: bool = true;
}
trait NoDisplay {
    const IS_DISPLAY: bool = false;
}
impl<T: ?Sized> NoDisplay for T {}
struct ProbeDisplay<T: ?Sized>(PhantomData<T>);
#[allow(dead_code)]
impl<T: ?Sized + std::fmt::Display> ProbeDisplay<T> {
    const IS_DISPLAY: bool = true;
}

#[test]
fn probes_detect_debug_and_display() {
    const { assert!(<ProbeDebug<u8>>::IS_DEBUG) };
    const { assert!(<ProbeDisplay<u8>>::IS_DISPLAY) };
}

#[test]
fn device_key_is_neither_debug_nor_display() {
    const { assert!(!<ProbeDebug<DeviceKey>>::IS_DEBUG) };
    const { assert!(!<ProbeDisplay<DeviceKey>>::IS_DISPLAY) };
}

#[test]
fn public_key_matches_rfc7748_vector() {
    let key = DeviceKey::from_private(unhex32(RFC7748_PRIVATE));
    assert_eq!(key.public(), &unhex32(RFC7748_PUBLIC));
    assert_eq!(key.private_bytes(), &unhex32(RFC7748_PRIVATE));
}

#[test]
fn generated_keys_differ_and_derive_their_public_key() {
    let a = DeviceKey::generate(&mut OsRng).unwrap();
    let b = DeviceKey::generate(&mut OsRng).unwrap();
    assert_ne!(a.public(), b.public());
    let again = DeviceKey::from_private(*a.private_bytes());
    assert_eq!(again.public(), a.public());
}

#[test]
fn device_id_is_domain_separated_sha256_of_public_key() {
    let id = DeviceId::from_public(&unhex32(RFC7748_PUBLIC));
    assert_eq!(id.to_hex(), EXPECTED_ID);
    assert_eq!(id.to_string(), EXPECTED_ID);
    let key = DeviceKey::from_private(unhex32(RFC7748_PRIVATE));
    assert_eq!(key.id(), id);
}

#[test]
fn device_id_hex_round_trip_is_strict() {
    let id = DeviceId::from_hex(EXPECTED_ID).unwrap();
    assert_eq!(id.to_hex(), EXPECTED_ID);
    assert!(DeviceId::from_hex(&EXPECTED_ID.to_uppercase()).is_err());
    assert!(DeviceId::from_hex(&EXPECTED_ID[..63]).is_err());
    assert!(DeviceId::from_hex(&format!("{EXPECTED_ID}0")).is_err());
    assert!(DeviceId::from_hex(&format!("g{}", &EXPECTED_ID[1..])).is_err());
    assert!(DeviceId::from_hex("").is_err());
}

#[test]
fn device_id_orders_by_bytes() {
    let low = DeviceId::from_bytes([0u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let mid = DeviceId::from_bytes(bytes);
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    let high = DeviceId::from_bytes(bytes);
    assert!(low < mid && mid < high);
    assert_eq!(high.as_bytes()[0], 1);
}

#[test]
fn fingerprint_is_base32_of_first_ten_id_bytes_in_groups() {
    let id = DeviceId::from_hex(EXPECTED_ID).unwrap();
    let fp: Fingerprint = id.fingerprint();
    assert_eq!(fp.to_string(), "5MQB-445B-7SQ4-NW4K");
    assert_eq!(fp.as_str().len(), 19);
    assert_eq!(fp.prefix4(), "5MQB");
    // RFC 4648 test vector: base32("foobar") = MZXW6YTBOI (first 10 bytes pad with zeros).
    let mut bytes = [0u8; 32];
    bytes[..10].copy_from_slice(b"foobarfoob");
    assert_eq!(
        DeviceId::from_bytes(bytes).fingerprint().to_string(),
        "MZXW-6YTB-OJTG-633C"
    );
}

fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn the_device_key_is_zeroize_on_drop_and_duplicates_without_a_bare_copy() {
    wiped_on_drop::<DeviceKey>();
    let key = DeviceKey::from_private(unhex32(RFC7748_PRIVATE));
    // The node gets its own key from a wiped buffer, never from `*private_bytes()`.
    let twin = key.duplicate();
    assert_eq!(twin.public(), key.public());
    assert_eq!(twin.private_bytes(), key.private_bytes());
    let from_wiped = DeviceKey::from_zeroizing(zeroize::Zeroizing::new(unhex32(RFC7748_PRIVATE)));
    assert_eq!(from_wiped.id(), key.id());
}
