use device_link::identity::DeviceId;
use device_link::name::DeviceName;

#[test]
fn accepts_one_to_sixty_four_scalars_including_multibyte() {
    assert_eq!(DeviceName::parse("A").unwrap().as_str(), "A");
    let max = "x".repeat(64);
    assert_eq!(DeviceName::parse(&max).unwrap().as_str(), max);
    let multi = "é".repeat(64); // 128 bytes, 64 scalars
    assert!(DeviceName::parse(&multi).is_ok());
    assert!(DeviceName::parse("Laptop de Henrique 💻").is_ok());
}

#[test]
fn rejects_empty_too_long_control_and_quote() {
    assert!(DeviceName::parse("").is_err());
    assert!(DeviceName::parse(&"x".repeat(65)).is_err());
    assert!(DeviceName::parse(&"é".repeat(65)).is_err());
    assert!(DeviceName::parse("tab\there").is_err());
    assert!(DeviceName::parse("new\nline").is_err());
    assert!(DeviceName::parse("del\u{7f}").is_err());
    assert!(DeviceName::parse("c1\u{85}").is_err());
    assert!(DeviceName::parse("say \"hi\"").is_err());
}

#[test]
fn default_name_uses_first_four_fingerprint_characters() {
    let id = DeviceId::from_hex("eb201e73a1fca1c6db8ad80b69706df1787f1316348ddc819dcf6171eef14d0f")
        .unwrap();
    let name = DeviceName::default_for(&id.fingerprint());
    assert_eq!(name.as_str(), "passwsync device 5MQB");
    assert_eq!(name.to_string(), "passwsync device 5MQB");
}
