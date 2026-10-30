//! FR-009: inbound secrets are converted in place and wiped on every path. Freed heap blocks
//! are additionally zeroed by the allocator (tests/memprotect.rs).

use passwsync_ffi::error::CoreError;
use passwsync_ffi::secret::SecretInput;

#[test]
fn valid_utf8_converts_in_place() {
    let bytes = "correct horse battery é".as_bytes().to_vec();
    let ptr = bytes.as_ptr();
    let secret = SecretInput::try_from(bytes).unwrap();
    assert_eq!(secret.as_str(), "correct horse battery é");
    assert_eq!(secret.as_str().as_ptr(), ptr, "no copy was made");
    let owned = secret.into_zeroizing();
    assert_eq!(owned.as_str(), "correct horse battery é");
}

#[test]
fn invalid_utf8_is_invalid_input() {
    let err = SecretInput::try_from(vec![0xff, 0xfe, b'a']).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput));
}

#[test]
fn the_error_path_wipes_the_returned_bytes() {
    // The rejected buffer is handed back by `from_utf8` and must go into `Zeroizing`.
    let source = include_str!("../src/secret.rs");
    assert!(source.contains("Zeroizing::new(error.into_bytes())"));
}

#[test]
fn debug_never_prints_content() {
    let secret = SecretInput::try_from(b"MARKER-secret-value".to_vec()).unwrap();
    let text = format!("{secret:?}");
    assert!(!text.contains("MARKER"), "{text}");
    assert_eq!(text, "SecretInput(..)");
}

#[test]
fn digits_only_codes_are_checked() {
    assert_eq!(
        SecretInput::digits(b"1234 5678".to_vec()).unwrap().as_str(),
        "12345678"
    );
    assert!(matches!(
        SecretInput::digits(b"12a4".to_vec()),
        Err(CoreError::InvalidInput)
    ));
}
