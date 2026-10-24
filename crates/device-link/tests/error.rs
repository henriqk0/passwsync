use device_link::error::{Error, FailReason};

#[test]
fn fail_reasons_render_exact_snake_case() {
    let all = [
        (FailReason::WrongCodeOrTampered, "wrong_code_or_tampered"),
        (FailReason::Expired, "expired"),
        (FailReason::Rejected, "rejected"),
        (FailReason::Timeout, "timeout"),
        (FailReason::IdMismatch, "id_mismatch"),
        (FailReason::SelfPair, "self"),
        (FailReason::AlreadyPaired, "already_paired"),
        (FailReason::Limit, "limit"),
        (FailReason::RefusedNotPairing, "refused_not_pairing"),
        (FailReason::Unreachable, "unreachable"),
        (FailReason::Cancelled, "cancelled"),
        (FailReason::Protocol, "protocol"),
    ];
    assert_eq!(all.len(), FailReason::ALL.len());
    for (reason, text) in all {
        assert_eq!(reason.as_str(), text);
        assert_eq!(reason.to_string(), text);
    }
}

#[test]
fn errors_render_fixed_codes_without_free_text() {
    let all = [
        (Error::InvalidName, "invalid_name"),
        (Error::InvalidDeviceId, "invalid_device_id"),
        (Error::InvalidCode, "invalid_code"),
        (Error::InvalidAddress, "invalid_address"),
        (Error::Malformed, "malformed"),
        (Error::Protocol, "protocol"),
        (Error::Storage, "storage_error"),
        (Error::SelfPair, "self"),
        (Error::AlreadyPaired, "already_paired"),
        (Error::Limit, "pair_limit"),
        (Error::NotFound, "device_not_found"),
        (Error::TooManyCodes, "too_many_codes"),
        (Error::Random, "random"),
        (Error::Crypto, "crypto"),
    ];
    for (error, text) in all {
        assert_eq!(error.code(), text);
        assert_eq!(error.to_string(), text);
    }
    // Copy + Eq: plain values, no payload.
    let a = Error::Storage;
    let b = a;
    assert_eq!(a, b);
}
