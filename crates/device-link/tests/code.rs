use std::time::Duration;

use device_link::code::{CODE_VALIDITY, CodeRateLimiter, CodeState, PairingCode, normalize_code};
use device_link::error::Error;
use device_link::testkit::ScriptedRng;

const S: fn(u64) -> Duration = Duration::from_secs;

#[test]
fn code_is_eight_digits_with_leading_zeros_kept() {
    let code = PairingCode::generate(&mut ScriptedRng::new(&[12_345]), S(0)).unwrap();
    assert_eq!(code.digits(), "00012345");
    assert_eq!(&*code.grouped(), "0001 2345");
    let code = PairingCode::generate(&mut ScriptedRng::new(&[4_199_999_999]), S(0)).unwrap();
    assert_eq!(code.digits(), "99999999");
}

#[test]
fn values_in_the_biased_tail_are_rejected_not_folded() {
    // 2^32 = 42 * 10^8 + 94_967_296: values >= 4_200_000_000 would bias low codes.
    let code = PairingCode::generate(
        &mut ScriptedRng::new(&[4_294_967_295, 4_200_000_000, 7]),
        S(0),
    )
    .unwrap();
    assert_eq!(code.digits(), "00000007");
}

#[test]
fn codes_from_the_os_rng_differ_and_are_digits() {
    let a = PairingCode::generate(&mut rand_core::OsRng, S(0)).unwrap();
    let b = PairingCode::generate(&mut rand_core::OsRng, S(0)).unwrap();
    assert!(a.digits().bytes().all(|c| c.is_ascii_digit()) && a.digits().len() == 8);
    assert_ne!(a.digits(), b.digits(), "1 in 10^8 flake");
}

#[test]
fn code_expires_after_300_seconds() {
    assert_eq!(CODE_VALIDITY, S(300));
    let code = PairingCode::generate(&mut ScriptedRng::new(&[1]), S(10)).unwrap();
    assert_eq!(code.state(S(10)), CodeState::Active);
    assert_eq!(code.seconds_left(S(10)), 300);
    assert_eq!(code.seconds_left(S(297)), 13);
    assert_eq!(code.state(S(309)), CodeState::Active);
    assert_eq!(code.state(S(310)), CodeState::Expired);
    assert_eq!(code.seconds_left(S(400)), 0);
    assert!(!code.matches_active("00000001", S(310)));
}

#[test]
fn state_transitions() {
    let rng = || ScriptedRng::new(&[42]);
    let mut code = PairingCode::generate(&mut rng(), S(0)).unwrap();
    code.consume(S(1)).unwrap();
    assert_eq!(code.state(S(1)), CodeState::Consumed);
    assert_eq!(code.consume(S(2)), Err(Error::InvalidCode), "single use");
    code.accept();
    assert_eq!(code.state(S(2)), CodeState::Accepted);

    let mut code = PairingCode::generate(&mut rng(), S(0)).unwrap();
    code.consume(S(1)).unwrap();
    code.fail();
    assert_eq!(code.state(S(1)), CodeState::Failed);

    let mut code = PairingCode::generate(&mut rng(), S(0)).unwrap();
    code.cancel();
    assert_eq!(code.state(S(1)), CodeState::Cancelled);
    assert_eq!(code.consume(S(1)), Err(Error::InvalidCode));

    let mut code = PairingCode::generate(&mut rng(), S(0)).unwrap();
    code.replace();
    assert_eq!(code.state(S(1)), CodeState::Replaced);

    let mut code = PairingCode::generate(&mut rng(), S(0)).unwrap();
    assert_eq!(code.consume(S(300)), Err(Error::InvalidCode), "expired");
    assert_eq!(code.state(S(300)), CodeState::Expired);
}

#[test]
fn rate_limiter_allows_five_codes_per_600_seconds() {
    let mut limiter = CodeRateLimiter::default();
    for i in 0..5 {
        assert!(limiter.try_create(S(i * 10)), "code {i}");
    }
    assert!(!limiter.try_create(S(100)), "6th within 600 s");
    assert!(!limiter.try_create(S(599)));
    assert!(limiter.try_create(S(600)), "oldest slid out");
    assert!(!limiter.try_create(S(601)));
}

#[test]
fn input_normalization_accepts_spaces_and_dashes() {
    assert_eq!(normalize_code("1234 5678").unwrap().as_str(), "12345678");
    assert_eq!(normalize_code(" 1234-5678 ").unwrap().as_str(), "12345678");
    assert_eq!(normalize_code("00012345").unwrap().as_str(), "00012345");
    for bad in [
        "1234567",
        "123456789",
        "1234 567a",
        "",
        "１２３４５６７８",
        "1234_5678",
    ] {
        assert_eq!(normalize_code(bad).err(), Some(Error::InvalidCode), "{bad}");
    }
}

#[test]
fn code_has_no_debug_and_wipes_on_drop() {
    // Compile-time trait absence: see identity.rs for the probe technique.
    trait NoDebug {
        const IS_DEBUG: bool = false;
    }
    impl<T: ?Sized> NoDebug for T {}
    struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
    #[allow(dead_code)]
    impl<T: ?Sized + std::fmt::Debug> Probe<T> {
        const IS_DEBUG: bool = true;
    }
    const { assert!(!<Probe<PairingCode>>::IS_DEBUG) };
    fn wipes<T: zeroize::ZeroizeOnDrop>() {}
    wipes::<PairingCode>();
}
