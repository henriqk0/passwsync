use wallet_service::Sessions;

fn sessions() -> Sessions {
    Sessions::new().unwrap()
}

#[test]
fn launch_token_is_32_random_bytes_fresh_per_run() {
    let a = sessions();
    let b = sessions();
    assert_eq!(a.launch_token().len(), 32);
    assert_ne!(a.launch_token(), b.launch_token());
    assert_ne!(a.launch_token(), &[0u8; 32]);
}

#[test]
fn exchange_is_single_use_and_rotates_the_token() {
    let mut s = sessions();
    let first = *s.launch_token();
    let grant = s.exchange(&first).expect("valid token");
    assert_eq!(&*grant.next_launch, s.launch_token());
    assert_ne!(s.launch_token(), &first);
    assert!(s.exchange(&first).is_none(), "old token is spent");
    assert_ne!(*grant.session_id, *grant.csrf);
    assert_eq!(s.len(), 1);
}

#[test]
fn wrong_or_malformed_tokens_fail() {
    let mut s = sessions();
    let mut wrong = *s.launch_token();
    wrong[31] ^= 1;
    assert!(s.exchange(&wrong).is_none());
    assert!(s.exchange(&[]).is_none());
    let short: Vec<u8> = s.launch_token()[..31].into();
    assert!(s.exchange(&short).is_none());
    assert_eq!(s.len(), 0);
}

#[test]
fn authenticate_finds_the_session_and_checks_its_csrf() {
    let mut s = sessions();
    let token = *s.launch_token();
    let grant = s.exchange(&token).unwrap();
    let session = s.authenticate(&*grant.session_id).expect("known cookie");
    assert!(Sessions::check_csrf(&session, &*grant.csrf));
    assert!(!Sessions::check_csrf(&session, &*grant.session_id));
    assert!(!Sessions::check_csrf(&session, b"short"));
    assert_eq!(**session.csrf(), *grant.csrf);
    assert!(s.authenticate(&*grant.csrf).is_none());
    assert!(s.authenticate(&[0u8; 32]).is_none());
    assert!(s.authenticate(b"").is_none());
}

#[test]
fn at_most_32_sessions_oldest_evicted() {
    let mut s = sessions();
    let mut grants = Vec::new();
    for _ in 0..33 {
        let token = *s.launch_token();
        grants.push(s.exchange(&token).unwrap());
    }
    assert_eq!(s.len(), 32);
    assert!(
        s.authenticate(&*grants[0].session_id).is_none(),
        "oldest evicted"
    );
    assert!(s.authenticate(&*grants[1].session_id).is_some());
    assert!(s.authenticate(&*grants[32].session_id).is_some());
}

#[test]
fn sessions_from_another_run_are_unknown() {
    let mut old = sessions();
    let token = *old.launch_token();
    let grant = old.exchange(&token).unwrap();
    let new = sessions();
    assert!(new.authenticate(&*grant.session_id).is_none());
}

#[test]
fn debug_output_contains_no_token_material() {
    let s = sessions();
    let text = format!("{s:?}");
    let hex: String = s
        .launch_token()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!text.contains(&hex));
    assert!(!text.contains(&format!("{:?}", s.launch_token())));
}
