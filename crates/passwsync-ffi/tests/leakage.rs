//! SC-003 (FR-009, FR-010, FR-057): every US1 and US2 operation is driven with marker values;
//! no marker password, notes or typed code ever appears in an error (Display or Debug), a log
//! line, a list or search record, a sealed plaintext, the settings file or the clipboard
//! marker. Titles, usernames and URLs are shown in lists by design but never logged. Later
//! stories extend this test in their own test tasks.

mod common;

use std::fs;
use std::time::Duration;

use common::{Fakes, TempDir, bytes, tree};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CopyField, CredentialInput, SettingsInput};

const MASTER: &str = "MARKER-master-password-1";
const NEW_MASTER: &str = "MARKER-master-password-2";
const PASSWORD: &str = "MARKER-credential-password";
const NEW_PASSWORD: &str = "MARKER-credential-password-new";
const USERNAME: &str = "MARKER-username";
const NOTES: &str = "MARKER-notes";
const URL: &str = "https://MARKER-url.example";
const TITLE: &str = "MARKER-title";
const CODE: &str = "MARKER-code-123456";

/// Never shown anywhere except through reveal or copy.
const SECRETS: [&str; 6] = [MASTER, NEW_MASTER, PASSWORD, NEW_PASSWORD, NOTES, CODE];
/// Shown in lists, never logged, sealed or written in clear.
const VISIBLE: [&str; 3] = [USERNAME, URL, TITLE];

fn assert_clean(what: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(!text.contains(marker), "{what} contains {marker}: {text}");
    }
}

fn record(errors: &mut Vec<CoreError>, result: Result<impl Sized, CoreError>) {
    if let Err(error) = result {
        errors.push(error);
    }
}

#[test]
fn no_marker_leaks_through_any_us1_or_us2_operation() {
    let dir = TempDir::new("leak");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let mut errors = Vec::new();
    let mut shown = Vec::new();

    // US1: create (refused variants first), unlock, change password, settings, locks.
    record(
        &mut errors,
        core.create_wallet("Personal".into(), bytes(MASTER), bytes(NEW_MASTER)),
    );
    record(
        &mut errors,
        core.create_wallet("Personal".into(), bytes("MARKER"), bytes("MARKER")),
    );
    core.create_wallet("Personal".into(), bytes(MASTER), bytes(MASTER))
        .unwrap();
    core.lock_all();
    record(
        &mut errors,
        core.unlock_wallet("Personal".into(), bytes(NEW_MASTER)),
    );
    record(
        &mut errors,
        core.unlock_wallet("Personal".into(), bytes(CODE)),
    );
    core.unlock_wallet("Personal".into(), bytes(MASTER))
        .unwrap();
    record(
        &mut errors,
        core.change_password(
            "Personal".into(),
            bytes(CODE),
            bytes(NEW_MASTER),
            bytes(NEW_MASTER),
        ),
    );
    core.change_password(
        "Personal".into(),
        bytes(MASTER),
        bytes(NEW_MASTER),
        bytes(NEW_MASTER),
    )
    .unwrap();
    record(
        &mut errors,
        core.update_settings(SettingsInput {
            auto_lock_minutes: 0,
            clipboard_clear_seconds: 30,
            device_name: Some(format!("{CODE}\n")),
            sync_interval_minutes: 60,
            network_interface: None,
        }),
    );

    // US2: credentials, search, reveal, copy, deadlines.
    let input = |password: Option<&str>| CredentialInput {
        title: TITLE.into(),
        username: USERNAME.into(),
        url: URL.into(),
        notes: NOTES.into(),
        password: password.map(bytes),
    };
    let id = core
        .add_credential("Personal".into(), input(Some(PASSWORD)))
        .unwrap();
    record(
        &mut errors,
        core.add_credential(
            "Personal".into(),
            CredentialInput {
                title: " ".into(),
                ..input(Some(PASSWORD))
            },
        ),
    );
    core.update_credential("Personal".into(), id.clone(), input(Some(NEW_PASSWORD)))
        .unwrap();
    for query in [TITLE, USERNAME, "marker", NOTES, PASSWORD] {
        shown.push(format!(
            "{:?}",
            core.search("Personal".into(), query.into()).unwrap()
        ));
    }
    shown.push(format!("{:?}", core.list_wallets().unwrap()));
    shown.push(format!("{:?}", core.settings()));
    shown.push(format!("{:?}", core.protection_status()));
    let details = core.get_credential("Personal".into(), id.clone()).unwrap();
    assert_eq!(details.notes, NOTES, "details show the notes by design");
    let revealed = core.reveal_password("Personal".into(), id.clone()).unwrap();
    assert_eq!(revealed.password, NEW_PASSWORD.as_bytes());
    core.copy_field("Personal".into(), id.clone(), CopyField::Password)
        .unwrap();
    let marker = fs::read_to_string(dir.path().join("clipboard-pending")).unwrap();
    core.copy_field("Personal".into(), id.clone(), CopyField::Username)
        .unwrap();
    record(
        &mut errors,
        core.get_credential("Personal".into(), CODE.into()),
    );
    record(
        &mut errors,
        core.reveal_password("Personal".into(), CODE.into()),
    );
    fakes.clock.advance(Duration::from_secs(31));
    core.on_deadline();
    core.leave_credential_view();
    core.delete_credential("Personal".into(), id).unwrap();
    core.on_screen_off();
    record(&mut errors, core.search("Personal".into(), PASSWORD.into()));
    let settings_text = fs::read_to_string(dir.path().join("settings")).unwrap_or_default();
    core.shutdown();

    assert!(
        errors.len() >= 8,
        "every refused call was recorded: {errors:?}"
    );
    for error in &errors {
        assert_clean("error Display", &error.to_string(), &SECRETS);
        assert_clean("error Display", &error.to_string(), &VISIBLE);
        assert_clean("error Debug", &format!("{error:?}"), &SECRETS);
        assert_clean("error Debug", &format!("{error:?}"), &VISIBLE);
    }
    for text in &shown {
        assert_clean("list or search record", text, &SECRETS);
    }
    for line in fakes.log.lines() {
        assert_clean("log line", &line, &SECRETS);
        assert_clean("log line", &line, &VISIBLE);
    }
    for plaintext in fakes.sealer.plaintexts() {
        let text = String::from_utf8_lossy(&plaintext);
        assert_clean("sealed plaintext", &text, &SECRETS);
        assert_clean("sealed plaintext", &text, &VISIBLE);
    }
    assert_clean("settings file", &settings_text, &SECRETS);
    assert_clean("clipboard marker", &marker, &SECRETS);
    assert_clean("clipboard marker", &marker, &VISIBLE);
    for event in fakes.notifier.events() {
        let text = format!("{event:?}");
        assert_clean("ui event", &text, &SECRETS);
        assert_clean("ui event", &text, &VISIBLE);
    }
    // No file of the data directory holds a marker in clear (wallets are encrypted).
    for (path, is_dir, _) in tree(dir.path()) {
        if is_dir {
            continue;
        }
        let content = fs::read(dir.path().join(&path)).unwrap();
        let text = String::from_utf8_lossy(&content);
        assert_clean(&path, &text, &SECRETS);
        assert_clean(&path, &text, &VISIBLE);
    }
}

#[test]
fn copied_values_reach_only_the_clipboard_port() {
    let dir = TempDir::new("leak-copy");
    let fakes = Fakes::new();
    let core = common::core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential(
            "Personal".into(),
            CredentialInput {
                title: "Mail".into(),
                username: USERNAME.into(),
                url: String::new(),
                notes: String::new(),
                password: Some(bytes(PASSWORD)),
            },
        )
        .unwrap();
    let ticket = core
        .copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    // The ticket carries only the countdown.
    assert_clean("copy ticket", &format!("{ticket:?}"), &SECRETS);
    assert_eq!(
        fakes.clipboard.current().as_deref(),
        Some(PASSWORD.as_bytes())
    );
    for line in fakes.log.lines() {
        assert_clean("log line", &line, &SECRETS);
    }
}

// --- T105 (US4): pairing codes and fingerprints ---------------------------------------------

#[test]
fn pairing_codes_never_reach_an_error_a_log_line_or_a_sealed_plaintext() {
    let _guard = common::serial();
    let (a, b) = common::two_nodes("leak-pair");
    let a_id = a.id();
    let shown = a.core().start_pairing().unwrap().code.unwrap();
    assert!(common::wait_for(Duration::from_secs(10), || b
        .core()
        .network()
        .nearby
        .iter()
        .any(|n| n.device.id == a_id)));
    let mut errors = Vec::new();
    // Typed codes that fail locally, and one wrong code that fails over the wire.
    for typed in ["98761234x", "9876 12", "87654321"] {
        record(
            &mut errors,
            b.core().join_pairing(a_id.clone(), bytes(typed)),
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    record(
        &mut errors,
        b.core().join_pairing(a_id.clone(), bytes(&shown)),
    );
    common::wait_for(Duration::from_secs(5), || {
        a.core().pairing().state == passwsync_ffi::records::PairingState::Confirming
    });
    record(&mut errors, a.core().accept_pairing("00".repeat(32)));
    a.core().cancel_pairing();
    let codes = [shown.as_str(), "98761234", "87654321"];
    for error in &errors {
        assert_clean("error", &format!("{error} {error:?}"), &codes);
    }
    for node in [&a, &b] {
        assert_clean("log", &node.fakes.log.lines().join("\n"), &codes);
        for plain in node.fakes.sealer.plaintexts() {
            assert_clean("sealed", &String::from_utf8_lossy(&plain), &codes);
        }
        for (path, is_dir, _) in tree(node.dir.path()) {
            if !is_dir {
                let text = fs::read(node.dir.path().join(&path)).unwrap_or_default();
                assert_clean(&path, &String::from_utf8_lossy(&text), &codes);
            }
        }
    }
    a.core().shutdown();
    b.core().shutdown();
}

// --- T114 (US5): sync and conflict records carry no secret ------------------------------------

#[test]
fn sync_status_conflict_views_and_sync_records_carry_no_password() {
    let _guard = common::serial();
    let wallet = "Shared";
    let (a, b) = common::synced_pair("leak-sync", wallet);
    let id = a.core().search(wallet.into(), "First".into()).unwrap()[0]
        .id
        .clone();
    common::background(&a);
    common::background(&b);
    let input = |pw: &str| CredentialInput {
        title: TITLE.into(),
        username: USERNAME.into(),
        url: URL.into(),
        notes: NOTES.into(),
        password: Some(bytes(pw)),
    };
    a.core()
        .update_credential(wallet.into(), id.clone(), input(PASSWORD))
        .unwrap();
    b.core()
        .update_credential(wallet.into(), id.clone(), input(NEW_PASSWORD))
        .unwrap();
    a.core().on_foreground();
    b.core().on_foreground();
    assert!(common::wait_for(Duration::from_secs(20), || a
        .core()
        .conflicts(wallet.into())
        .is_ok_and(|c| c.len() == 1)));
    // Every remaining operation once, errors recorded (SC-003 coverage, T126).
    let mut errors = Vec::new();
    let core = a.core();
    let peer = b.id();
    record(
        &mut errors,
        core.reveal_conflict_password(wallet.into(), id.clone(), 0)
            .map(drop),
    );
    record(
        &mut errors,
        core.copy_conflict_field(wallet.into(), id.clone(), 1, CopyField::Password),
    );
    let _ = core.clipboard_pending_ms();
    record(&mut errors, core.sync_now());
    record(
        &mut errors,
        core.open_pending_with_password(wallet.into(), peer.clone(), bytes(MASTER)),
    );
    record(
        &mut errors,
        core.resolve_password_choice(
            wallet.into(),
            peer.clone(),
            passwsync_ffi::records::PasswordChoiceKind::Copy,
            bytes(NEW_MASTER),
        ),
    );
    let _ = core.run_sync_window();
    let _ = core.background_plan();
    let _ = core.multicast_wanted();
    core.set_eligible_interfaces(vec!["lo".into()]);
    record(&mut errors, core.set_networking(true, true));
    core.reject_pairing();
    core.cancel_invitation();
    record(&mut errors, core.discard_received(CODE.into()));
    let views = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        a.core().sync_status(),
        a.core().conflicts(wallet.into()).unwrap(),
        a.core()
            .conflict_versions(wallet.into(), id.clone())
            .unwrap(),
        a.core().pending_copies(wallet.into()).unwrap(),
        a.core().list_wallets().unwrap(),
    );
    assert_clean("views", &views, &[PASSWORD, NEW_PASSWORD, common::PASSWORD]);
    record(
        &mut errors,
        a.core().resolve_conflict(
            wallet.into(),
            id.clone(),
            passwsync_ffi::records::ConflictChoice::Both,
        ),
    );
    record(&mut errors, a.core().lock_wallet(wallet.into()));
    let _ = a.core().on_background();
    a.core().on_foreground();
    record(&mut errors, a.core().revoke_device(peer));
    record(&mut errors, a.core().reset_identity());
    for error in &errors {
        assert_clean("error", &format!("{error} {error:?}"), &SECRETS);
        assert_clean("error", &format!("{error} {error:?}"), &[common::PASSWORD]);
    }
    for node in [&a, &b] {
        assert_clean(
            "log",
            &node.fakes.log.lines().join("\n"),
            &[
                PASSWORD,
                NEW_PASSWORD,
                NOTES,
                USERNAME,
                TITLE,
                common::PASSWORD,
            ],
        );
        for (path, is_dir, _) in tree(&node.dir.path().join("sync")) {
            if !is_dir {
                let text = fs::read(node.dir.path().join("sync").join(&path)).unwrap();
                assert_clean(&path, &String::from_utf8_lossy(&text), &SECRETS);
                assert_clean(&path, &String::from_utf8_lossy(&text), &VISIBLE);
            }
        }
    }
    a.core().shutdown();
    b.core().shutdown();
}

// --- T120 (US6): invite codes and shared-wallet secrets -------------------------------------

#[test]
fn invite_codes_and_wallet_passwords_never_leak_through_sharing() {
    let _guard = common::serial();
    let wallet = "MARKER-wallet-name";
    let (a, b) = common::two_nodes("leak-share");
    common::pair(&a, &b);
    assert!(common::wait_for(Duration::from_secs(8), || {
        common::connected(&a, &b)
    }));
    a.core()
        .create_wallet(wallet.into(), bytes(MASTER), bytes(MASTER))
        .unwrap();
    let mut errors = Vec::new();
    let view = a.core().create_invitation(wallet.into(), b.id()).unwrap();
    let code = view.code.clone();
    record(
        &mut errors,
        b.core().redeem_invitation(a.id(), bytes("1234")),
    );
    b.core().redeem_invitation(a.id(), bytes(&code)).unwrap();
    assert!(common::wait_for(Duration::from_secs(20), || a
        .core()
        .invitation()
        .is_some_and(|i| {
            i.state == passwsync_ffi::records::InvitationState::AwaitingAcceptance
        })));
    a.core().accept_recipient(b.id()).unwrap();
    assert!(common::wait_for(Duration::from_secs(20), || b
        .core()
        .received()
        .len()
        == 1));
    let id = b.core().received()[0].id.clone();
    record(
        &mut errors,
        b.core()
            .open_received(id.clone(), wallet.into(), bytes(NEW_MASTER)),
    );
    record(
        &mut errors,
        b.core()
            .open_received("zz".into(), wallet.into(), bytes(MASTER)),
    );
    b.core()
        .open_received(id, wallet.into(), bytes(MASTER))
        .unwrap();
    record(&mut errors, a.core().accept_recipient(b.id()));
    let markers = [code.as_str(), MASTER, NEW_MASTER];
    for error in &errors {
        assert_clean("error", &format!("{error} {error:?}"), &markers);
        assert_clean("error", &format!("{error} {error:?}"), &[wallet]);
    }
    for node in [&a, &b] {
        assert_clean("log", &node.fakes.log.lines().join("\n"), &markers);
        for plain in node.fakes.sealer.plaintexts() {
            let text = String::from_utf8_lossy(&plain);
            assert_clean("sealed", &text, &markers);
            assert_clean("sealed", &text, &[wallet]);
        }
        for (path, is_dir, _) in tree(node.dir.path()) {
            if !is_dir {
                let text = fs::read(node.dir.path().join(&path)).unwrap_or_default();
                let text = String::from_utf8_lossy(&text);
                assert_clean(&path, &text, &markers);
                if path.starts_with("received") {
                    assert_clean(&path, &text, &[wallet]);
                }
            }
        }
    }
    a.core().shutdown();
    b.core().shutdown();
}

// --- T126: every exported operation is driven by this file at least once --------------------

#[test]
fn every_exported_operation_is_exercised_here() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let inventory = fs::read_to_string(root.join("tests/api_inventory.txt")).unwrap();
    let source = fs::read_to_string(root.join("tests/leakage.rs")).unwrap();
    let mut missing = Vec::new();
    let mut covered = Vec::new();
    for line in inventory
        .lines()
        .filter(|l| l.starts_with("PasswsyncCore::"))
    {
        let method = &line["PasswsyncCore::".len()..];
        // `start` is the constructor every test calls through the fakes.
        if method == "start" || source.contains(&format!(".{method}(")) {
            covered.push(method);
        } else {
            missing.push(method);
        }
    }
    println!(
        "SC-003 coverage: {} operations: {}",
        covered.len(),
        covered.join(", ")
    );
    assert!(
        missing.is_empty(),
        "not exercised by leakage.rs: {missing:?}"
    );
}
