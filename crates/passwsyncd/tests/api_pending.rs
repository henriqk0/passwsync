//! 004 T089: pending-copy routes (contracts/http-api-sync.md): open with a password,
//! choose a password after concurrent changes, discard.

mod common;

use std::fs;

use common::server::{Fixture, Session, TestServer, net_config};
use common::sync::{PASSWORD, place_wallet};
use vault_core::testkit::fork;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
use wallet_sync::ports::PeerId;
use wallet_sync::record::{PendingCopy, PendingStatus, decode, encode};

const NEW: &str = "PHONE-PASSWORD-MARKER-123";
const LOCAL: &str = "LOCAL-PASSWORD-MARKER-456";
const PEER: PeerId = PeerId([0x42; 32]);

fn titled(t: &str) -> EntryFields {
    let mut f = EntryFields::default();
    f.title = t.into();
    f
}

struct Setup {
    server: TestServer,
    s: Session,
    wallet_dir: std::path::PathBuf,
}

/// `local_password`: the wallet's password on this device; the pending copy was changed to
/// `NEW` on the phone (and holds "From phone").
fn setup(local_changed: bool) -> Setup {
    let base = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        DeviceId::new("origin").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    let mut local = fork(&base, "laptop", 2);
    if local_changed {
        local
            .change_master_password(MasterPassword::new(LOCAL.into()))
            .unwrap();
    }
    let mut phone = fork(&base, "phone", 3);
    phone
        .change_master_password(MasterPassword::new(NEW.into()))
        .unwrap();
    phone.add_entry(titled("From phone")).unwrap();
    let fx = Fixture::new(&net_config());
    place_wallet(&fx, "Personal", &local.seal().unwrap());
    let server = TestServer::start_in(fx);
    let s = server.login();
    let password = if local_changed { LOCAL } else { PASSWORD };
    let body = format!(r#"{{"password":"{password}"}}"#);
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Personal/unlock", Some(&body))
            .status,
        200
    );
    // The record exists now (written at unlock); add the pending copy and its line.
    let sync = server.fx.home.join(".local/share/passwsync/sync");
    let wallet_dir = fs::read_dir(&sync).unwrap().next().unwrap().unwrap().path();
    let pending = wallet_dir.join(format!("pending-{}", PEER.to_hex()));
    fs::write(&pending, phone.seal().unwrap()).unwrap();
    common::set_mode(&pending, 0o600);
    let path = wallet_dir.join("record");
    let mut record = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    record.pending.insert(
        PEER,
        PendingCopy {
            claimed: phone.state().clone(),
            size: 1,
            received_at: 1,
            status: PendingStatus::CannotOpen,
        },
    );
    fs::write(&path, encode(&record)).unwrap();
    Setup {
        server,
        s,
        wallet_dir,
    }
}

fn route(action: &str) -> String {
    format!(
        "/api/wallets/Personal/sync/pending/{}/{action}",
        PEER.to_hex()
    )
}

fn titles(st: &Setup) -> usize {
    st.server
        .api(
            &st.s,
            "POST",
            "/api/wallets/Personal/search",
            Some(r#"{"query":""}"#),
        )
        .json()["entries"]
        .as_array()
        .unwrap()
        .len()
}

#[test]
fn opening_with_the_copys_password_merges_it() {
    let st = setup(false);
    let wrong = st.server.api(
        &st.s,
        "POST",
        &route("open"),
        Some(r#"{"password":"WRONG-PASSWORD-MARKER"}"#),
    );
    assert_eq!(wrong.status, 422);
    assert_eq!(wrong.error_code(), "invalid_password_or_corrupted");
    assert!(
        st.wallet_dir
            .join(format!("pending-{}", PEER.to_hex()))
            .exists()
    );
    let ok = st.server.api(
        &st.s,
        "POST",
        &route("open"),
        Some(&format!(r#"{{"password":"{NEW}"}}"#)),
    );
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(ok.json()["merged"], true);
    assert_eq!(titles(&st), 1);
    assert!(
        !st.wallet_dir
            .join(format!("pending-{}", PEER.to_hex()))
            .exists()
    );
    for text in [st.server.log_text(), ok.text(), wrong.text()] {
        assert!(!text.contains(NEW) && !text.contains("WRONG-PASSWORD-MARKER"));
    }
}

#[test]
fn concurrent_password_changes_are_resolved_by_choosing() {
    let st = setup(true);
    let conflict = st.server.api(
        &st.s,
        "POST",
        &route("open"),
        Some(&format!(r#"{{"password":"{NEW}"}}"#)),
    );
    assert_eq!(conflict.status, 409);
    assert_eq!(conflict.error_code(), "password_conflict");
    let wrong = st.server.api(
        &st.s,
        "POST",
        &route("choose-password"),
        Some(r#"{"keep":"local","password":"WRONG-PASSWORD-MARKER"}"#),
    );
    assert_eq!(wrong.status, 422);
    assert_eq!(
        st.server
            .api(
                &st.s,
                "POST",
                &route("choose-password"),
                Some(r#"{"keep":"mine","password":"x"}"#)
            )
            .status,
        400
    );
    let ok = st.server.api(
        &st.s,
        "POST",
        &route("choose-password"),
        Some(&format!(r#"{{"keep":"local","password":"{NEW}"}}"#)),
    );
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(titles(&st), 1);
    assert!(!st.server.log_text().contains(NEW) && !st.server.log_text().contains(LOCAL));
}

#[test]
fn discarding_deletes_the_copy() {
    let st = setup(false);
    let resp = st.server.api(&st.s, "POST", &route("discard"), None);
    assert_eq!(resp.status, 200);
    assert!(
        !st.wallet_dir
            .join(format!("pending-{}", PEER.to_hex()))
            .exists()
    );
    let record = fs::read_to_string(st.wallet_dir.join("record")).unwrap();
    assert!(!record.contains(&format!("pending {}", PEER.to_hex())));
}

#[test]
fn locked_wallets_bad_peers_and_protections() {
    let st = setup(false);
    assert_eq!(
        st.server
            .api(
                &st.s,
                "POST",
                "/api/wallets/Personal/sync/pending/zz/open",
                Some("{}")
            )
            .status,
        404
    );
    assert_eq!(
        st.server
            .api(&st.s, "POST", "/api/wallets/Personal/lock", None)
            .status,
        200
    );
    let resp = st.server.api(
        &st.s,
        "POST",
        &route("open"),
        Some(&format!(r#"{{"password":"{NEW}"}}"#)),
    );
    assert_eq!(resp.status, 423);
    let cookie = format!("pws_session={}", st.s.cookie);
    for action in ["open", "choose-password", "discard"] {
        let path = route(action);
        assert_eq!(st.server.send("POST", &path, &[], b"{}").status, 401);
        assert_eq!(
            st.server
                .send(
                    "POST",
                    &path,
                    &[("Cookie", &cookie), ("X-CSRF-Token", &st.s.csrf)],
                    b"{}"
                )
                .status,
            403,
            "Origin required"
        );
        assert_eq!(st.server.api(&st.s, "GET", &path, None).status, 405);
    }
}
