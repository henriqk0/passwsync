//! 004 UI asset checks (T078 conflicts, T090 pending prompts, T109 warnings, T119 status).
//! Static checks of the embedded UI; behaviour in a browser is a manual quickstart scenario.

use passwsyncd::assets::{APP_JS, INDEX_HTML};

fn html() -> String {
    String::from_utf8(INDEX_HTML.to_vec()).unwrap()
}

fn js() -> String {
    String::from_utf8(APP_JS.to_vec()).unwrap()
}

fn has_id(html: &str, id: &str) -> bool {
    html.contains(&format!("id=\"{id}\""))
}

#[test]
fn conflict_list_and_view_are_present_and_keyboard_operable() {
    let html = html();
    for id in [
        "conflicts-section",
        "conflict-list",
        "conflict-view",
        "conflict-versions",
    ] {
        assert!(has_id(&html, id), "{id}");
    }
    let js = js();
    for needle in [
        "\"/conflicts\"",
        "\"/resolve\"",
        "keep: \"both\"",
        "Keep this version",
        "Keep both",
        "conflicted",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
    // Actions are real buttons (focusable, Enter/Space) built with the shared helper.
    assert!(js.contains("button(\"Keep this version\""));
    assert!(js.contains("button(\"Keep both\""));
}

#[test]
fn conflict_passwords_are_masked_until_revealed() {
    let js = js();
    // The view route returns no password; a version's password comes only from the
    // explicit reveal / copy action (002 rules).
    assert!(js.contains("\"/field\""));
    assert!(js.contains("Reveal password"));
    assert!(!js.contains("innerHTML"), "DOM built with textContent only");
}

#[test]
fn pending_copy_prompts_are_present() {
    let html = html();
    assert!(has_id(&html, "sync-pending-list"));
    let js = js();
    for needle in [
        "changes waiting: unlock to merge",
        "cannot open: different master password or corrupted",
        "password changed on two devices",
        "\"/sync/pending/\"",
        "\"/open\"",
        "\"/choose-password\"",
        "\"/discard\"",
        "button(\"Discard\"",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
}

#[test]
fn warnings_and_recovery_actions_need_confirmation() {
    let html = html();
    assert!(has_id(&html, "sync-warnings"));
    let js = js();
    for needle in [
        "\"/api/sync/warnings/dismiss\"",
        "Accept this older state",
        "Reset sync state",
        "\"/sync/accept-older\"",
        "\"/sync/reset\"",
        "confirm: true",
        "window.confirm(",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
}

#[test]
fn status_details_last_rounds_and_sync_now() {
    let html = html();
    for id in [
        "wallet-sync-state",
        "sync-details",
        "sync-peer-list",
        "sync-now-all",
        "sync-now-wallet",
        "sync-device-list",
    ] {
        assert!(has_id(&html, id), "{id}");
    }
    let js = js();
    for needle in [
        "\"/api/sync\"",
        "\"/api/sync/now\"",
        "sync unsupported by peer",
        "in sync",
        "not synced",
        "possible rollback",
        "sync off (networking disabled)",
        "Last synced",
        "syncPoll",
        "document.visibilityState === \"hidden\"",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
    // Buttons, not clickable divs: keyboard operable.
    assert!(html.contains("<button id=\"sync-now-all\" type=\"button\""));
    assert!(html.contains("<button id=\"sync-now-wallet\" type=\"button\""));
}
