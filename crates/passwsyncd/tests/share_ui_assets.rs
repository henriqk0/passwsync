//! 005 T039: static checks of the sharing UI (contracts/http-api-share.md "UI", FR-026).
//! Behaviour in a real browser is the manual quickstart (T046).

use passwsyncd::assets::{self, APP_CSS, APP_JS, INDEX_HTML};

fn html() -> String {
    String::from_utf8(INDEX_HTML.to_vec()).unwrap()
}

fn js() -> String {
    String::from_utf8(APP_JS.to_vec()).unwrap()
}

fn has_id(html: &str, id: &str) -> bool {
    html.contains(&format!("id=\"{id}\""))
}

/// Body of `function name(` (up to the next top-level function).
fn function<'a>(js: &'a str, name: &str) -> &'a str {
    let start = js
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name}"));
    let rest = &js[start..];
    let end = rest[1..].find("\nfunction ").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn share_dialog_invitation_panel_and_acceptance_prompt_exist() {
    let html = html();
    for id in [
        "share-wallet",
        "share-dialog",
        "share-device-list",
        "share-panel",
        "share-state",
        "share-code",
        "share-qr",
        "share-countdown",
        "share-cancel",
        "share-decision",
        "share-decision-text",
        "share-accept",
        "share-reject",
    ] {
        assert!(has_id(&html, id), "{id}");
    }
    for id in [
        "share-wallet",
        "share-cancel",
        "share-accept",
        "share-reject",
    ] {
        assert!(
            html.contains(&format!("<button id=\"{id}\" type=\"button\"")),
            "{id} is a real button"
        );
    }
    let js = js();
    for needle in [
        "\"/share\"",
        "\"/api/share/accept\"",
        "Send wallet '",
        "this device does not support sharing",
        "renderQr($(\"share-qr\")",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
    // The prompt names the device and its fingerprint.
    let prompt = function(&js, "renderInvitation");
    assert!(prompt.contains("recipient.name") && prompt.contains("recipient.fingerprint"));
    // The code is shown in groups (the server sends "1234 5678").
    assert!(prompt.contains("inv.code"));
}

#[test]
fn receive_form_and_received_list_exist() {
    let html = html();
    for id in [
        "receive-heading",
        "receive-form",
        "receive-sender",
        "receive-address",
        "receive-code",
        "receive-cancel",
        "receive-state",
        "received-list",
    ] {
        assert!(has_id(&html, id), "{id}");
    }
    assert!(html.contains("Receive a wallet"));
    assert!(html.contains("Received wallets"));
    for id in ["receive-sender", "receive-address", "receive-code"] {
        assert!(html.contains(&format!("for=\"{id}\"")), "label for {id}");
    }
    let js = js();
    for needle in [
        "\"/api/receive\"",
        "\"/api/received/\"",
        "\"/open\"",
        "button(\"Open\"",
        "Shared wallet ",
        "type = \"password\"",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
}

#[test]
fn polling_is_5_seconds_and_1_second_while_active() {
    let js = js();
    assert!(js.contains("const SHARE_POLL_MS = 5000;"));
    assert!(js.contains("const SHARE_FAST_POLL_MS = 1000;"));
    assert!(js.contains("\"GET\", \"/api/share\""));
    let delay = function(&js, "sharePollDelay");
    assert!(delay.contains("SHARE_FAST_POLL_MS") && delay.contains("SHARE_POLL_MS"));
}

#[test]
fn share_and_receive_are_disabled_with_the_reason_when_unavailable() {
    let js = js();
    let render = function(&js, "renderShare");
    assert!(render.contains("data.available"));
    assert!(render.contains("$(\"share-wallet\").disabled"));
    assert!(render.contains("receive-form"));
    for reason in ["networking_off", "network_unavailable", "received_unusable"] {
        assert!(js.contains(reason), "{reason}");
    }
}

#[test]
fn qr_uses_dom_apis_no_new_assets_and_no_html_injection() {
    let js = js();
    assert!(!js.contains("innerHTML") && !js.contains("outerHTML"));
    assert!(!js.contains("insertAdjacentHTML"));
    assert!(js.contains("createElementNS(SVG_NS, \"svg\")"));
    // No new asset files: the embedded set is unchanged.
    let names: Vec<&str> = assets::ALL.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "index.html",
            "app.js",
            "app.css",
            "icon.svg",
            "instructions.html",
            "launch-invalid.html"
        ]
    );
    assert!(assets::static_asset("/static/share.js").is_none());
    // CSP unchanged.
    assert_eq!(
        passwsyncd::http::response::CSP,
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    );
    let css = String::from_utf8(APP_CSS.to_vec()).unwrap();
    assert!(css.contains(".qr"));
}

// --- 005 T073 (US4): consent and cancellation controls ---

#[test]
fn cancel_reject_and_cancel_while_waiting_are_wired() {
    let js = js();
    for needle in [
        "\"/api/share/cancel\"",
        "\"/api/share/reject\"",
        "\"/api/receive/cancel\"",
        "$(\"share-cancel\")",
        "$(\"share-reject\")",
        "$(\"receive-cancel\")",
    ] {
        assert!(js.contains(needle), "{needle}");
    }
}

#[test]
fn discard_asks_for_confirmation_and_shows_the_time_left() {
    let js = js();
    let received = function(&js, "renderReceived");
    assert!(received.contains("button(\"Discard\""));
    assert!(received.contains("expires_at"));
    assert!(js.contains("deleted automatically in"));
    let discard = function(&js, "discardReceived");
    assert!(discard.contains("window.confirm("));
    assert!(discard.contains("\"/discard\""));
}

#[test]
fn notices_are_shown_with_dismiss() {
    let html = html();
    assert!(has_id(&html, "share-notices"));
    let js = js();
    let notices = function(&js, "renderShareNotices");
    assert!(notices.contains("button(\"Dismiss\""));
    assert!(js.contains("\"/api/share/notices/dismiss\""));
    for kind in [
        "received_expired",
        "received_deleted_revoked",
        "received_cleaned",
        "already_present",
    ] {
        assert!(js.contains(kind), "{kind}");
    }
}

#[test]
fn cancel_after_completion_explains_what_cannot_be_undone() {
    let js = js();
    assert!(js.contains("the encrypted copy already reached \" + "));
    assert!(js.contains("to stop access, revoke the device and change the master password"));
    assert!(js.contains("already_delivered"));
}
