//! Static checks of the embedded UI (FR-011, FR-031b). Behaviour in a real browser is
//! covered by the manual quickstart scenarios.

use passwsyncd::assets::{APP_CSS, APP_JS, INDEX_HTML};

fn html() -> String {
    String::from_utf8(INDEX_HTML.to_vec()).unwrap()
}

fn js() -> String {
    String::from_utf8(APP_JS.to_vec()).unwrap()
}

fn css() -> String {
    String::from_utf8(APP_CSS.to_vec()).unwrap()
}

/// Every `<input`, `<textarea` and `<select` has an id with a matching `<label for=...>`
/// or an aria-label.
fn assert_inputs_labelled(html: &str) {
    for tag in ["<input", "<textarea", "<select"] {
        for (pos, _) in html.match_indices(tag) {
            let end = html[pos..].find('>').unwrap() + pos;
            let element = &html[pos..end];
            if element.contains("type=\"hidden\"") || element.contains("aria-label=") {
                continue;
            }
            let id_start = element
                .find(" id=\"")
                .unwrap_or_else(|| panic!("no id: {element}"))
                + 5;
            let id = &element[id_start..id_start + element[id_start..].find('"').unwrap()];
            assert!(html.contains(&format!("for=\"{id}\"")), "no label for {id}");
        }
    }
}

#[test]
fn no_inline_script_or_style_anywhere() {
    let html = html();
    for (pos, _) in html.match_indices("<script") {
        let end = html[pos..].find('>').unwrap() + pos;
        assert!(
            html[pos..end].contains("src=\"/static/app.js\""),
            "inline script"
        );
    }
    assert!(!html.contains("<style"));
    assert!(!html.contains(" style="));
    let lower = html.to_ascii_lowercase();
    for handler in [
        " onclick=",
        " onload=",
        " onsubmit=",
        " oninput=",
        " onchange=",
        "javascript:",
    ] {
        assert!(!lower.contains(handler), "{handler}");
    }
    assert!(!js().contains("eval("));
    assert!(!js().contains("new Function"));
    assert!(
        !js().contains("innerHTML"),
        "build DOM with textContent only"
    );
}

#[test]
fn create_wallet_form_wallet_list_and_add_credential_form_exist() {
    let html = html();
    for id in [
        "create-wallet-form",
        "create-name",
        "create-password",
        "create-password-confirm",
        "wallet-list",
        "add-entry-form",
        "entry-title",
        "entry-username",
        "entry-password",
        "entry-url",
        "entry-notes",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    assert!(html.contains("id=\"create-password\" type=\"password\""));
    assert!(html.contains("id=\"create-password-confirm\" type=\"password\""));
    assert!(html.contains("id=\"entry-password\" type=\"password\""));
    assert_inputs_labelled(&html);
    let js = js();
    assert!(js.contains("\"/api/wallets\""));
    assert!(js.contains("X-CSRF-Token"));
    assert!(js.contains("csrf-token"));
}

#[test]
fn keyboard_focus_is_visible() {
    assert!(css().contains(":focus-visible"));
    assert!(!css().contains("outline: none") && !css().contains("outline:none"));
}

#[test]
fn unlock_prompt_only_for_locked_wallets() {
    let html = html();
    for id in ["unlock-form", "unlock-password"] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    assert!(html.contains("id=\"unlock-password\" type=\"password\""));
    assert_inputs_labelled(&html);
    let js = js();
    assert!(js.contains("\"/unlock\""));
    // The unlock form is hidden for unlocked wallets and shown for locked ones.
    assert!(js.contains("$(\"unlock-form\").hidden = wallet.unlocked"));
}

#[test]
fn state_is_polled_every_5_seconds_in_the_background() {
    let js = js();
    assert!(js.contains("const POLL_MS = 5000;"));
    assert!(js.contains("setInterval(poll, POLL_MS)"));
    assert!(js.contains("\"GET\", \"/api/state\""));
}

/// A server-side auto-lock or suspend lock must clear the clipboard within seconds, not at
/// the next 5 s poll (FR-027 "immediately when the wallet is locked").
#[test]
fn state_is_polled_faster_while_a_copied_value_is_pending() {
    let js = js();
    assert!(js.contains("const FAST_POLL_MS = 1000;"));
    assert!(js.contains("setInterval(fastPoll, FAST_POLL_MS)"));
    let fast = function(&js, "fastPoll");
    assert!(fast.contains("clip.value") && fast.contains("poll()"));
    // The clipboard is cleared when the wallet it was copied from locks, selected or not.
    let refresh = function(&js, "refreshState");
    assert!(refresh.contains("clip.wallet") && refresh.contains("clearClipboard(\"lock\")"));
    assert!(function(&js, "copyField").contains("clip.wallet = wallet"));
}

/// The background poll must not rebuild unchanged lists: a rebuild would drop keyboard
/// focus from a list button every poll tick (FR-031b), every second while a copied value
/// is pending clearance (FR-027 countdown).
#[test]
fn unchanged_lists_are_not_rebuilt_by_the_poll() {
    let js = js();
    for (name, key) in [
        ("renderWallets", "ui.walletsKey"),
        ("renderEntries", "ui.entriesKey"),
    ] {
        let body = function(&js, name);
        let guard = body
            .find(&format!("=== {key}) return;"))
            .unwrap_or_else(|| panic!("{name} must skip the rebuild when {key} is unchanged"));
        let rebuild = body
            .find("replaceChildren()")
            .unwrap_or_else(|| panic!("{name}"));
        assert!(
            guard < rebuild,
            "{name}: guard must come before the rebuild"
        );
        assert!(
            body.contains(&format!("{key} = ")),
            "{name} must remember the rendered data"
        );
    }
    // The key covers everything the list shows, so a real change still re-renders.
    let wallets = function(&js, "renderWallets");
    for part in ["ui.selected", "w.name", "w.unlocked"] {
        assert!(wallets.contains(part), "wallet key misses {part}");
    }
    let entries = function(&js, "renderEntries");
    for part in ["e.id", "e.title", "e.username"] {
        assert!(entries.contains(part), "entry key misses {part}");
    }
    // The poll itself still goes through the render path.
    assert!(function(&js, "refreshState").contains("render()"));
}

#[test]
fn edit_form_delete_confirmation_and_search_box() {
    let html = html();
    for id in [
        "search-form",
        "search-query",
        "entry-list",
        "entry-details",
        "edit-entry-form",
        "edit-title",
        "edit-username",
        "edit-password",
        "edit-url",
        "edit-notes",
        "delete-entry",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    assert!(html.contains("id=\"search-query\" type=\"search\""));
    assert_inputs_labelled(&html);
    let js = js();
    assert!(js.contains("\"/search\""));
    assert!(js.contains("\"PUT\""));
    assert!(js.contains("\"DELETE\""));
    assert!(
        js.contains("window.confirm("),
        "deleting asks for confirmation"
    );
}

/// Body of the `$("<id>").addEventListener(...)` handler.
fn handler<'a>(js: &'a str, id: &str) -> &'a str {
    let start = js
        .find(&format!("$(\"{id}\").addEventListener"))
        .unwrap_or_else(|| panic!("{id}"));
    js[start..].split("\n});\n").next().unwrap()
}

fn function<'a>(js: &'a str, name: &str) -> &'a str {
    let start = js
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("{name}"));
    js[start..].split("\n}\n").next().unwrap()
}

#[test]
fn editing_never_fetches_the_stored_password() {
    let js = js();
    let edit = handler(&js, "edit-entry-form");
    assert!(
        !edit.contains("/field"),
        "the edit form must not fetch the password (FR-024)"
    );
    assert!(edit.contains("keep_password"));
}

#[test]
fn opening_another_credential_or_saving_an_edit_hides_the_revealed_password() {
    let js = js();
    assert!(
        function(&js, "showEntry").contains("hideRevealed()"),
        "showEntry must hide a revealed password (FR-027a)"
    );
    let edit = handler(&js, "edit-entry-form");
    assert!(
        edit.contains("hideRevealed()"),
        "saving an edit must hide a revealed password"
    );
}

#[test]
fn copy_reveal_countdown_and_clipboard_clearing() {
    let html = html();
    for id in [
        "reveal-password",
        "copy-password",
        "copy-username",
        "revealed-password",
        "clipboard-countdown",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    assert!(
        html.contains("only while this page stays open"),
        "copy notice"
    );
    let js = js();
    assert!(js.contains("ui.settings.clipboard_clear_seconds"));
    assert!(js.contains("navigator.clipboard.writeText"));
    assert!(js.contains("navigator.clipboard.readText"));
    assert!(js.contains("\"/field\""));
    // Cleared on timeout, on lock and when the page is hidden.
    assert!(js.contains("function clearClipboard("));
    assert!(js.contains("addEventListener(\"pagehide\""));
    assert!(js.contains("addEventListener(\"visibilitychange\""));
    assert!(js.contains("function onWalletLocked("));
    // Revealed passwords hide after the timeout, on lock and on leaving the view.
    assert!(js.contains("function hideRevealed("));
    let close = js.find("function closeDetails(").unwrap();
    assert!(
        js[close..]
            .split("\n}\n")
            .next()
            .unwrap()
            .contains("hideRevealed()")
    );
    let locked = js.find("function onWalletLocked(").unwrap();
    let body = js[locked..].split("\n}\n").next().unwrap();
    assert!(body.contains("clearClipboard(") && body.contains("hideRevealed()"));
}

#[test]
fn lock_controls_and_locked_rendering() {
    let html = html();
    for id in ["lock-wallet", "lock-all"] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    let js = js();
    assert!(js.contains("\"/lock\""));
    assert!(js.contains("\"/api/lock-all\""));
    // Locking clears the clipboard and hides secrets at once.
    for handler in [
        "$(\"lock-wallet\").addEventListener",
        "$(\"lock-all\").addEventListener",
    ] {
        let start = js.find(handler).unwrap_or_else(|| panic!("{handler}"));
        let body = js[start..].split("\n});\n").next().unwrap();
        assert!(body.contains("onWalletLocked()"), "{handler}");
    }
    assert!(js.contains("$(\"lock-wallet\").hidden = !wallet.unlocked"));
}
