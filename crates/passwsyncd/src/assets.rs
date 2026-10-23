//! The web UI, embedded at build time. No external references (FR-012).

pub const INDEX_HTML: &[u8] = include_bytes!("../ui/index.html");
pub const APP_JS: &[u8] = include_bytes!("../ui/app.js");
pub const APP_CSS: &[u8] = include_bytes!("../ui/app.css");
pub const ICON_SVG: &[u8] = include_bytes!("../ui/icon.svg");

/// Placeholder in `index.html` replaced by the session's CSRF token (hex only).
pub const CSRF_PLACEHOLDER: &str = "{{CSRF_TOKEN}}";

pub const INSTRUCTIONS_HTML: &[u8] = b"<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>passwsync</title>
<link rel=\"icon\" href=\"/static/icon.svg\" type=\"image/svg+xml\">
<link rel=\"stylesheet\" href=\"/static/app.css\"></head>
<body><main class=\"notice\"><h1>passwsync</h1>
<p>Open the launch address to use this service. It is in the file
<code>$XDG_RUNTIME_DIR/passwsync/launch-url</code>, for example:</p>
<pre>xdg-open \"$(cat \"$XDG_RUNTIME_DIR/passwsync/launch-url\")\"</pre>
</main></body></html>
";

pub const LAUNCH_INVALID_HTML: &[u8] = b"<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>passwsync</title>
<link rel=\"icon\" href=\"/static/icon.svg\" type=\"image/svg+xml\">
<link rel=\"stylesheet\" href=\"/static/app.css\"></head>
<body><main class=\"notice\"><h1>passwsync</h1>
<p>This launch address is no longer valid; open the current one from the launch file
(<code>$XDG_RUNTIME_DIR/passwsync/launch-url</code>).</p>
</main></body></html>
";

/// Every embedded file, for scans.
pub const ALL: &[(&str, &[u8])] = &[
    ("index.html", INDEX_HTML),
    ("app.js", APP_JS),
    ("app.css", APP_CSS),
    ("icon.svg", ICON_SVG),
    ("instructions.html", INSTRUCTIONS_HTML),
    ("launch-invalid.html", LAUNCH_INVALID_HTML),
];

/// `/static/<name>` assets: (content type, bytes).
pub fn static_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    match path {
        "/static/app.js" => Some(("text/javascript; charset=utf-8", APP_JS)),
        "/static/app.css" => Some(("text/css; charset=utf-8", APP_CSS)),
        "/static/icon.svg" => Some(("image/svg+xml", ICON_SVG)),
        _ => None,
    }
}
