"use strict";
// passwsync web UI. No framework, no external code. DOM is built with textContent only.

const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
const $ = (id) => document.getElementById(id);
const POLL_MS = 5000;
// While a copied value awaits clearance, poll faster so a server-side lock clears it soon.
const FAST_POLL_MS = 1000;

const ui = {
  wallets: [],
  settings: null,
  selected: null,
  entries: [],
  current: null, // id of the credential shown in the details view
  // What each list last rendered. The poll skips an unchanged rebuild so a focused list
  // button keeps keyboard focus (FR-031b).
  walletsKey: null,
  entriesKey: null,
};

// Clipboard and reveal state. Secret values live only in these variables and are
// overwritten with "" as soon as they are no longer needed.
const clip = { value: "", wallet: null, timer: null, tick: null, deadline: 0, retry: false };
const reveal = { value: "", timer: null };

function clearSeconds() {
  return ui.settings ? ui.settings.clipboard_clear_seconds : 30;
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(method, path, body) {
  const headers = { "X-CSRF-Token": csrfToken };
  const options = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    const code = data && data.error ? data.error : "http_" + response.status;
    const message = data && data.message ? data.message : "request failed (" + response.status + ")";
    throw new ApiError(response.status, code, message);
  }
  return data;
}

function walletPath(name, rest) {
  return "/api/wallets/" + encodeURIComponent(name) + (rest || "");
}

function setStatus(text, isError) {
  const status = $("status");
  status.textContent = text;
  status.classList.toggle("error", Boolean(isError));
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function button(text, onClick, className) {
  const node = element("button", text, className);
  node.type = "button";
  node.addEventListener("click", onClick);
  return node;
}

function selectedWallet() {
  return ui.wallets.find((w) => w.name === ui.selected) || null;
}

function renderWallets() {
  const key = JSON.stringify([ui.selected, ui.wallets.map((w) => [w.name, w.unlocked, w.sync])]);
  if (key === ui.walletsKey) return;
  ui.walletsKey = key;
  const list = $("wallet-list");
  list.replaceChildren();
  if (ui.wallets.length === 0) {
    list.append(element("li", "No wallets yet.", "muted"));
  }
  for (const wallet of ui.wallets) {
    const item = element("li");
    const open = button(wallet.name, () => selectWallet(wallet.name), "link");
    if (wallet.name === ui.selected) open.setAttribute("aria-current", "true");
    item.append(open, element("span", wallet.unlocked ? "unlocked" : "locked", "badge"));
    item.append(element("span", syncLabel(wallet.sync), "muted small"));
    if (wallet.sync && wallet.sync.last_synced_at) {
      item.append(element("span", "Last synced " + new Date(wallet.sync.last_synced_at * 1000).toLocaleString(), "muted small"));
    }
    list.append(item);
  }
}

function renderWalletView() {
  const view = $("wallet-view");
  const wallet = selectedWallet();
  view.hidden = wallet === null;
  if (!wallet) return;
  $("wallet-title").textContent = wallet.name;
  $("unlock-form").hidden = wallet.unlocked;
  $("lock-wallet").hidden = !wallet.unlocked;
  $("unlocked-view").hidden = !wallet.unlocked;
  if (!wallet.unlocked) {
    ui.entries = [];
    closeDetails();
  }
  renderEntries();
}

function renderEntries() {
  const unlocked = Boolean(selectedWallet() && selectedWallet().unlocked);
  const key = JSON.stringify([unlocked, ui.entries.map((e) => [e.id, e.title, e.username, e.conflicted])]);
  if (key === ui.entriesKey) return;
  ui.entriesKey = key;
  const list = $("entry-list");
  list.replaceChildren();
  for (const entry of ui.entries) {
    const item = element("li");
    const open = button(entry.title, () => showEntry(entry.id).catch(handleError), "link");
    item.append(open, element("span", entry.username, "muted"));
    if (entry.conflicted) item.append(element("span", "conflicted", "badge warn"));
    list.append(item);
  }
  if (ui.entries.length === 0 && unlocked) {
    list.append(element("li", "No credentials found.", "muted"));
  }
}

async function loadEntries() {
  const wallet = ui.selected;
  if (!wallet) return;
  const result = await api("POST", walletPath(wallet, "/search"), { query: $("search-query").value });
  if (wallet !== ui.selected) return;
  ui.entries = result.entries;
  renderEntries();
  loadConflicts().catch(handleError);
}

function closeDetails() {
  hideRevealed();
  ui.current = null;
  $("entry-details").hidden = true;
  for (const id of ["details-title", "details-username", "details-url", "details-notes", "details-modified"]) {
    $(id).textContent = "";
  }
  for (const id of ["edit-title", "edit-username", "edit-password", "edit-url", "edit-notes"]) {
    $(id).value = "";
  }
}

async function showEntry(id) {
  // Leaving the shown credential (for another one, or the same one re-read) hides a
  // revealed password at once (FR-027a).
  hideRevealed();
  const wallet = ui.selected;
  const entry = await api("GET", walletPath(wallet, "/entries/" + id));
  ui.current = entry.id;
  $("details-title").textContent = entry.title;
  $("details-username").textContent = entry.username;
  $("details-url").textContent = entry.url;
  $("details-notes").textContent = entry.notes;
  $("details-modified").textContent = new Date(entry.modified_at * 1000).toLocaleString();
  $("edit-title").value = entry.title;
  $("edit-username").value = entry.username;
  $("edit-password").value = "";
  $("edit-url").value = entry.url;
  $("edit-notes").value = entry.notes;
  $("entry-details").hidden = false;
  $("details-title").focus();
}

function render() {
  renderWallets();
  renderWalletView();
}

async function refreshState() {
  const state = await api("GET", "/api/state");
  const before = selectedWallet();
  ui.settings = state.settings;
  ui.wallets = state.wallets;
  const after = selectedWallet();
  if (before && before.unlocked && (!after || !after.unlocked)) onWalletLocked();
  // The wallet a value was copied from locked (idle, suspend, other tab), selected or not.
  const source = ui.wallets.find((w) => w.name === clip.wallet);
  if (clip.value !== "" && (!source || !source.unlocked)) clearClipboard("lock");
  if (ui.selected !== null && !selectedWallet()) ui.selected = null;
  render();
}

function selectWallet(name) {
  if (ui.selected !== name) {
    ui.entries = [];
    closeDetails();
  }
  ui.selected = name;
  render();
  loadEntries().catch(handleError);
  const wallet = selectedWallet();
  if (wallet && !wallet.unlocked) $("unlock-password").focus();
}

// Background status refresh: GET /api/state never counts as activity for auto-lock.
async function poll() {
  try {
    await refreshState();
  } catch (error) {
    report(error);
  }
}

function fastPoll() {
  if (clip.value !== "") poll();
}

function report(error) {
  setStatus(error instanceof ApiError ? error.message : "The service could not be reached.", true);
}

// A 423 means the wallet was locked meanwhile (manual, idle or suspend): re-read the state.
function handleError(error) {
  report(error);
  if (error instanceof ApiError && error.status === 423) {
    onWalletLocked();
    refreshState().catch(report);
  }
}

// The selected wallet is locked now: nothing secret may stay on screen or in the clipboard.
function onWalletLocked() {
  clearClipboard("lock");
  hideRevealed();
  ui.entries = [];
  closeDetails();
  renderEntries();
  closeConflicts();
}

function stopCountdown() {
  clearTimeout(clip.timer);
  clearInterval(clip.tick);
  clip.timer = null;
  clip.tick = null;
  $("clipboard-countdown").hidden = true;
  $("clipboard-countdown").textContent = "";
}

function showCountdown() {
  const left = Math.max(0, Math.ceil((clip.deadline - Date.now()) / 1000));
  const node = $("clipboard-countdown");
  node.hidden = false;
  node.textContent = "Clipboard will be cleared in " + left + " s.";
}

// Empties the clipboard if it still holds what we copied (or if it cannot be read).
async function clearClipboard(reason) {
  if (clip.value === "") return;
  stopCountdown();
  let cleared = false;
  try {
    const current = await navigator.clipboard.readText();
    if (current === clip.value) await navigator.clipboard.writeText("");
    cleared = true;
  } catch (_) {
    try {
      await navigator.clipboard.writeText("");
      cleared = true;
    } catch (_) {
      cleared = false;
    }
  }
  if (cleared) {
    clip.value = "";
    clip.wallet = null;
    clip.retry = false;
    if (reason !== "pagehide") setStatus("Clipboard cleared.");
  } else {
    // Browsers refuse clipboard access while the page is not focused: retry on focus.
    clip.retry = true;
  }
}

async function copyField(field) {
  const wallet = ui.selected;
  const id = ui.current;
  if (!wallet || !id) return;
  try {
    const result = await api("POST", walletPath(wallet, "/entries/" + id + "/field"), { field });
    await clearClipboard("replace");
    await navigator.clipboard.writeText(result.value);
    clip.value = result.value;
    clip.wallet = wallet;
    result.value = "";
    clip.deadline = Date.now() + clearSeconds() * 1000;
    clip.timer = setTimeout(() => clearClipboard("timeout"), clearSeconds() * 1000);
    clip.tick = setInterval(showCountdown, 1000);
    showCountdown();
    setStatus((field === "password" ? "Password" : "Username") + " copied.");
  } catch (error) {
    handleError(error);
  }
}

function hideRevealed() {
  clearTimeout(reveal.timer);
  reveal.timer = null;
  reveal.value = "";
  $("revealed-password").textContent = "";
  $("reveal-password").setAttribute("aria-pressed", "false");
  $("reveal-password").textContent = "Reveal password";
}

async function toggleReveal() {
  if (reveal.value !== "") {
    hideRevealed();
    return;
  }
  const wallet = ui.selected;
  const id = ui.current;
  try {
    const result = await api("POST", walletPath(wallet, "/entries/" + id + "/field"), { field: "password" });
    reveal.value = result.value;
    result.value = "";
    $("revealed-password").textContent = reveal.value;
    $("reveal-password").setAttribute("aria-pressed", "true");
    $("reveal-password").textContent = "Hide password";
    reveal.timer = setTimeout(hideRevealed, clearSeconds() * 1000);
  } catch (error) {
    handleError(error);
  }
}

$("create-wallet-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("create-name");
  const password = $("create-password");
  const confirm = $("create-password-confirm");
  const body = { name: name.value, password: password.value, password_confirm: confirm.value };
  password.value = "";
  confirm.value = "";
  try {
    const created = await api("POST", "/api/wallets", body);
    body.password = "";
    body.password_confirm = "";
    name.value = "";
    ui.selected = created.name;
    setStatus("Wallet " + created.name + " created.");
    await refreshState();
  } catch (error) {
    body.password = "";
    body.password_confirm = "";
    report(error);
  }
});

$("add-entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const wallet = ui.selected;
  const ids = ["entry-title", "entry-username", "entry-password", "entry-url", "entry-notes"];
  const body = {
    title: $("entry-title").value,
    username: $("entry-username").value,
    password: $("entry-password").value,
    url: $("entry-url").value,
    notes: $("entry-notes").value,
  };
  $("entry-password").value = "";
  try {
    await api("POST", walletPath(wallet, "/entries"), body);
    body.password = "";
    for (const id of ids) $(id).value = "";
    setStatus("Credential added.");
    await loadEntries();
  } catch (error) {
    body.password = "";
    handleError(error);
  }
});

$("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadEntries().catch(handleError);
});

$("edit-entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const wallet = ui.selected;
  const id = ui.current;
  const body = {
    title: $("edit-title").value,
    username: $("edit-username").value,
    password: $("edit-password").value,
    url: $("edit-url").value,
    notes: $("edit-notes").value,
  };
  // An empty password field keeps the stored password: the service merges it, so the
  // password never has to come to the page for an edit (FR-024).
  body.keep_password = body.password === "";
  $("edit-password").value = "";
  try {
    await api("PUT", walletPath(wallet, "/entries/" + id), body);
    body.password = "";
    hideRevealed();
    setStatus("Credential saved.");
    await loadEntries();
    await showEntry(id);
  } catch (error) {
    body.password = "";
    handleError(error);
  }
});

$("delete-entry").addEventListener("click", async () => {
  const wallet = ui.selected;
  const id = ui.current;
  const title = $("details-title").textContent;
  if (!window.confirm("Delete the credential \"" + title + "\"? This cannot be undone.")) return;
  try {
    await api("DELETE", walletPath(wallet, "/entries/" + id));
    closeDetails();
    setStatus("Credential deleted.");
    await loadEntries();
  } catch (error) {
    handleError(error);
  }
});

$("lock-wallet").addEventListener("click", async () => {
  const wallet = ui.selected;
  onWalletLocked();
  try {
    await api("POST", walletPath(wallet, "/lock"));
    setStatus("Wallet " + wallet + " locked.");
    await refreshState();
  } catch (error) {
    handleError(error);
  }
});

$("lock-all").addEventListener("click", async () => {
  onWalletLocked();
  try {
    const result = await api("POST", "/api/lock-all");
    setStatus(result.locked.length === 0 ? "No wallet was unlocked." : "All wallets locked.");
    await refreshState();
  } catch (error) {
    handleError(error);
  }
});

$("close-details").addEventListener("click", closeDetails);
$("copy-password").addEventListener("click", () => copyField("password"));
$("copy-username").addEventListener("click", () => copyField("username"));
$("reveal-password").addEventListener("click", toggleReveal);

window.addEventListener("pagehide", () => {
  hideRevealed();
  clearClipboard("pagehide");
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") hideRevealed();
});
window.addEventListener("focus", () => {
  if (clip.retry) clearClipboard("timeout");
});

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const wallet = ui.selected;
  const input = $("unlock-password");
  const body = { password: input.value };
  input.value = "";
  try {
    await api("POST", walletPath(wallet, "/unlock"), body);
    body.password = "";
    setStatus("Wallet " + wallet + " unlocked.");
    await refreshState();
    await loadEntries();
  } catch (error) {
    body.password = "";
    report(error);
  }
});

// --- Devices (003). Read-only network status; settings change only in the config file. ---

const NET_POLL_MS = 5000;
// While a pairing code is shown or a join runs, poll faster for progress.
const NET_FAST_POLL_MS = 1000;
const SVG_NS = "http://www.w3.org/2000/svg";
const net = { data: null, timer: null, keys: {} };

const NET_STATES = {
  off: "off",
  identity_unusable: "unavailable: the device identity file is unusable",
  peers_unusable: "unavailable: the paired devices file is unusable",
  port_in_use: "unavailable: port in use",
  no_local_network: "no local network",
  on: "on",
};

const PEER_STATUS = {
  connected: "connected",
  offline: "offline",
  refused_by_peer: "refused by peer",
};

const PAIRING_STATES = {
  waiting: "Enter this code on the other device.",
  exchanging: "Checking the code...",
  awaiting_acceptance: "Accept only if the fingerprint matches the other device.",
  paired: "Paired.",
  failed: "Pairing failed, try again.",
};

const JOIN_STATES = {
  connecting: "Connecting...",
  exchanging: "Checking the code...",
  awaiting_acceptance: "Waiting for the other device to accept...",
  paired: "Paired.",
  failed: "Pairing failed, try again.",
};

const FAIL_REASONS = {
  wrong_code_or_tampered: "wrong code",
  expired: "the code expired",
  rejected: "rejected on the other device",
  timeout: "no answer in time",
  id_mismatch: "a different device answered",
  self: "this is this device",
  already_paired: "already paired",
  limit: "too many paired devices",
  refused_not_pairing: "the other device is not showing a code",
  unreachable: "the address cannot be reached",
  cancelled: "cancelled",
  protocol: "unexpected answer",
};

function formatTime(seconds) {
  return seconds ? new Date(seconds * 1000).toLocaleString() : "never";
}

/// Builds the QR `<svg>` with DOM APIs from the server-made path (CSP: no inline content).
function renderQr(container, qr) {
  container.replaceChildren();
  if (!qr) return;
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 " + qr.size + " " + qr.size);
  svg.setAttribute("role", "img");
  svg.setAttribute("shape-rendering", "crispEdges");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", qr.path);
  svg.append(path);
  container.append(svg);
}

function renderPairing() {
  const pairing = net.data.pairing;
  const panel = $("pairing-panel");
  panel.hidden = pairing === null;
  if (!pairing) return;
  let state = PAIRING_STATES[pairing.state] || pairing.state;
  if (pairing.reason) state += " (" + (FAIL_REASONS[pairing.reason] || pairing.reason) + ")";
  $("pairing-state").textContent = state;
  $("pairing-code").textContent = pairing.code || "";
  const key = pairing.code || "";
  if (net.keys.qr !== key) {
    net.keys.qr = key;
    renderQr($("pairing-qr"), pairing.qr);
  }
  $("pairing-countdown").textContent = pairing.code ? "Valid for " + pairing.expires_in + " s" : "";
  const peer = pairing.peer;
  const deciding = pairing.state === "awaiting_acceptance" && peer !== null;
  $("pairing-decision").hidden = !deciding;
  $("pairing-peer-name").textContent = deciding ? peer.name : "";
  $("pairing-peer-fingerprint").textContent = deciding ? peer.fingerprint : "";
  $("pairing-accept").dataset.deviceId = deciding ? peer.device_id : "";
}

function renderJoin() {
  const join = net.data.join;
  if (!join) {
    $("join-state").textContent = "";
    return;
  }
  let text = JOIN_STATES[join.state] || join.state;
  if (join.reason) text += " (" + (FAIL_REASONS[join.reason] || join.reason) + ")";
  if (join.peer) text += " Fingerprint of the other device: " + join.peer.fingerprint;
  $("join-state").textContent = text;
}

function renderNearby() {
  const items = net.data.nearby;
  const key = JSON.stringify(items.map((n) => [n.device_id, n.addr, n.paired]));
  if (key === net.keys.nearby) return;
  net.keys.nearby = key;
  const list = $("nearby-list");
  list.replaceChildren();
  if (items.length === 0) {
    list.append(element("li", "No devices nearby. You can type an address instead.", "muted"));
  }
  for (const n of items) {
    const item = element("li");
    const label = n.fingerprint + " at " + n.addr + (n.paired ? " (paired)" : "");
    item.append(
      button(label, () => {
        $("join-address").value = n.addr;
        $("join-device-id").value = n.device_id;
        $("join-code").focus();
      }, "link"),
    );
    list.append(item);
  }
}

function renderPaired() {
  const items = net.data.paired;
  const key = JSON.stringify(items.map((p) => [p.device_id, p.name, p.last_seen, p.status]));
  if (key === net.keys.paired) return;
  net.keys.paired = key;
  const list = $("paired-list");
  list.replaceChildren();
  if (items.length === 0) list.append(element("li", "No paired devices.", "muted"));
  for (const p of items) {
    const item = element("li");
    item.append(
      element("strong", p.name),
      element("span", " " + p.fingerprint + " ", "fingerprint"),
      element("span", PEER_STATUS[p.status] || p.status, "badge"),
      element("span", " paired " + formatTime(p.paired_at) + ", last seen " + formatTime(p.last_seen), "muted small"),
      button("Revoke", () => revokeDevice(p), "danger"),
    );
    list.append(item);
  }
}

/// Revocation is local and final: only a new pairing restores trust (FR-033).
async function revokeDevice(p) {
  const question =
    "Revoke " + p.name + " (" + p.fingerprint + ")? It will be refused from now on; " +
    "only a new pairing restores it.";
  if (!window.confirm(question)) return;
  await netAction("POST", "/api/devices/" + encodeURIComponent(p.device_id) + "/revoke", undefined, "Device revoked.");
}

function renderWarnings() {
  const items = net.data.warnings;
  const list = $("warnings-list");
  list.replaceChildren();
  for (const w of items) {
    list.append(
      element(
        "li",
        "An unpaired key (" + w.fingerprint + ") was presented at " + w.addr +
          ", the address of paired device " + w.claimed_fingerprint + ".",
      ),
    );
  }
  $("warnings-clear").hidden = items.length === 0;
}

function renderNetwork() {
  const data = net.data;
  if (!data) return;
  const device = data.this_device;
  $("this-device-name").textContent = device ? device.name : "-";
  $("this-device-fingerprint").textContent = device ? device.fingerprint : "-";
  let state = NET_STATES[data.status.state] || data.status.state;
  if (data.status.state === "port_in_use" && data.status.port) state += " " + data.status.port;
  $("network-state").textContent = state;
  const names = data.status.interfaces.map((i) => i.name + " " + i.addr + "/" + i.prefix);
  $("network-interfaces").textContent = names.length ? names.join(", ") : "-";
  const s = data.settings;
  $("network-settings").textContent =
    "network = " + s.network + ", peer_port = " + s.peer_port + ", discovery_port = " +
    s.discovery_port + (s.interface ? ", network_interface = " + s.interface : "");
  $("pair-start").disabled = data.status.state !== "on";
  renderPairing();
  renderJoin();
  renderNearby();
  renderPaired();
  renderWarnings();
}

function netPollDelay() {
  const data = net.data;
  const active =
    data &&
    ((data.pairing && !["paired", "failed"].includes(data.pairing.state)) ||
      (data.join && !["paired", "failed"].includes(data.join.state)));
  return active ? NET_FAST_POLL_MS : NET_POLL_MS;
}

async function netPoll() {
  try {
    net.data = await api("GET", "/api/network");
    renderNetwork();
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) report(error);
  }
}

function scheduleNetPoll() {
  clearTimeout(net.timer);
  net.timer = setTimeout(async () => {
    await netPoll();
    scheduleNetPoll();
  }, netPollDelay());
}

async function netAction(method, path, body, done) {
  try {
    await api(method, path, body);
    if (done) setStatus(done);
  } catch (error) {
    report(error);
  }
  await netPoll();
  scheduleNetPoll();
}

$("pair-start").addEventListener("click", () => netAction("POST", "/api/pairing/start", undefined, "Pairing code shown."));
$("pairing-cancel").addEventListener("click", () => netAction("POST", "/api/pairing/cancel", undefined, "Pairing cancelled."));
$("pairing-reject").addEventListener("click", () => netAction("POST", "/api/pairing/reject", undefined, "Pairing rejected."));
$("pairing-accept").addEventListener("click", () => {
  const body = { device_id: $("pairing-accept").dataset.deviceId };
  return netAction("POST", "/api/pairing/accept", body, "Device paired.");
});

$("join-address").addEventListener("input", () => {
  $("join-device-id").value = "";
});

$("join-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const id = $("join-device-id").value;
  const body = { address: $("join-address").value.trim(), code: $("join-code").value, device_id: id || null };
  $("join-code").value = "";
  return netAction("POST", "/api/pairing/join", body, "Joining...");
});

$("warnings-clear").addEventListener("click", () => netAction("POST", "/api/network/warnings/clear"));

netPoll().then(scheduleNetPoll);

refreshState().catch(report);
setInterval(poll, POLL_MS);
setInterval(fastPoll, FAST_POLL_MS);

// --- Wallet sync (004): conflicts, sync status, changes waiting, warnings. ---

const sync = { conflicts: [], conflictsKey: null, conflict: null, revealTimer: null };

function closeConflicts() {
  clearTimeout(sync.revealTimer);
  sync.conflicts = [];
  sync.conflictsKey = null;
  sync.conflict = null;
  $("conflict-list").replaceChildren();
  $("conflict-versions").replaceChildren();
  $("conflict-actions").replaceChildren();
  $("conflict-view").hidden = true;
  $("conflicts-section").hidden = true;
}

async function loadConflicts() {
  const wallet = selectedWallet();
  if (!wallet || !wallet.unlocked) {
    closeConflicts();
    return;
  }
  const data = await api("GET", walletPath(wallet.name, "/conflicts"));
  if (!selectedWallet() || selectedWallet().name !== wallet.name) return;
  sync.conflicts = data.entries;
  renderConflicts();
}

function renderConflicts() {
  const key = JSON.stringify(sync.conflicts.map((c) => [c.id, c.title, c.versions]));
  if (key === sync.conflictsKey) return;
  sync.conflictsKey = key;
  const list = $("conflict-list");
  list.replaceChildren();
  for (const c of sync.conflicts) {
    const item = element("li");
    item.append(
      button(c.title, () => showConflict(c.id).catch(handleError), "link"),
      element("span", c.versions + " versions", "badge warn"),
    );
    list.append(item);
  }
  $("conflicts-section").hidden = sync.conflicts.length === 0;
  if (sync.conflicts.length === 0) {
    $("conflict-view").hidden = true;
  }
}

async function showConflict(id) {
  const wallet = ui.selected;
  const data = await api("GET", walletPath(wallet, "/conflicts/" + id));
  sync.conflict = id;
  const versions = $("conflict-versions");
  versions.replaceChildren();
  for (const v of data.versions) {
    const item = element("li", undefined, "version");
    const title = v.deleted ? "(deleted)" : v.title;
    item.append(element("strong", title));
    const facts = element("dl", undefined, "fields");
    const fact = (label, value) => facts.append(element("dt", label), element("dd", value || "-"));
    if (!v.deleted) {
      fact("Username", v.username);
      fact("URL", v.url);
      fact("Notes", v.notes);
    }
    fact("Modified", new Date(v.modified_at * 1000).toLocaleString());
    fact("Device", v.device);
    item.append(facts);
    const secret = element("code", "", "secret");
    secret.setAttribute("aria-live", "polite");
    const actions = element("div", undefined, "row");
    actions.append(button("Keep this version", () => resolveConflict(id, v.index).catch(handleError)));
    if (!v.deleted) {
      actions.append(
        button("Reveal password", async () => {
          if (secret.textContent !== "") {
            secret.textContent = "";
            return;
          }
          const field = await api("POST", walletPath(wallet, "/conflicts/" + id + "/field"), {
            index: v.index,
            field: "password",
          }).catch(handleError);
          if (!field) return;
          secret.textContent = field.value;
          field.value = "";
          clearTimeout(sync.revealTimer);
          sync.revealTimer = setTimeout(() => {
            secret.textContent = "";
          }, clearSeconds() * 1000);
        }, "secondary"),
      );
    }
    item.append(actions, secret);
    versions.append(item);
  }
  const bottom = $("conflict-actions");
  bottom.replaceChildren(
    button("Keep both", () => resolveConflict(id, "both").catch(handleError)),
    button("Close", () => {
      $("conflict-view").hidden = true;
      $("conflict-versions").replaceChildren();
    }, "secondary"),
  );
  $("conflict-title").textContent = "Versions of " + (data.versions[0].title || "a deleted credential");
  $("conflict-view").hidden = false;
  $("conflict-title").focus();
}

async function resolveConflict(id, keep) {
  const wallet = ui.selected;
  const body = keep === "both" ? { keep: "both" } : { keep };
  await api("POST", walletPath(wallet, "/conflicts/" + id + "/resolve"), body);
  setStatus("Conflict resolved; the other devices take this choice on their next sync.");
  $("conflict-view").hidden = true;
  $("conflict-versions").replaceChildren();
  await loadEntries();
}

const SYNC_STATES = {
  sync_off: "sync off (networking disabled)",
  disabled: "disabled",
  possible_rollback: "possible rollback",
  conflicts: "conflicts",
  changes_waiting: "changes waiting: unlock to merge",
  syncing: "syncing",
  sync_error: "sync error",
  not_synced: "not synced",
  in_sync: "in sync",
};
const SYNC_REASONS = {
  corrupted_record: "the sync record is corrupted",
  duplicate_wallet_id: "another wallet file has the same identity",
  too_many_conflicts: "too many conflicts, resolve first",
  no_peer: "no peer holds it",
  unlock_once: "unlock once to enable sync",
  format_v1: "format version 1",
};
const PENDING_STATUS = {
  waiting: "changes waiting: unlock to merge",
  cannot_open: "cannot open: different master password or corrupted",
  password_conflict: "password changed on two devices",
  too_many_conflicts: "too many conflicts, resolve first",
};
const POSITIONS = {
  in_sync: "in sync",
  behind: "behind",
  ahead: "ahead",
  diverged: "diverged",
  unknown: "unknown",
  offline: "offline",
  older_state_offered: "older state offered",
  error: "error",
};
const WARNING_KINDS = {
  possible_rollback: "possible rollback: this wallet is older than one this device saved",
  older_state_offered: "a device offered an older state than it sent before",
  invalid_copy: "a device sent a copy that is not valid for this wallet",
  cannot_open: "cannot open: different master password or corrupted",
  self_rollback_recovered: "this device had lost changes; they were recovered from another device",
  password_adopted: "the master password was changed on another device; use the new password next time",
  record_corrupted: "the sync record is corrupted; reset sync state after unlocking",
  duplicate_wallet_id: "another wallet file has the same identity; sync is disabled for both",
};
const syncData = { overview: null, detail: null, key: null };

function syncLabel(sync) {
  if (!sync) return SYNC_STATES.sync_off;
  let text = SYNC_STATES[sync.state] || sync.state;
  if (sync.state === "conflicts") text += " (" + sync.conflicts + ")";
  if (sync.reason) text += ": " + (SYNC_REASONS[sync.reason] || sync.reason);
  return text;
}

function shortPeer(hex) {
  const peer = syncData.overview && syncData.overview.peers.find((p) => p.device_id === hex);
  return peer ? peer.name : "unknown device";
}

function renderSyncOverview() {
  const data = syncData.overview;
  if (!data) return;
  $("sync-now-all").disabled = !data.enabled;
  const devices = $("sync-device-list");
  devices.replaceChildren();
  for (const peer of data.peers) {
    const item = element("li");
    item.append(element("strong", peer.name));
    if (peer.sync === "unsupported") {
      item.append(element("span", "sync unsupported by peer", "badge warn"));
    } else if (peer.last_round_at) {
      item.append(element("span", "Last synced " + new Date(peer.last_round_at * 1000).toLocaleString() +
        " (" + (peer.last_outcome || "unknown") + ")", "muted small"));
    } else {
      item.append(element("span", "not synced yet", "muted small"));
    }
    devices.append(item);
  }
  const warnings = $("sync-warnings");
  warnings.replaceChildren();
  for (const w of data.warnings) {
    const item = element("li");
    let text = w.wallet + ": " + (WARNING_KINDS[w.kind] || w.kind);
    if (w.peer) text += " (" + shortPeer(w.peer) + ")";
    item.append(element("span", text));
    item.append(button("Dismiss", () => dismissWarning(w.id).catch(report), "secondary"));
    warnings.append(item);
  }
  if (data.warnings.length === 0) warnings.append(element("li", "No sync warnings.", "muted"));
}

async function dismissWarning(id) {
  await api("POST", "/api/sync/warnings/dismiss", { ids: [id] });
  await syncPoll();
}

function passwordAction(label, onSubmit) {
  const form = element("form", undefined, "row");
  const id = "pending-password-" + Math.random().toString(36).slice(2);
  const labelNode = element("label", label);
  labelNode.htmlFor = id;
  const input = element("input");
  input.type = "password";
  input.id = id;
  input.autocomplete = "off";
  form.append(labelNode, input);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const password = input.value;
    input.value = "";
    onSubmit(password).catch(handleError);
  });
  return { form, input };
}

function renderPending(wallet, detail) {
  const list = $("sync-pending-list");
  list.replaceChildren();
  for (const p of detail.pending) {
    const item = element("li");
    item.append(element("span", (PENDING_STATUS[p.status] || p.status) + " (from " + shortPeer(p.peer) + ")"));
    const base = walletPath(wallet.name, "/sync/pending/" + p.peer);
    if (wallet.unlocked && p.status === "cannot_open") {
      const open = passwordAction("Master password of that copy", async (password) => {
        await api("POST", base + "/open", { password });
        setStatus("The copy was merged.");
        await refreshAfterSync();
      });
      open.form.append(element("button", "Open copy"));
      item.append(open.form);
    }
    if (wallet.unlocked && p.status === "password_conflict") {
      const choose = passwordAction("Master password of that copy", async () => {});
      const keep = (which) => async () => {
        const password = choose.input.value;
        choose.input.value = "";
        await api("POST", base + "/choose-password", { keep: which, password });
        setStatus("Password choice saved; the wallet was merged.");
        await refreshAfterSync();
      };
      choose.form.append(
        button("Keep this device's password", () => keep("local")().catch(handleError)),
        button("Keep the other device's password", () => keep("copy")().catch(handleError), "secondary"),
      );
      item.append(choose.form);
    }
    item.append(button("Discard", async () => {
      if (!window.confirm("Discard the copy received from " + shortPeer(p.peer) + "? Its changes are not merged.")) return;
      await api("POST", base + "/discard").catch(handleError);
      await syncPoll();
    }, "danger"));
    list.append(item);
  }
}

function renderSyncDetail() {
  const wallet = selectedWallet();
  const detail = syncData.detail;
  if (!wallet || !detail) return;
  let text = syncLabel({ state: detail.state, reason: detail.reason, conflicts: wallet.sync ? wallet.sync.conflicts : 0 });
  if (wallet.sync && wallet.sync.last_synced_at) {
    text += " - Last synced " + new Date(wallet.sync.last_synced_at * 1000).toLocaleString();
  }
  $("wallet-sync-state").textContent = text;
  $("sync-now-wallet").disabled = detail.state === "sync_off";
  renderPending(wallet, detail);
  const peers = $("sync-peer-list");
  peers.replaceChildren();
  for (const p of detail.peers) {
    const item = element("li");
    item.append(element("strong", p.name), element("span", POSITIONS[p.position] || p.position, "badge"));
    if (p.last_round_at) item.append(element("span", "Last synced " + new Date(p.last_round_at * 1000).toLocaleString(), "muted small"));
    peers.append(item);
  }
  const recovery = $("sync-recovery");
  recovery.replaceChildren();
  if (detail.state === "possible_rollback") {
    recovery.append(button("Accept this older state", () => recover("/sync/accept-older",
      "Accept this older state? Newer changes that were lost on this device will not come back unless another device still has them.").catch(handleError), "danger"));
  }
  if (detail.state === "disabled" && detail.reason === "corrupted_record") {
    recovery.append(button("Reset sync state", () => recover("/sync/reset",
      "Reset the sync state of this wallet? It is rebuilt from the wallet as it is now.").catch(handleError), "danger"));
  }
}

async function recover(path, question) {
  const wallet = selectedWallet();
  if (!wallet) return;
  if (!wallet.unlocked) {
    setStatus("Unlock the wallet first.", true);
    return;
  }
  if (!window.confirm(question)) return;
  await api("POST", walletPath(wallet.name, path), { confirm: true });
  setStatus(path === "/sync/reset" ? "Sync state reset." : "The older state was accepted.");
  await syncPoll();
}

async function refreshAfterSync() {
  await refreshState();
  await loadEntries();
  await syncPoll();
}

// Background, on the network poll's interval; skipped while the tab is hidden.
async function syncPoll() {
  if (document.visibilityState === "hidden") return;
  try {
    syncData.overview = await api("GET", "/api/sync");
    renderSyncOverview();
    const wallet = selectedWallet();
    if (wallet) {
      syncData.detail = await api("GET", walletPath(wallet.name, "/sync"));
      renderSyncDetail();
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return;
  }
}

async function syncNow(wallet) {
  try {
    await api("POST", "/api/sync/now", { wallet });
    setStatus("Sync started with every connected device.");
  } catch (error) {
    report(error);
  }
}

$("sync-now-all").addEventListener("click", () => syncNow(null));
$("sync-now-wallet").addEventListener("click", () => syncNow(ui.selected));
syncPoll();
setInterval(syncPoll, NET_POLL_MS);

// --- Wallet sharing (005): Share dialog, invitation panel, Receive form, Received list. ---

const SHARE_POLL_MS = 5000;
// While an invitation or a redemption is in progress, poll every second.
const SHARE_FAST_POLL_MS = 1000;
const share = { data: null, timer: null, keys: {}, dialogOpen: false };

const SHARE_STATES = {
  active: "Enter this code on the receiving device.",
  awaiting_acceptance: "The receiving device entered the code.",
  transferring: "Sending the encrypted wallet...",
  completed: "Delivered.",
  cancelled: "Invitation cancelled",
  expired: "The invitation expired.",
  rejected: "Rejected.",
  refused: "Refused",
  failed: "Sharing failed",
};
const SHARE_REASONS = {
  by_person: "by you",
  wallet_locked: "the wallet was locked",
  recipient_revoked: "the device was revoked",
  replaced: "replaced by a new invitation",
  wrong_code: "wrong code",
  not_recipient: "not recipient",
  recipient_cancelled: "cancelled on the other device",
  channel_lost: "connection lost",
  busy: "busy, try again later",
  sender_error: "the wallet file changed or could not be read",
  storage: "the other device could not store it",
  too_large: "too large",
  received_limit: "the other device already holds 8 received wallets",
  timeout: "no answer in time",
};
const RECEIVE_STATES = {
  connecting: "Connecting to the sender...",
  awaiting_sender: "Waiting for the sender to accept...",
  receiving: "Receiving the encrypted wallet...",
  stored: "Received. Open it below with its master password.",
  failed: "Receiving failed",
  cancelled: "Cancelled.",
};
const RECEIVE_REASONS = {
  invalid: "invalid: wrong code, not for this device, or already used",
  cancelled_by_sender: "invitation cancelled by sender",
  expired: "the invitation expired",
  rejected: "rejected by the sender",
  busy: "busy, try again later",
  too_large: "too large",
  storage: "could not store it on this device",
  sender_error: "the sender's wallet file changed",
  unreachable: "the sender cannot be reached",
  unsupported: "this device does not support sharing",
  received_limit: "8 received wallets already wait: open or discard one first",
  channel_lost: "connection lost",
  timeout: "no answer in time",
  id_mismatch: "a different device answered at that address",
};
const SHARE_UNAVAILABLE = {
  networking_off: "Sharing needs networking; it is turned on in the configuration file.",
  network_unavailable: "Sharing is unavailable: no local network.",
  received_unusable: "Sharing is unavailable: the received wallets folder has wrong owner or permissions.",
};
const SHARE_SUPPORT = {
  supported: "",
  unsupported: "this device does not support sharing",
  unknown: "not seen yet",
};

function peerLabel(peer) {
  if (!peer) return "unknown device";
  return (peer.name || "unnamed device") + " (" + peer.fingerprint + ")";
}

function renderShareDialog() {
  const data = share.data;
  const dialog = $("share-dialog");
  const wallet = selectedWallet();
  dialog.hidden = !share.dialogOpen || !wallet || !wallet.unlocked;
  if (dialog.hidden || !data) return;
  const key = JSON.stringify([wallet.name, data.peers.map((p) => [p.device_id, p.name, p.status, p.share])]);
  if (key === share.keys.dialog) return;
  share.keys.dialog = key;
  const list = $("share-device-list");
  list.replaceChildren();
  if (data.peers.length === 0) list.append(element("li", "No paired devices. Pair a device first.", "muted"));
  for (const p of data.peers) {
    const item = element("li");
    const choose = button(peerLabel(p), () => createInvitation(wallet.name, p).catch(report), "link");
    choose.disabled = p.share === "unsupported";
    item.append(choose, element("span", PEER_STATUS[p.status] || p.status, "badge"));
    if (SHARE_SUPPORT[p.share]) item.append(element("span", SHARE_SUPPORT[p.share], "muted small"));
    list.append(item);
  }
}

async function createInvitation(wallet, peer) {
  await api("POST", walletPath(wallet, "/share"), { device_id: peer.device_id });
  share.dialogOpen = false;
  setStatus("Invitation for " + peerLabel(peer) + " created.");
  await sharePoll();
  scheduleSharePoll();
}

function renderInvitation() {
  const inv = share.data.invitation;
  const panel = $("share-panel");
  panel.hidden = inv === null;
  if (!inv) return;
  const recipient = inv.recipient;
  let text = (SHARE_STATES[inv.state] || inv.state) + " Wallet '" + inv.wallet + "' for " + peerLabel(recipient) + ".";
  if (inv.reason) text += " (" + (SHARE_REASONS[inv.reason] || inv.reason) + ")";
  if (inv.progress) text += " " + inv.progress.sent + " of " + inv.progress.size + " bytes.";
  $("share-state").textContent = text;
  $("share-code").textContent = inv.code || "";
  const qrKey = inv.code || "";
  if (share.keys.qr !== qrKey) {
    share.keys.qr = qrKey;
    renderQr($("share-qr"), inv.qr);
  }
  $("share-countdown").textContent = inv.code ? "Valid for " + inv.expires_in + " s" : "";
  const deciding = inv.state === "awaiting_acceptance";
  $("share-decision").hidden = !deciding;
  $("share-decision-text").textContent = deciding
    ? "Send wallet '" + inv.wallet + "' to " + recipient.name + " (" + recipient.fingerprint + ")?"
    : "";
  $("share-accept").dataset.deviceId = deciding ? recipient.device_id : "";
  const live = ["active", "awaiting_acceptance", "transferring"].includes(inv.state);
  $("share-cancel").hidden = !live && inv.state !== "completed";
  if (inv.state !== "completed") $("share-explain").hidden = true;
}

function renderReceive() {
  const r = share.data.receive;
  if (!r) {
    $("receive-state").textContent = "";
    $("receive-cancel").hidden = true;
    return;
  }
  let text = RECEIVE_STATES[r.state] || r.state;
  if (r.sender) text += " Sender: " + peerLabel(r.sender) + ".";
  if (r.seconds_left) text += " The sender has " + r.seconds_left + " s to accept.";
  if (r.progress) text += " " + r.progress.received + " of " + r.progress.size + " bytes.";
  if (r.reason) text += " (" + (RECEIVE_REASONS[r.reason] || r.reason) + ")";
  $("receive-state").textContent = text;
  $("receive-cancel").hidden = !["connecting", "awaiting_sender", "receiving"].includes(r.state);
}

function shortFingerprint(peer) {
  return peer && peer.fingerprint ? peer.fingerprint.slice(0, 4) : "";
}

function timeLeft(expiresAt) {
  const seconds = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours + " h " + minutes + " min";
}

function renderReceived() {
  const items = share.data.received;
  const key = JSON.stringify(items.map((r) => [r.id, r.sender.name, r.expires_at, timeLeft(r.expires_at)]));
  if (key === share.keys.received) return;
  share.keys.received = key;
  const list = $("received-list");
  list.replaceChildren();
  if (items.length === 0) list.append(element("li", "No received wallets.", "muted"));
  for (const r of items) {
    const item = element("li");
    item.append(
      element("strong", "From " + peerLabel(r.sender)),
      element("span", " received " + formatTime(r.received_at), "muted small"),
      element("span", " deleted automatically in " + timeLeft(r.expires_at), "muted small"),
    );
    const open = element("form", undefined, "row");
    const nameId = "received-name-" + r.id;
    const passwordId = "received-password-" + r.id;
    const nameLabel = element("label", "Local name");
    nameLabel.htmlFor = nameId;
    const nameInput = element("input");
    nameInput.id = nameId;
    nameInput.type = "text";
    nameInput.maxLength = 64;
    nameInput.value = "Shared wallet " + shortFingerprint(r.sender);
    const passwordLabel = element("label", "Master password");
    passwordLabel.htmlFor = passwordId;
    const passwordInput = element("input");
    passwordInput.id = passwordId;
    passwordInput.type = "password";
    passwordInput.autocomplete = "off";
    open.append(nameLabel, nameInput, passwordLabel, passwordInput, button("Open", () => openReceived(r, nameInput, passwordInput).catch(handleError)));
    open.addEventListener("submit", (event) => {
      event.preventDefault();
      openReceived(r, nameInput, passwordInput).catch(handleError);
    });
    item.append(open, button("Discard", () => discardReceived(r).catch(report), "danger"));
    list.append(item);
  }
}

async function discardReceived(r) {
  const question = "Discard the wallet received from " + peerLabel(r.sender) + "? It is deleted from this device.";
  if (!window.confirm(question)) return;
  await api("POST", "/api/received/" + encodeURIComponent(r.id) + "/discard");
  setStatus("Received wallet discarded.");
  await sharePoll();
}

const NOTICE_TEXTS = {
  received_expired: (n) => "A received wallet from " + n.sender + " was deleted after 24 hours.",
  received_deleted_revoked: (n) => "Received wallets from " + n.sender + " were deleted because the device was revoked.",
  received_cleaned: (n) => n.count + " incomplete or unusable received file(s) were removed at start-up.",
  already_present: (n) => "That wallet is already on this device as '" + n.existing + "'.",
};

function renderShareNotices() {
  const items = share.data.notices;
  const key = JSON.stringify(items.map((n) => n.id));
  if (key === share.keys.notices) return;
  share.keys.notices = key;
  const list = $("share-notices");
  list.replaceChildren();
  for (const n of items) {
    const item = element("li");
    const text = NOTICE_TEXTS[n.kind] ? NOTICE_TEXTS[n.kind](n) : n.kind;
    item.append(element("span", text), button("Dismiss", () => dismissNotice(n.id).catch(report), "secondary"));
    list.append(item);
  }
}

async function dismissNotice(id) {
  await api("POST", "/api/share/notices/dismiss", { ids: [id] });
  await sharePoll();
}

async function openReceived(r, nameInput, passwordInput) {
  const body = { name: nameInput.value, password: passwordInput.value };
  passwordInput.value = "";
  try {
    const opened = await api("POST", "/api/received/" + encodeURIComponent(r.id) + "/open", body);
    body.password = "";
    ui.selected = opened.name;
    setStatus("Wallet " + opened.name + " opened; it now syncs with " + peerLabel(r.sender) + ".");
    await refreshState();
    await loadEntries();
  } catch (error) {
    body.password = "";
    throw error;
  } finally {
    await sharePoll();
  }
}

function renderReceiveSenders() {
  const peers = share.data.peers;
  const key = JSON.stringify(peers.map((p) => [p.device_id, p.name]));
  if (key === share.keys.senders) return;
  share.keys.senders = key;
  const select = $("receive-sender");
  const current = select.value;
  select.replaceChildren();
  const none = element("option", "(enter an address instead)");
  none.value = "";
  select.append(none);
  for (const p of peers) {
    const option = element("option", peerLabel(p));
    option.value = p.device_id;
    select.append(option);
  }
  select.value = current;
}

function renderShare() {
  const data = share.data;
  if (!data) return;
  const available = data.available;
  $("share-unavailable").hidden = available;
  $("share-unavailable").textContent = available ? "" : SHARE_UNAVAILABLE[data.unavailable_reason] || data.unavailable_reason;
  $("share-wallet").disabled = !available;
  for (const node of $("receive-form").elements) node.disabled = !available;
  renderReceiveSenders();
  renderShareDialog();
  renderInvitation();
  renderReceive();
  renderReceived();
  renderShareNotices();
}

function sharePollDelay() {
  const data = share.data;
  const active =
    data &&
    ((data.invitation && ["active", "awaiting_acceptance", "transferring"].includes(data.invitation.state)) ||
      (data.receive && ["connecting", "awaiting_sender", "receiving"].includes(data.receive.state)));
  return active ? SHARE_FAST_POLL_MS : SHARE_POLL_MS;
}

// Background: GET /api/share never counts as activity for auto-lock.
async function sharePoll() {
  try {
    share.data = await api("GET", "/api/share");
    renderShare();
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) report(error);
  }
}

function scheduleSharePoll() {
  clearTimeout(share.timer);
  share.timer = setTimeout(async () => {
    await sharePoll();
    scheduleSharePoll();
  }, sharePollDelay());
}

async function shareAction(method, path, body, done) {
  try {
    await api(method, path, body);
    if (done) setStatus(done);
  } catch (error) {
    report(error);
  }
  await sharePoll();
  scheduleSharePoll();
}

$("share-wallet").addEventListener("click", () => {
  share.dialogOpen = true;
  share.keys.dialog = null;
  renderShareDialog();
  $("share-dialog-heading").focus();
});
$("share-dialog-close").addEventListener("click", () => {
  share.dialogOpen = false;
  renderShareDialog();
});
$("share-accept").addEventListener("click", () => {
  const body = { device_id: $("share-accept").dataset.deviceId };
  return shareAction("POST", "/api/share/accept", body, "Sending the encrypted wallet.");
});
$("share-reject").addEventListener("click", () => shareAction("POST", "/api/share/reject", undefined, "Invitation rejected."));
$("share-cancel").addEventListener("click", async () => {
  const inv = share.data && share.data.invitation;
  try {
    const result = await api("POST", "/api/share/cancel");
    if (result && result.already_delivered) {
      const name = inv ? peerLabel(inv.recipient) : "the other device";
      const explain = $("share-explain");
      explain.textContent =
        "Nothing to cancel: the encrypted copy already reached " + name +
        "; to stop access, revoke the device and change the master password.";
      explain.hidden = false;
      return;
    }
    setStatus("Invitation cancelled.");
  } catch (error) {
    report(error);
  }
  await sharePoll();
  scheduleSharePoll();
});
$("receive-cancel").addEventListener("click", () => shareAction("POST", "/api/receive/cancel", undefined, "Receiving cancelled."));
$("receive-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const sender = $("receive-sender").value;
  const address = $("receive-address").value.trim();
  const body = { code: $("receive-code").value, device_id: sender || null, address: address || null };
  $("receive-code").value = "";
  return shareAction("POST", "/api/receive", body, "Redeeming the invitation...");
});

sharePoll().then(scheduleSharePoll);
