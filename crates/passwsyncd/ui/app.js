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
  const key = JSON.stringify([ui.selected, ui.wallets.map((w) => [w.name, w.unlocked])]);
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
  const key = JSON.stringify([unlocked, ui.entries.map((e) => [e.id, e.title, e.username])]);
  if (key === ui.entriesKey) return;
  ui.entriesKey = key;
  const list = $("entry-list");
  list.replaceChildren();
  for (const entry of ui.entries) {
    const item = element("li");
    const open = button(entry.title, () => showEntry(entry.id).catch(handleError), "link");
    item.append(open, element("span", entry.username, "muted"));
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

refreshState().catch(report);
setInterval(poll, POLL_MS);
setInterval(fastPoll, FAST_POLL_MS);
