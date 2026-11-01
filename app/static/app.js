/* Airlock UI: vanilla JS, no build step, no external requests.
   All server-provided text is inserted with textContent (never innerHTML). */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
}

const state = { config: null, examples: [], running: false, activeExample: null };

/* ------------------------------------------------------------------ API */
function apiKey() { try { return sessionStorage.getItem("airlock.key") || ""; } catch { return ""; } }

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const key = apiKey();
  if (key) headers["X-API-Key"] = key;
  const res = await fetch(path, { ...options, headers });
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    let detail = body && body.detail;
    if (Array.isArray(detail)) detail = detail.map(d => d.msg).join("; ");
    const err = new Error(detail || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return body;
}

/* ------------------------------------------------------------ constants */
const VERDICTS = {
  success:        { cls: "ok",   title: "Completed",                note: "The script finished normally inside its limits." },
  error:          { cls: "warn", title: "Script exited with an error", note: "The sandbox worked; the code itself failed. The traceback is below." },
  timeout:        { cls: "stop", title: "Killed at the time limit",  note: "The container was stopped and removed." },
  oom_killed:     { cls: "stop", title: "Killed at the memory limit", note: "The kernel stopped the process at its RAM cap." },
  output_limit:   { cls: "stop", title: "Output capped",             note: "Output exceeded the size limit and was cut off." },
  blocked:        { cls: "stop", title: "Blocked by policy",         note: "The static check rejected this code; nothing was executed." },
  internal_error: { cls: "stop", title: "Sandbox failure",           note: "The backend could not run the code. This is not your script's fault." },
};
const SEALS = [
  ["time", "Time"], ["memory", "Memory"], ["processes", "Processes"],
  ["network", "Network"], ["filesystem", "Filesystem"], ["output", "Output"], ["policy", "Policy"],
];
const PHASES = [
  ["policy_ms", "Policy check"], ["prepare_ms", "Set up"], ["run_ms", "Run"], ["cleanup_ms", "Tear down"],
];

/* ---------------------------------------------------------- header bits */
function renderLimits(cfg) {
  const box = $("#limits");
  box.replaceChildren();
  const L = cfg.limits, C = cfg.capabilities || {};
  const chip = (label, value) => el("span", { class: "chip" }, `${label} `, el("b", { text: value }));
  box.append(
    chip("Memory", `${L.memory_mb} MB`),
    chip("CPU", `${L.cpus} core`),
    chip("Processes", `${L.pids_limit}`),
    chip("Network", C.network_isolated === false ? "NOT isolated" : "none"),
    chip("Policy", cfg.policy_mode),
    chip("Backend", cfg.backend),
  );
  const t = $("#timeout");
  t.max = L.max_timeout_s;
  t.value = L.default_timeout_s;
  $("#timeoutOut").textContent = `${t.value} s`;
}

async function loadHealth() {
  const box = $("#health");
  try {
    const h = await api("/api/health");
    box.className = "health " + (h.ok ? "ok" : "bad");
    $("#healthText").textContent = h.ok ? `Ready. ${h.detail}` : h.detail;
  } catch (e) {
    box.className = "health bad";
    $("#healthText").textContent = e.message;
  }
}

/* --------------------------------------------------------------- editor */
const editor = $("#editor");
const gutter = $("#gutter");

function syncGutter() {
  const lines = editor.value.split("\n").length;
  gutter.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
  gutter.scrollTop = editor.scrollTop;
  $("#charCount").textContent = `${editor.value.length.toLocaleString()} chars`;
}
editor.addEventListener("input", () => { syncGutter(); markActive(null); });
editor.addEventListener("scroll", () => { gutter.scrollTop = editor.scrollTop; });
editor.addEventListener("keydown", (e) => {
  if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    const { selectionStart: s, selectionEnd: en, value } = editor;
    editor.value = value.slice(0, s) + "    " + value.slice(en);
    editor.selectionStart = editor.selectionEnd = s + 4;
    syncGutter();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); runCurrent(); }
});
$("#timeout").addEventListener("input", (e) => { $("#timeoutOut").textContent = `${e.target.value} s`; });

function setCode(code) { editor.value = code; syncGutter(); }

/* -------------------------------------------------------------- results */
function showRunning(label) {
  $("#result").replaceChildren(el("div", { class: "running" }, el("div", { class: "spinner" }), el("span", { text: label })));
}

function showError(title, message) {
  $("#result").replaceChildren(el("div", { class: "error-box", role: "alert" }, el("strong", { text: title }), el("span", { text: message })));
}

function outputBlock(label, text, isErr) {
  const empty = !text;
  return el("div", {},
    el("div", { class: "out-label" }, el("span", { text: label }), el("span", { text: empty ? "empty" : `${text.length.toLocaleString()} chars` })),
    el("pre", { class: "out" + (isErr && !empty ? " err" : "") + (empty ? " none" : ""), text: empty ? "(nothing written)" : text }));
}

function renderResult(r) {
  const v = VERDICTS[r.status] || VERDICTS.error;
  const root = el("div", { class: "res" });

  root.append(el("div", { class: "verdict " + v.cls },
    el("span", { class: "v-title", text: v.title }),
    el("span", { class: "v-note", text: v.note })));

  root.append(el("dl", { class: "meta" },
    el("div", {}, el("dt", { text: "Exit code" }), el("dd", { text: String(r.exit_code) })),
    el("div", {}, el("dt", { text: "Total time" }), el("dd", { text: `${Math.round(r.execution_time_ms)} ms` })),
    el("div", {}, el("dt", { text: "Backend" }), el("dd", { text: r.backend })),
    el("div", {}, el("dt", { text: "Run id" }), el("dd", { text: r.id }))));

  // Limits that fired
  const hit = new Set(r.tripped || []);
  const seals = el("div", { class: "seals" });
  for (const [key, label] of SEALS) {
    const on = hit.has(key);
    seals.append(el("div", { class: "seal" + (on ? " hit" : "") },
      el("span", { class: "n", text: label }), el("span", { class: "s", text: on ? "Limit hit" : "Not hit" })));
  }
  root.append(el("div", {}, el("p", { class: "h3", text: "Limits that fired" }), seals));

  // Lifecycle timeline, widths proportional to time spent
  const phases = PHASES.filter(([k]) => typeof r.phases[k] === "number");
  const total = phases.reduce((a, [k]) => a + r.phases[k], 0) || 1;
  const bar = el("div", { class: "timeline", role: "img", "aria-label": "Time spent in each phase of the run" });
  const legend = el("div", { class: "legend" });
  for (const [k, label] of PHASES) {
    if (typeof r.phases[k] !== "number") continue;
    const ms = r.phases[k];
    const pct = Math.max(3, (ms / total) * 100);
    bar.append(el("div", { class: `seg ${k}`, style: `width:${pct}%`, title: `${label}: ${ms} ms`, text: pct > 14 ? `${Math.round(ms)} ms` : "" }));
    legend.append(el("span", {}, el("i", { class: `seg ${k}`, style: "padding:0;min-width:10px" }), `${label} ${Math.round(ms)} ms`));
  }
  root.append(el("div", {}, el("p", { class: "h3", text: "Lifecycle of this run" }), bar, legend));

  // Policy findings
  const f = (r.policy && r.policy.findings) || [];
  if (f.length) {
    const ul = el("ul", { class: "findings" });
    for (const x of f) {
      ul.append(el("li", { class: x.severity },
        el("code", { text: `line ${x.line}` }), ` ${x.message} `, el("span", { class: "muted", text: `(${x.category}, ${x.severity})` })));
    }
    const mode = r.policy.mode;
    const note = mode === "block" ? "Static policy findings (high severity blocks execution)" : "Static policy findings (advisory; the container still enforces limits)";
    root.append(el("div", {}, el("p", { class: "h3", text: note }), ul));
  }

  root.append(outputBlock("stdout", r.stdout, false));
  root.append(outputBlock("stderr", r.stderr, true));
  $("#result").replaceChildren(root);
}

/* --------------------------------------------------------------- running */
function setBusy(on, label) {
  state.running = on;
  $("#runBtn").disabled = on;
  $("#suiteBtn").disabled = on;
  if (on && label) showRunning(label);
}

async function execute(code, timeout) {
  return api("/api/execute", { method: "POST", body: JSON.stringify({ code, timeout_seconds: timeout }) });
}

function revealResultOnSmallScreens() {
  // Single-column layout: the report sits below the editor and payload list.
  if (!window.matchMedia("(max-width: 960px)").matches) return;
  const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  $(".result-panel").scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
}

async function runCurrent() {
  if (state.running) return;
  const code = editor.value;
  if (!code.trim()) { showError("Nothing to run", "Write or load some Python first."); return; }
  setBusy(true, "Starting a disposable sandbox…");
  try {
    const r = await execute(code, Number($("#timeout").value));
    renderResult(r);
    pushHistory(code, r);
    revealResultOnSmallScreens();
  } catch (e) {
    showError(e.status === 429 ? "Slow down" : e.status === 503 ? "Sandbox busy" : e.status === 401 ? "API key needed" : "Request failed", e.message);
  } finally {
    setBusy(false);
  }
}
$("#runBtn").addEventListener("click", runCurrent);

/* --------------------------------------------------------------- gallery */
function markActive(id) {
  state.activeExample = id;
  document.querySelectorAll(".ex").forEach(b => b.classList.toggle("active", b.dataset.id === id));
}

function renderGallery() {
  const g = $("#gallery");
  g.replaceChildren();
  const groups = [["normal", "Everyday code"], ["hostile", "Hostile payloads"]];
  for (const [key, title] of groups) {
    g.append(el("p", { class: "group-title", text: title }));
    for (const ex of state.examples.filter(e => e.group === key)) {
      g.append(el("button", { class: "ex", type: "button", "data-id": ex.id, onclick: () => {
        setCode(ex.code); $("#timeout").value = ex.timeout; $("#timeoutOut").textContent = `${ex.timeout} s`; markActive(ex.id);
      } },
        el("span", { class: "t", text: ex.title }),
        el("span", { class: "b", text: ex.blurb }),
        el("span", { class: "badge", id: `badge-${ex.id}`, hidden: true })));
    }
  }
}

function setBadge(id, cls, text) {
  const b = $(`#badge-${id}`);
  if (!b) return;
  b.hidden = false; b.className = `badge ${cls}`; b.textContent = text;
}

function judge(ex, r) {
  const statusOk = !ex.expect_status || ex.expect_status.includes(r.status);
  const trippedOk = (ex.expect_tripped || []).every(t => (r.tripped || []).includes(t));
  const outOk = !ex.expect_stdout || (r.stdout || "").includes(ex.expect_stdout);
  const truncOk = ex.expect_truncated == null || r.truncated === ex.expect_truncated;
  // A policy block is a valid way to stop the shell-escape example.
  if (r.status === "blocked" && (ex.expect_status || []).includes("blocked")) return true;
  return statusOk && trippedOk && outOk && truncOk;
}

async function runSuite() {
  if (state.running) return;
  const caps = (state.config && state.config.capabilities) || {};
  const summary = $("#suiteSummary");
  summary.hidden = false; summary.className = "suite-summary running"; summary.textContent = "Running the suite…";
  setBusy(true, "Running every payload in its own sandbox…");
  let held = 0, failed = 0, skipped = 0;
  document.querySelectorAll("#gallery .badge").forEach(b => { b.hidden = true; });
  try {
    for (const ex of state.examples) {
      if (ex.needs && caps[ex.needs] === false) {
        skipped++; setBadge(ex.id, "skip", "Not enforced here"); continue;
      }
      setBadge(ex.id, "run", "Running…");
      let r;
      try { r = await execute(ex.code, ex.timeout); }
      catch (e) { failed++; setBadge(ex.id, "fail", e.message.slice(0, 30)); if (e.status === 429) break; continue; }
      if (judge(ex, r)) { held++; setBadge(ex.id, "held", ex.group === "hostile" ? "Contained" : "As expected"); }
      else { failed++; setBadge(ex.id, "fail", "Unexpected"); }
      renderResult(r);
      pushHistory(ex.code, r);
    }
  } finally {
    setBusy(false);
  }
  const total = held + failed;
  summary.className = "suite-summary " + (failed ? "warn" : "good");
  summary.textContent = failed
    ? `${held} of ${total} behaved as expected, ${failed} did not. Check the badges below.`
    : `All ${held} payloads behaved as expected` + (skipped ? ` (${skipped} skipped: limit not enforced on this backend).` : ".");
}
$("#suiteBtn").addEventListener("click", runSuite);

/* --------------------------------------------------------------- history */
const HKEY = "airlock.history";
function loadHistory() { try { return JSON.parse(localStorage.getItem(HKEY) || "[]"); } catch { return []; } }
function saveHistory(h) { try { localStorage.setItem(HKEY, JSON.stringify(h)); } catch { /* storage unavailable */ } }

function pushHistory(code, r) {
  const h = loadHistory();
  h.unshift({ code: code.slice(0, 20000), status: r.status, ms: Math.round(r.execution_time_ms), at: Date.now() });
  saveHistory(h.slice(0, 12));
  renderHistory();
}

function renderHistory() {
  const ul = $("#history");
  const h = loadHistory();
  ul.replaceChildren();
  if (!h.length) { ul.append(el("li", { class: "muted", text: "Runs from this browser appear here." })); return; }
  for (const item of h) {
    const v = VERDICTS[item.status] || VERDICTS.error;
    const first = (item.code.split("\n").find(l => l.trim()) || "").trim();
    ul.append(el("li", {}, el("button", { class: "hrow", type: "button", title: "Load this code", onclick: () => { setCode(item.code); markActive(null); } },
      el("span", { class: "badge " + (v.cls === "ok" ? "held" : v.cls === "warn" ? "skip" : "fail"), text: item.status }),
      el("span", { class: "code", text: first }),
      el("span", { class: "ms", text: `${item.ms} ms` }))));
  }
}
$("#clearHistory").addEventListener("click", () => { saveHistory([]); renderHistory(); });

/* ------------------------------------------------------------------ init */
async function init() {
  syncGutter();
  renderHistory();
  try {
    const [cfg, examples] = await Promise.all([api("/api/config"), api("/api/examples")]);
    state.config = cfg; state.examples = examples;
    renderLimits(cfg);
    renderGallery();
    if (cfg.auth_required) {
      $("#authBar").hidden = false;
      $("#apiKey").value = apiKey();
      $("#apiKey").addEventListener("input", (e) => { try { sessionStorage.setItem("airlock.key", e.target.value); } catch { /* ignore */ } });
    }
    const first = examples[0];
    if (first) { setCode(first.code); markActive(first.id); }
  } catch (e) {
    showError("Cannot reach the sandbox API", e.message);
  }
  loadHealth();
}
init();
