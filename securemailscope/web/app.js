/* SecureMailScope web frontend. Vanilla JS, no build step, talks to the Flask JSON API.
   Views:  #/               new analysis + recent analyses
           #/r/<id>         report dashboard with the wire replay (capture simulation)
           #/r/<id>/s/<sid> session handshake replay
   Every string that came off the wire is escaped with esc() before it reaches the DOM. */
(() => {
"use strict";

// ------------------------------------------------------------------ helpers
const app = document.getElementById("app");
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
// Colours come from the stylesheet so the theme has exactly one source of truth;
// the literals are only a fallback for the case where CSS has not applied yet.
const cssVar = (name, fallback) => {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch (e) { return fallback; }
};
let SEV_COLOR = {}, C = {}, CAT = {};
// Protocol is identity, so it takes categorical hues. Severity keeps the status
// palette to itself: a protocol that borrowed "high" would read as a verdict.
const PROTO_HUE = { SMTP: 1, IMAP: 2, POP3: 3 };
const protoColor = (p) => CAT[PROTO_HUE[p]] || C.idle;
function readTheme() {
  SEV_COLOR = { critical: cssVar("--crit", "#C43526"), high: cssVar("--high", "#C2691A"),
                medium: cssVar("--med", "#B08307"), low: cssVar("--low", "#2565A9"),
                info: cssVar("--info", "#9AA4AF") };
  C = { accent: cssVar("--accent", "#0F7A62"), clear: cssVar("--high", "#C2691A"),
        bad: cssVar("--crit", "#C43526"), idle: cssVar("--faint", "#6E7A88"),
        tcp: cssVar("--tcp", "#7C8591"), deep: cssVar("--accent-deep", "#0F7A62") };
  CAT = { 1: cssVar("--cat-1", "#2A78D6"), 2: cssVar("--cat-2", "#EB6834"),
          3: cssVar("--cat-3", "#1BAF7A"), 4: cssVar("--cat-4", "#EDA100"),
          5: cssVar("--cat-5", "#4A3AA7") };
}
readTheme();

// ---------- theme switch (light is the default; the choice is remembered)
function applyTheme(dark) {
  const root = document.documentElement;
  if (dark) root.setAttribute("data-theme", "dark");
  else root.removeAttribute("data-theme");
  try { localStorage.setItem("sms-theme", dark ? "dark" : "light"); } catch (e) {}
  readTheme();                       // SVG colours are inlined, so re-read the tokens
  const btn = document.getElementById("themebtn");
  if (btn) btn.setAttribute("aria-pressed", String(dark));
  window.dispatchEvent(new CustomEvent("sms:theme"));
}
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("themebtn");
  if (!btn) return;
  btn.setAttribute("aria-pressed", String(document.documentElement.getAttribute("data-theme") === "dark"));
  btn.addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") !== "dark"));
});
const cache = new Map();
let teardown = [];            // cleanup callbacks for the current view (timers, observers)

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
const sevChip = (s) => `<span class="chip s-${esc(s)}">${esc(SEV_LABEL[s] || s)}</span>`;
const worst = (fs) => fs.reduce((w, f) => (SEVS.indexOf(f.severity) < SEVS.indexOf(w) ? f.severity : w), "info");
const code = (t) => esc(t).replace(/`([^`]+)`/g, "<code>$1</code>");
const shortHash = (h) => (h ? `${h.slice(0, 8)}…${h.slice(-4)}` : "");
const utc = (ts) => new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
const hhmmss = (ts) => new Date(ts * 1000).toISOString().slice(11, 19);
const icon = {
  play: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 4.5v15l13-7.5z"/></svg>',
  pause: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4.5" width="4" height="15" rx="1"/><rect x="14" y="4.5" width="4" height="15" rx="1"/></svg>',
  restart: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 3v6h6"/></svg>',
  back: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M17 4.5v15L6 12z"/><rect x="4" y="4.5" width="2.5" height="15" rx="1"/></svg>',
  fwd: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 4.5v15L18 12z"/><rect x="17.5" y="4.5" width="2.5" height="15" rx="1"/></svg>',
  down: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 20h14"/></svg>',
  lock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  unlock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/></svg>',
  alert: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 21h20z"/><path d="M12 10v5M12 18v.5"/></svg>',
  upload: '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 15V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>',
  client: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  server: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/></svg>',
  path: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M3 12h6M15 12h6M12 3v6M12 15v6"/></svg>',
};

function toast(msg) {
  const t = document.getElementById("toast");
  t.innerHTML = `<div class="t">${esc(msg)}</div>`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.innerHTML = ""), 4200);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

async function getReport(id) {
  if (!cache.has(id)) cache.set(id, await api(`/api/report/${encodeURIComponent(id)}`));
  return cache.get(id);
}

function countUp(el, to, dur = 1100) {
  if (REDUCED || !to) { el.textContent = to; return; }
  const t0 = performance.now();
  const tick = (now) => {
    const p = Math.min(1, (now - t0) / dur);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function afterPaint(fn) { requestAnimationFrame(() => requestAnimationFrame(fn)); }

// ------------------------------------------------------------------ router
function route() {
  teardown.forEach((fn) => { try { fn(); } catch (e) { /* view already gone */ } });
  teardown = [];
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  $$(".topnav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === "home"));
  window.scrollTo(0, 0);
  app.classList.toggle("wide", parts[0] === "r");
  if (parts[0] === "r" && parts[1] && parts[2] === "s" && parts[3]) return viewSession(parts[1], parts[3]);
  if (parts[0] === "r" && parts[1]) return viewReport(parts[1], parts[2] || "overview");
  return viewHome();
}
window.addEventListener("hashchange", route);

// ================================================================== HOME
async function viewHome() {
  document.title = "SecureMailScope";
  app.innerHTML = `
  <section class="hero">
    <div>
      <div class="eyebrow reveal">EMAIL TRANSPORT SECURITY · FROM A PACKET CAPTURE</div>
      <h1 class="reveal" style="animation-delay:.05s">See what actually happened on your mail wire.</h1>
      <p class="lead reveal" style="animation-delay:.1s">Drop in a capture. SecureMailScope rebuilds every SMTP, IMAP and POP3 session, replays each handshake, catches STARTTLS stripping and injection, grades the TLS and certificates, and ranks what to fix first.</p>
      <div class="feats">
        ${feat('<path d="M4 7h16M4 12h10M4 17h7"/><path d="m16 15 5 5M21 15l-5 5"/>', "STARTTLS stripping and injection", "Same-length capability rewrites, refused upgrades, cleartext smuggled across the switch.", 0.15)}
        ${feat('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M15 8l2 2"/>', "Credentials found, never stored", "You learn whose password to rotate. The password itself is discarded.", 0.2)}
        ${feat('<path d="M3 17l5-5 4 4 8-8"/><path d="M14 8h6v6"/>', "Per-endpoint baseline", "A self-signed cert is Medium. A self-signed cert where a CA cert always was is a possible MITM.", 0.25)}
      </div>
    </div>
    <form class="card upload reveal" style="animation-delay:.12s" id="upform">
      <h2>New analysis</h2>
      <div class="drop" id="drop">
        <span style="color:var(--accent)">${icon.upload}</span>
        <div class="big" id="dropmsg">Drop a .pcap or .pcapng here</div>
        <div class="faint" style="font-size:13px" id="dropsub">or click to choose · .gz, .bz2, .xz and .zst unwrap automatically · Ethernet, VLAN, Linux cooked, raw IP · up to 256 MB</div>
        <input type="file" id="file" accept=".pcap,.pcapng,.cap,.dmp,.gz,.bz2,.xz,.zst,.pcap.gz,.pcapng.gz,application/vnd.tcpdump.pcap" aria-label="Choose a capture file">
      </div>
      <label class="opt"><input type="checkbox" id="noml"><span>Rules and baseline only<small>Skip the risk model and isolation forest</small></span></label>
      <button class="btn primary" id="go" type="submit" disabled>Analyse capture</button>
      <div class="or">or</div>
      <button class="btn" id="demo" type="button">${icon.play} Run the built-in demo capture</button>
      <div class="faint" style="font-size:12.5px;text-align:center">Captures are hashed, analysed and deleted. Reports keep metadata only.</div>
    </form>
  </section>
  <section style="margin-top:64px">
    <div class="section-head"><h2>Recent analyses</h2><span class="hint">Kept in memory · last 20</span></div>
    <div class="card" id="recent"><div class="empty">Loading…</div></div>
  </section>`;

  const drop = $("#drop"), file = $("#file"), go = $("#go");
  const pick = () => {
    const f = file.files[0];
    if (!f) return;
    drop.classList.add("has");
    $("#dropmsg").textContent = f.name;
    $("#dropsub").textContent = `${(f.size / 1048576).toFixed(2)} MB · ready`;
    go.disabled = false;
  };
  file.addEventListener("change", pick);
  ["dragenter", "dragover"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((e) => drop.addEventListener(e, () => drop.classList.remove("over")));
  drop.addEventListener("drop", (ev) => { ev.preventDefault(); if (ev.dataTransfer.files.length) { file.files = ev.dataTransfer.files; pick(); } });
  $("#upform").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!file.files[0]) return;
    const fd = new FormData();
    fd.append("file", file.files[0]);
    const q = $("#noml").checked ? "?ml=0" : "";      // read before the form is replaced
    runAnalysis(file.files[0].name, () => api(`/api/analyze${q}`, { method: "POST", body: fd }));
  });
  $("#demo").addEventListener("click", () => {
    const q = $("#noml").checked ? "?ml=0" : "";
    runAnalysis("demo_enterprise.pcap", () => api(`/api/demo${q}`, { method: "POST" }));
  });

  try {
    const list = await api("/api/reports");
    $("#recent").innerHTML = list.length ? list.map((r) => `
      <a class="recent-row" href="#/r/${esc(r.id)}">
        <span class="grade g-${esc(r.grade)}">${esc(r.grade)}</span>
        <span class="mono ellip">${esc(r.name)}</span>
        <span class="muted" style="font-size:14px">${r.sessions} sessions · <span style="color:var(--crit-ink)">${r.counts.critical} critical</span> · ${r.counts.high} high</span>
        <span class="mono faint" style="font-size:12.5px">${esc(shortHash(r.sha256))}</span>
        <span style="text-align:right;color:var(--accent);font-size:14px">Open report</span>
      </a>`).join("") : `<div class="empty">Nothing yet. Upload a capture, or run the built-in demo to see every detection in action.</div>`;
  } catch (e) {
    $("#recent").innerHTML = `<div class="empty">Could not load recent analyses: ${esc(e.message)}</div>`;
  }
}

function feat(path, title, body, delay) {
  return `<div class="feat reveal" style="animation-delay:${delay}s"><div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg></div><div><b>${esc(title)}</b><span>${esc(body)}</span></div></div>`;
}

// ------------------------------------------------------------------ analysis progress
const STAGES = [
  ["00–01", "Read the capture: PCAP/PCAPNG, link → IP → TCP", "read"],
  ["02", "Reassemble TCP streams (reorder, retransmit, overlap, wrap)", "reassembly"],
  ["03–04", "Identify protocols by banner · STARTTLS state machine", "protocol"],
  ["05–07", "Parse TLS handshakes · check certificates · apply rules", "crypto_rules"],
  ["08–09", "Feature vectors · per-endpoint baseline", "baseline"],
  ["10", "Risk model · isolation forest · explanations", "ml"],
  ["11", "Prioritise findings · posture score", "scoring"],
  ["12", "Render the report", null],
];

async function runAnalysis(name, request) {
  app.innerHTML = `
  <div class="progress-wrap">
    <div class="eyebrow">ANALYSING</div>
    <h1 class="mono" style="font-weight:500;font-size:26px;overflow-wrap:anywhere">${esc(name)}</h1>
    <p class="muted" style="margin:0">Passive analysis: nothing is sent to the network. The file is hashed first, for evidence integrity.</p>
    <ol class="stages">${STAGES.map((s, i) => `<li class="stage" id="st${i}"><span class="dot"></span><span class="num">${s[0]}</span><span>${esc(s[1])}</span><span class="t"></span></li>`).join("")}</ol>
  </div>`;
  let i = 0, done = false;
  const set = (k, cls) => { const el = $(`#st${k}`); if (el) el.className = `stage ${cls}`; };
  set(0, "run");
  const timer = setInterval(() => {                 // walk the stages while the server works
    if (done || i >= STAGES.length - 3) return;
    set(i, "done"); i += 1; set(i, "run");
  }, 420);
  teardown.push(() => clearInterval(timer));
  try {
    const rep = await request();
    done = true;
    clearInterval(timer);
    cache.set(rep.id, rep);
    const tm = rep.timings_seconds || {};
    for (let k = 0; k < STAGES.length; k++) {
      await new Promise((r) => setTimeout(r, REDUCED ? 0 : k < i ? 30 : 160));
      set(k, "done");
      const key = STAGES[k][2];
      $(`#st${k} .t`).textContent = key && tm[key] != null ? `${(tm[key] * 1000).toFixed(tm[key] < 0.01 ? 1 : 0)} ms` : "";
    }
    await new Promise((r) => setTimeout(r, REDUCED ? 0 : 500));
    location.hash = `#/r/${rep.id}`;
  } catch (e) {
    done = true;
    clearInterval(timer);
    set(i, "fail");
    $(`#st${i} .t`).textContent = "failed";
    app.insertAdjacentHTML("beforeend", `<div class="progress-wrap"><div class="card card-pad" style="border-color:var(--crit-line)"><b style="color:var(--crit-ink)">Analysis failed.</b> <span class="muted">${esc(e.message)}</span><div style="margin-top:14px"><a class="btn" href="#/">Back</a></div></div></div>`);
  }
}

// ================================================================== REPORT
function classify(r) {
  const s = r.session, d = r.baseline_deviations || [];
  if (s.strip_indicators.length) return { kind: "bad", label: "STARTTLS stripped" };
  if (s.injection_indicators.length) return { kind: "bad", label: "Command injection" };
  if (d.includes("cert_change")) return { kind: "bad", label: "Certificate swapped" };
  if (d.includes("downgrade")) return { kind: "bad", label: "Downgraded" };
  if (r.tls && r.tls.server_hello_seen) return { kind: "tls", label: r.tls.version_name };
  return { kind: "clear", label: "Cleartext" };
}

// ------------------------------------------------------------------ report shell: sidebar + one section at a time
const TABS = [
  ["overview", "Overview", '<rect x="4" y="4" width="7" height="9" rx="1.5"/><rect x="13" y="4" width="7" height="5" rx="1.5"/><rect x="13" y="11" width="7" height="9" rx="1.5"/><rect x="4" y="15" width="7" height="5" rx="1.5"/>'],
  ["wire", "Wire replay", '<circle cx="5" cy="6" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="12" r="2"/><path d="M7 6.8 17 11.2M7 17.2l10-4.4"/>'],
  ["findings", "Findings", '<path d="M12 3 2 21h20z"/><path d="M12 10v5M12 18v.5"/>'],
  ["certs", "Certificates", '<path d="M12 3 4 6v5.5c0 4.4 3.2 8.2 8 9.5 4.8-1.3 8-5.1 8-9.5V6z"/><path d="m9 11.8 2.1 2.2L15 10"/>'],
  ["capture", "Capture", '<path d="M4 5h16v14H4z"/><path d="M4 9.5h16M4 14.5h16M9 5v14"/>'],
  ["endpoints", "Endpoints", '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>'],
  ["sessions", "Sessions", '<path d="M4 6h16M4 12h16M4 18h10"/>'],
  ["about", "How it scores", '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.4"/>'],
];

function shell(rep, id, active, inner, sid) {
  const p = rep.posture;
  const counts = { findings: rep.findings.filter((f) => f.severity !== "info").length, sessions: rep.sessions.length, endpoints: Object.keys(p.endpoints).length, certs: collectCerts(rep).certs.length,
    capture: (rep.packets || []).length };
  const sess = [...rep.sessions].sort((a, b) => a.session.start_ts - b.session.start_ts);
  return `<div class="shell">
    <aside class="sidenav" aria-label="Report navigation">
      <a class="side-rep g-${esc(p.grade)}" href="#/r/${esc(id)}/overview">
        <span class="grade g-${esc(p.grade)}">${esc(p.grade)}</span>
        <span style="min-width:0"><span class="mono ellip" style="display:block;font-size:13px">${esc(rep.meta.input)}</span><span class="faint" style="font-size:12px">${p.score == null ? "not assessed" : `${p.score}/100`} · ${p.sessions} sessions</span></span>
      </a>
      <nav class="side-links" aria-label="Report sections">${TABS.map(([k, label, ic]) => `
        <a href="#/r/${esc(id)}/${k}" data-sec="${k}" class="${active === k ? "on" : ""}"${active === k ? ' aria-current="page"' : ""}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ic}</svg>
          <span>${label}</span>${counts[k] != null ? `<span class="cnt${(k === "findings" && p.counts.critical) || (k === "certs" && certsFailing(rep)) ? " hot" : ""}">${counts[k]}</span>` : ""}
        </a>`).join("")}</nav>
      <div class="side-sess">
        <div class="side-h">Replay a session</div>
        ${sess.map((r) => { const c = classify(r); return `<a href="#/r/${esc(id)}/s/${esc(r.session.session_id)}" class="${sid === r.session.session_id ? "on" : ""}" title="${esc(r.session.endpoint)} · ${esc(c.label)}"><i class="dot d-${c.kind}"></i><span class="mono">${esc(r.session.session_id)}</span><span class="ellip faint">${esc(r.session.endpoint)}</span></a>`; }).join("")}
      </div>
      <div class="side-foot"><a href="/report/${esc(id)}.json">JSON</a> · <a href="/report/${esc(id)}" target="_blank" rel="noopener">HTML report</a> · <a href="#/">New analysis</a></div>
    </aside>
    <div class="pane">${inner}</div>
  </div>`;
}

function pageHead(title, sub, extra = "") {
  return `<header class="page-h reveal"><div style="min-width:0"><h1>${title}</h1>${sub ? `<div class="meta" style="margin-top:6px">${sub}</div>` : ""}</div>${extra}</header>`;
}

async function viewReport(id, tab) {
  app.innerHTML = `<div class="empty">Loading report…</div>`;
  let rep;
  try { rep = await getReport(id); } catch (e) {
    app.innerHTML = `<div class="empty">That report is no longer in memory (the server keeps the last 20). <a href="#/">Start a new analysis</a>.</div>`;
    return;
  }
  const tabs = { overview: tabOverview, wire: tabWire, findings: tabFindings, certs: tabCerts,
                 capture: tabCapture, endpoints: tabEndpoints, sessions: tabSessions,
                 about: tabAbout };
  const key = tabs[tab] ? tab : "overview";
  document.title = `${TABS.find((t) => t[0] === key)[1]} · ${rep.meta.input} · SecureMailScope`;
  app.innerHTML = shell(rep, id, key, tabs[key].html(rep, id));
  if (tabs[key].init) tabs[key].init(rep, id);
}

const tabOverview = {
  html(rep, id) {
    const m = rep.meta, p = rep.posture;
    if (p.assessed === false) {
      // A capture with no mail in it is not a clean capture. Say so, rather than
      // drawing an empty ring that reads as a pass.
      return `${pageHead(`<span class="mono" style="font-weight:500;font-size:26px">${esc(m.input)}</span>`,
        `<span>${m.read.frames} frames · ${m.flows} TCP flows read successfully</span><span class="mono faint">sha256 ${esc(shortHash(m.input_sha256))}</span>`, "")}
      <div class="card card-pad" style="border-left:4px solid var(--med)">
        <b style="font-size:17px">Nothing to assess</b>
        <p class="muted" style="margin:8px 0 0">${esc(p.note || "No mail session could be parsed.")}</p>
        ${(m.unclassified_mail_flows || []).length ? `<div class="caveats" style="margin:14px 0 0">
          <div class="caveat c-partial"><span class="cv-ic">!</span><span>
          ${m.unclassified_mail_flows.length} flow(s) on a mail port were present but could not be classified:
          ${esc(m.unclassified_mail_flows.slice(0, 3).map((u) =>
            `${u.client} → ${u.server} (${u.client_bytes}/${u.server_bytes} bytes, ${u.reason})`).join("; "))}
          </span></div></div>` : ""}
        <p class="faint" style="margin:10px 0 0;font-size:13.5px">The capture parsed cleanly — this is not a read error.
        SecureMailScope only grades SMTP, IMAP and POP3, so a capture of other traffic has no transport posture to report.
        An absence of findings here means an absence of evidence, not a clean bill of health.</p>
        <div style="margin-top:16px"><a class="btn" href="#/">Analyse another capture</a></div>
      </div>`;
    }
    const total = SEVS.reduce((n, s) => n + p.counts[s], 0);
    // Caveats that bound what the rest of the page is claiming. A report over a
    // partially-read file, or one whose grade was capped rather than earned,
    // has to say so where the grade is, not only in the JSON.
    const caveats = [];
    (m.read.notes || []).forEach((n) => caveats.push(["read", n]));
    (p.floors || []).forEach((f, i) => caveats.push([
      f.binding ? "floor" : "floor-soft",
      (p.floor_reasons || [])[i] || f.reason,
    ]));
    const oneSided = rep.sessions.filter((r) => r.session.identified_by === "client-verbs").length;
    if (oneSided) caveats.push(["partial",
      `${oneSided} session${oneSided === 1 ? " was" : "s were"} identified from the client's commands only — ` +
      "the server side was missing or unrecognised, so STARTTLS negotiation could not be evaluated for them"]);
    const unclassified = (m.unclassified_mail_flows || []).length;
    if (unclassified) caveats.push(["partial",
      `${unclassified} flow${unclassified === 1 ? "" : "s"} on a mail port could not be classified and ` +
      "were not analysed"]);
    const caveatHtml = caveats.length ? `<div class="caveats reveal">${caveats.map(([kind, text]) =>
      `<div class="caveat c-${kind}"><span class="cv-ic">${kind.startsWith("floor") ? "!" : "i"}</span><span>${esc(text)}</span></div>`
      ).join("")}</div>` : "";
    const exposed = rep.sessions.filter((r) => r.session.auth_events.some((a) => a.secret_exposed)).length;
    const usedTls = rep.sessions.filter((r) => r.tls && r.tls.server_hello_seen).length;
    const attacked = rep.sessions.filter((r) => classify(r).kind === "bad").length;
    const top = groupFindings(rep.findings).filter((g) => g.f.severity === "critical" || g.f.severity === "high").slice(0, 4);
    const verdict = attacked ? "Active interference detected" : p.counts.critical ? "Critical exposure" : p.grade <= "B" ? "Mail transport is well protected" : "Weak transport security";
    return `${pageHead(`<span class="mono" style="font-weight:500;font-size:26px">${esc(m.input)}</span>`,
      `<span>Captured ${esc(m.capture_start.replace("T", " ").slice(0, 16))}–${esc(m.capture_end.slice(11, 16))} UTC</span><span>${m.read.frames} frames · ${m.flows} flows · ${m.mail_sessions} mail sessions</span><span>Analysed in ${(rep.timings_seconds.total || 0).toFixed(2)} s</span><span class="mono faint">sha256 ${esc(shortHash(m.input_sha256))}</span>`,
      `<div class="actions"><a class="btn" href="/report/${esc(id)}.json">${icon.down} JSON</a><a class="btn primary" href="/report/${esc(id)}" target="_blank" rel="noopener">${icon.down} HTML report</a></div>`)}
    ${caveatHtml}
    <div class="stack" style="gap:20px">
      <section class="summary">
        <div class="card posture reveal g-${esc(p.grade)}">
          <div class="ring" id="ring">
            <svg width="132" height="132" viewBox="0 0 132 132" aria-hidden="true"><circle cx="66" cy="66" r="56" fill="none" stroke="var(--line)" stroke-width="10"/><circle class="val" id="ringval" cx="66" cy="66" r="56" fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="351.9" stroke-dashoffset="351.9"/></svg>
            <div class="in"><span class="g" id="grade">${esc(p.grade)}</span><span class="sc"><span id="score">0</span> / 100</span></div>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <div class="muted" style="font-size:13px">Transport posture</div>
            <div style="font-family:var(--display);font-size:22px;font-weight:600;line-height:1.2">${esc(verdict)}</div>
            <div class="faint" style="font-size:13px">${(() => {
            const bind = (p.floors || []).find((f) => f.binding);
            if (bind) return `Capped at ${esc(bind.grade)}: ${esc(bind.reason)}. Penalties alone gave ${p.earned_score}.`;
            return `${p.unique_issues} distinct issues, scored on their own weight.`;
          })()}</div>
          </div>
        </div>
        <div class="card stats reveal" style="animation-delay:.06s">
          <div class="nums">
            <div class="num t-info"><b data-count="${p.sessions}">0</b><span>mail sessions</span></div>
            <div class="num ${usedTls === p.sessions ? "t-good" : "t-warn"}"><b><span data-count="${usedTls}">0</span><span style="font-size:18px;color:var(--faint)">/${p.sessions}</span></b><span>used TLS</span></div>
            <div class="num ${attacked ? "t-bad" : "t-good"}"><b data-count="${attacked}">0</b><span>sessions attacked</span></div>
            <div class="num ${exposed ? "t-bad" : "t-good"}"><b data-count="${exposed}">0</b><span>leaked a password</span></div>
            <div class="num ${p.counts.critical ? "t-bad" : p.unique_issues ? "t-warn" : "t-good"}"><b data-count="${p.unique_issues}">0</b><span>distinct issues</span></div>
          </div>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div class="sevbar" role="img" aria-label="${total} findings: ${SEVS.map((s) => `${p.counts[s]} ${s}`).join(", ")}">${SEVS.map((s) => `<div class="b-${s}" data-w="${total ? (100 * p.counts[s]) / total : 0}"></div>`).join("")}</div>
            <div class="legend">${SEVS.map((s) => `<span><i class="b-${s}"></i>${SEV_LABEL[s]} <b>${p.counts[s]}</b></span>`).join("")}</div>
          </div>
        </div>
      </section>
      <section class="ov-grid">
        <div style="min-width:0">
          <div class="section-head"><h2>Act on these first</h2><a href="#/r/${esc(id)}/findings" style="font-size:13px">All ${rep.findings.filter((f) => f.severity !== "info").length} findings →</a></div>
          <div class="find-list">${top.length ? top.map((g, i) => findRow(g, i, id)).join("") : `<div class="empty">No critical or high findings.</div>`}</div>
        </div>
        <a class="card cta reveal" style="animation-delay:.12s" href="#/r/${esc(id)}/wire">
          <div class="cta-art" aria-hidden="true">${miniWire(rep)}</div>
          <div><b>Watch the wire replay</b><span>All ${rep.sessions.length} sessions play back as live traffic: ${usedTls} sealed, ${attacked} attacked.</span></div>
          <span class="btn primary" style="align-self:flex-start">${icon.play} Play the capture</span>
        </a>
      </section>
    </div>`;
  },
  init(rep) {
    const p = rep.posture;
    if (p.assessed === false) return;
    afterPaint(() => {
      const ringval = $("#ringval");
      ringval.style.stroke = p.score >= 80 ? C.accent : p.score >= 60 ? C.clear : C.bad;
      // A score of 0 draws nothing: a round line-cap on a near-zero arc reads as a
      // stray dot, not as "zero".
      ringval.style.opacity = p.score > 0 ? "1" : "0";
      ringval.style.strokeDashoffset = String(351.9 * (1 - Math.max(p.score, 0) / 100));
      $("#ring").classList.add("on");
      countUp($("#score"), p.score, 1400);
      $$("[data-count]").forEach((el) => countUp(el, +el.dataset.count));
      $$(".sevbar > div").forEach((el, i) => setTimeout(() => (el.style.width = `${el.dataset.w}%`), 120 * i));
      $$(".find [data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`));
    });
    $("#grade").style.color = p.grade === "A" ? "var(--accent-ink)" : p.grade === "F" ? "var(--crit-ink)" : p.grade === "B" ? "var(--good-ink)" : "var(--med-ink)";
  },
};

function findRow(g, i, id) {
  return `<a class="find reveal" data-sev="${esc(g.f.severity)}" style="animation-delay:${0.05 * i}s" href="#/r/${esc(id)}/s/${esc(g.f.session_id)}">
    <span class="rank">${String(i + 1).padStart(2, "0")}</span>
    <span>${sevChip(g.f.severity)}</span>
    <span style="min-width:0"><span class="title">${esc(g.f.title.replace(/ \(deviates from endpoint baseline.*\)$/, ""))}</span>${g.f.escalated_from ? `<span class="esc">escalated from ${esc(g.f.escalated_from)}</span>` : ""}
      <div class="sub ellip"><span class="mono" style="color:var(--text)">${esc(g.f.endpoint)}</span> · ${esc(g.f.evidence[0] || "")}</div></span>
    <span class="risk"><span class="bar"><span data-w="${g.f.risk}" style="background:${SEV_COLOR[g.f.severity]}"></span></span>${Math.round(g.f.risk)}</span>
  </a>`;
}

function miniWire(rep) {
  const ss = [...rep.sessions].sort((a, b) => a.session.start_ts - b.session.start_ts);
  const n = ss.length || 1;
  return `<svg viewBox="0 0 300 120" width="100%" height="120">${ss.map((r, i) => {
    const k = classify(r).kind, y1 = 10 + (i * 100) / n, y2 = 20 + ((i * 37) % n) * (80 / n);
    const col = k === "tls" ? C.accent : k === "clear" ? C.clear : C.bad;
    return `<path d="M 20 ${y1.toFixed(1)} Q 150 ${((y1 + y2) / 2 + ((i % 5) - 2) * 6).toFixed(1)} 280 ${y2.toFixed(1)}" fill="none" stroke="${col}" stroke-width="1.6" stroke-dasharray="400" stroke-dashoffset="400" opacity="${k === "bad" ? 1 : 0.55}"><animate attributeName="stroke-dashoffset" from="400" to="0" dur="${(1.2 + (i % 4) * 0.3).toFixed(1)}s" begin="${(i * 0.12).toFixed(2)}s" fill="freeze"/></path>`;
  }).join("")}</svg>`;
}

const tabWire = {
  html(rep) {
    const n = (k) => rep.sessions.filter((r) => classify(r).kind === k).length;
    return `${pageHead("Wire replay", `<span>Every session in the capture, in the order it happened. Click a link or a feed item to replay its handshake.</span>`,
      `<div class="legend"><span><i style="background:${C.accent}"></i>sealed <b>${n("tls")}</b></span><span><i style="background:${C.clear}"></i>cleartext <b>${n("clear")}</b></span><span><i style="background:${C.bad}"></i>attacked <b>${n("bad")}</b></span></div>`)}
    <section class="card wire reveal" aria-label="Wire replay">
      <div class="wire-top">
        <span class="clock" id="clock" style="text-align:left;margin-right:auto">—</span>
        <button class="btn icon" id="wplay" aria-label="Pause">${icon.pause}</button>
        <button class="btn icon" id="wrestart" aria-label="Restart replay">${icon.restart}</button>
        <label class="sr" for="wspeed">Replay speed</label>
        <select class="speed" id="wspeed"><option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option></select>
      </div>
      <div class="wire-body">
        <div class="wire-stage" id="wstage"></div>
        <div class="wire-feed" id="wfeed" aria-live="polite"><div class="faint" style="font-size:13px">Sessions appear here as they complete.</div></div>
      </div>
      <div style="padding:0 20px"><label class="sr" for="wscrub">Replay position</label><input type="range" class="scrub" id="wscrub" min="0" max="1000" value="0"></div>
      <div class="wire-foot">
        <span class="k"><span class="ln" style="background:${C.accent}"></span>TLS sealed</span>
        <span class="k"><span class="ln" style="background:${C.clear}"></span>cleartext</span>
        <span class="k"><span class="ln" style="background:${C.bad}"></span>stripped, injected, swapped or downgraded</span>
        <span class="tally" id="tally"></span>
      </div>
    </section>`;
  },
  init(rep, id) {
    const sim = new WireSim(rep, id);
    teardown.push(() => sim.destroy());
  },
};

const tabFindings = {
  html(rep, id) {
    const p = rep.posture;
    return `${pageHead("Findings", `<span>${rep.findings.length} findings grouped by rule and endpoint, ranked by risk. Each has evidence, a fix and a compliance mapping.</span>`)}
    <section class="card reveal" style="overflow:hidden">
      <div class="filters" role="group" aria-label="Filter findings">
        ${SEVS.map((s) => `<button type="button" class="fchip" aria-pressed="true" data-sev="${s}"><i class="b-${s}" style="width:8px;height:8px;border-radius:2px;display:inline-block"></i>${SEV_LABEL[s]} ${p.counts[s]}</button>`).join("")}
        <label class="search"><span class="sr">Search findings</span><input type="search" id="fq" placeholder="Search endpoint, rule, evidence…"></label>
      </div>
      <div id="flist" class="fill">${groupFindings(rep.findings).map((g) => findingDetails(g, id)).join("")}</div>
    </section>`;
  },
  init() {
    const active = new Set(SEVS);
    const apply = () => {
      const q = $("#fq").value.trim().toLowerCase();
      $$("#flist details").forEach((d) => { d.style.display = active.has(d.dataset.sev) && (!q || d.textContent.toLowerCase().includes(q)) ? "" : "none"; });
    };
    $$(".fchip").forEach((b) => b.addEventListener("click", () => {
      const on = b.getAttribute("aria-pressed") !== "true";
      b.setAttribute("aria-pressed", String(on));
      on ? active.add(b.dataset.sev) : active.delete(b.dataset.sev);
      apply();
    }));
    $("#fq").addEventListener("input", apply);
  },
};

// ------------------------------------------------------------------ capture (packet list)
//
// The whole PCAP, one row per TCP segment, with the session each frame belongs
// to. Every frame number here is the same identity the replay steps point at,
// which is what makes "this protocol step is these packets" navigable in both
// directions.

const pktDirCls = (rep, row) => {
  const s = row.session && rep.sessions.find((x) => x.session.session_id === row.session);
  if (!s) return "";
  return `${row.src}:${row.sport}` === `${s.session.client[0]}:${s.session.client[1]}` ? "c2s" : "s2c";
};

// Time base. Seconds-since-first-frame is the natural reading for a single
// capture, but merged corpora (the Ultimate PCAP, anything built with mergecap)
// span years, and "37032:36:16.9" tells nobody anything. Long captures default
// to wall clock instead, and the header offers the other reading either way.
function relTime(dt) {
  if (!isFinite(dt)) return "—";
  if (dt < 600) return dt.toFixed(3);
  const h = Math.floor(dt / 3600), m = Math.floor((dt % 3600) / 60), sec = dt % 60;
  const mm = String(m).padStart(2, "0"), ss = sec.toFixed(1).padStart(4, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

const absTime = (ts) => new Date(ts * 1000).toISOString().slice(11, 23).replace("T", " ");
const absDate = (ts) => new Date(ts * 1000).toISOString().slice(0, 19).replace("T", " ");

function packetTime(row, opts) {
  return opts.absolute ? absTime(row.ts) : relTime(row.ts - (opts.t0 ?? row.ts));
}

function packetRowHtml(rep, row, id, opts = {}) {
  const dir = pktDirCls(rep, row);
  const href = row.session && !opts.noLink ? ` href="#/r/${esc(id)}/s/${esc(row.session)}"` : "";
  const tag = href ? "a" : "div";
  const t = packetTime(row, opts);
  return `<${tag}${href} class="pk-row ${dir}${opts.compact ? " compact" : ""}" data-frame="${row.frame}" data-session="${esc(row.session || "")}">
    <span class="mono pk-n">${row.frame}</span>
    <span class="mono pk-t" title="${esc(absDate(row.ts))} UTC">${esc(t)}</span>
    ${opts.compact ? "" : `<span class="mono pk-ep pk-src">${esc(row.src)}:${row.sport}</span>
    <span class="pk-arrow">${dir === "s2c" ? "←" : "→"}</span>
    <span class="mono pk-ep pk-dst">${esc(row.dst)}:${row.dport}</span>
    <span class="pk-proto"><span class="ptag p-${esc((row.proto || "TCP").toLowerCase())}">${esc(row.proto || "TCP")}</span></span>
    <span class="mono pk-port">${row.port ?? ""}</span>`}
    <span class="mono pk-flags">${esc(row.flags)}</span>
    <span class="mono pk-len">${row.len || ""}</span>
    <span class="ellip pk-info mono">${esc(row.info)}</span>
    ${opts.compact ? "" : `<span class="mono pk-sess">${esc(row.session || "—")}</span>`}
  </${tag}>`;
}

const tabCapture = {
  html(rep, id) {
    const rows = rep.packets || [];
    if (!rows.length) {
      return `${pageHead("Capture", "<span>This report was produced before the packet table existed.</span>")}
        <div class="empty card">No packet rows in this report — re-run the analysis to populate them.</div>`;
    }
    const t0 = rows[0].ts;
    const span = rows[rows.length - 1].ts - t0;
    const absolute = span > 86400;          // merged captures read better on the clock
    const m = rep.meta;
    const withPayload = rows.filter((r) => r.len).length;
    const sessions = new Set(rows.map((r) => r.session).filter(Boolean));
    const spanLabel = span > 86400 ? `${(span / 86400).toFixed(0)} days` :
      span > 3600 ? `${(span / 3600).toFixed(1)} hours` : `${span.toFixed(1)} s`;
    return `${pageHead("Capture", `<span>${rows.length.toLocaleString()} TCP segments${m.packet_rows_truncated ? ` (first ${rows.length.toLocaleString()} of ${m.read.tcp_segments.toLocaleString()})` : ""}</span><span>${withPayload.toLocaleString()} carry data</span><span>${sessions.size} mail sessions</span><span>spans ${esc(spanLabel)}</span><span class="mono faint">sha256 ${esc(shortHash(m.input_sha256))}</span>`,
      `<div class="actions"><a class="btn" href="/report/${esc(id)}.json">${icon.down} JSON</a></div>`)}
    <section class="card pk-card reveal" style="overflow:hidden">
      <div class="filters">
        <button class="fchip" data-pf="all" aria-pressed="true">All</button>
        <button class="fchip" data-pf="data" aria-pressed="false">With payload</button>
        <button class="fchip" data-pf="tls" aria-pressed="false">TLS records</button>
        <button class="fchip" data-pf="clear" aria-pressed="false">Cleartext protocol</button>
        <button class="fchip" data-pf="mail" aria-pressed="false">Mail commands</button>
        <button class="fchip" id="tbase" data-abs="${absolute ? 1 : 0}" aria-pressed="${absolute}"
          title="Switch between seconds since the first frame and wall-clock UTC">${absolute ? "UTC clock" : "Relative time"}</button>
        <label class="search"><span class="sr">Filter packets</span>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/></svg>
          <input id="pksearch" type="search" placeholder="address, port, session or text"></label>
      </div>
      <div class="trow head pk-row"><span>#</span><span id="thead">${absolute ? "TIME UTC" : "TIME"}</span><span class="pk-src">SOURCE</span><span class="pk-arrow"></span><span class="pk-dst">DESTINATION</span><span>PROTO</span><span class="pk-port">PORT</span><span class="pk-flags">FLAGS</span><span class="pk-len">LEN</span><span>INFO</span><span class="pk-sess">SESSION</span></div>
      <div class="tscroll fill" id="pklist">${rows.map((r) => packetRowHtml(rep, r, id, { t0, absolute })).join("")}</div>
      <div class="pk-foot faint" id="pkfoot">${rows.length.toLocaleString()} of ${rows.length.toLocaleString()} shown · times are seconds from the first frame · click a row to open its session</div>
    </section>`;
  },
  init(rep) {
    const list = $("#pklist"), foot = $("#pkfoot"), search = $("#pksearch");
    if (!list) return;
    const all = $$(".pk-row", list);
    let mode = "all", q = "";
    const apply = () => {
      let n = 0;
      all.forEach((el) => {
        const info = (el.querySelector(".pk-info")?.textContent || "");
        const len = +(el.querySelector(".pk-len")?.textContent || 0);
        const proto = (el.querySelector(".ptag")?.textContent || "").trim();
        let ok = mode === "all"
          || (mode === "data" && len > 0)
          || (mode === "tls" && proto === "TLS")
          || (mode === "mail" && ["SMTP", "IMAP", "POP3"].includes(proto))
          || (mode === "clear" && len > 0 && proto !== "TLS" && !/bytes of data$/.test(info));
        if (ok && q) ok = el.textContent.toLowerCase().includes(q);
        el.hidden = !ok;
        if (ok) n += 1;
      });
      foot.textContent = `${n.toLocaleString()} of ${all.length.toLocaleString()} shown · times are seconds from the first frame · click a row to open its session`;
    };
    $$(".fchip[data-pf]").forEach((b) => b.addEventListener("click", () => {
      mode = b.dataset.pf;
      $$(".fchip[data-pf]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      apply();
    }));
    const tbase = $("#tbase");
    if (tbase) {
      const rows = rep.packets || [];
      const t0 = rows.length ? rows[0].ts : 0;
      tbase.addEventListener("click", () => {
        const abs = tbase.dataset.abs !== "1";
        tbase.dataset.abs = abs ? "1" : "0";
        tbase.setAttribute("aria-pressed", String(abs));
        tbase.textContent = abs ? "UTC clock" : "Relative time";
        $("#thead").textContent = abs ? "TIME UTC" : "TIME";
        const byFrame = new Map(rows.map((r) => [r.frame, r]));
        all.forEach((el) => {
          const row = byFrame.get(+el.dataset.frame);
          if (row) el.querySelector(".pk-t").textContent = packetTime(row, { t0, absolute: abs });
        });
      });
    }
    search.addEventListener("input", () => { q = search.value.trim().toLowerCase(); apply(); });
    // Deep link: #/r/<id>/capture?f=42 scrolls to and flashes frame 42.
    const want = (location.hash.split("?")[1] || "").match(/(?:^|&)f=(\d+)/);
    if (want) {
      const el = list.querySelector(`.pk-row[data-frame="${want[1]}"]`);
      if (el) afterPaint(() => { el.classList.add("hit"); el.scrollIntoView({ block: "center" }); });
    }
  },
};

// ------------------------------------------------------------------ how it scores
//
// Rendered from the `scoring` block the analyser emits with every report, not
// from constants restated here: change a penalty in scoring.py and this page
// changes with it. A score nobody can audit is a score nobody should act on.

const SEV_ROWS = ["critical", "high", "medium", "low", "info"];

function scoreBar(v, max, colour) {
  return `<span class="bar" style="width:100%"><span data-w="${(100 * v) / (max || 1)}" style="background:${colour}"></span></span>`;
}

const tabAbout = {
  html(rep, id) {
    const sc = rep.scoring;
    if (!sc) {
      return `${pageHead("How it scores", "<span>This report predates the scoring reference.</span>")}
        <div class="empty card">Re-run the analysis to include it.</div>`;
    }
    const p = rep.posture;
    const maxPen = Math.max(...Object.values(sc.penalty));

    const sevTable = SEV_ROWS.map((k) => `<div class="trow ab-sev">
      <span>${sevChip(k)}</span>
      <span class="mono">${sc.severity_weight[k].toFixed(2)}</span>
      <span class="mono">−${sc.penalty[k]}</span>
      <span>${scoreBar(sc.penalty[k], maxPen, SEV_COLOR[k])}</span>
      <span class="mono" style="text-align:right">${p.counts[k]}</span>
    </div>`).join("");

    const grades = sc.grades.map((g, i) => {
      const hi = i === 0 ? 100 : sc.grades[i - 1].min - 1;
      const on = p.grade === g.grade;
      return `<div class="gband${on ? " on" : ""}">
        <span class="grade g-${esc(g.grade)}">${esc(g.grade)}</span>
        <span class="mono">${g.min}–${hi}</span>
        ${on ? `<span class="faint">this capture${p.score == null ? "" : ` · ${p.score}`}</span>` : ""}
      </div>`;
    }).join("");

    const exposure = Object.entries(sc.exposure).map(([k, v]) =>
      `<div class="xrow"><span class="muted">${esc(k)}</span>
       <span class="track"><span data-w="${v * 100}" style="left:0;background:${C.accent}"></span></span>
       <span class="mono" style="text-align:right">${v.toFixed(2)}</span></div>`).join("");

    const formulas = sc.formulas.map((f) => `<div class="formula">
      <b>${esc(f.name)}</b>
      <code class="fexpr">${esc(f.expr)}</code>
      <p class="muted">${esc(f.note)}</p>
    </div>`).join("");

    const fired = new Set(rep.findings.map((f) => f.rule_id));
    const ruleRows = sc.rules.map((r) => {
      const n = rep.findings.filter((f) => f.rule_id === r.id).length;
      return `<div class="trow ab-rule${n ? " fired" : ""}">
        <span class="mono">${esc(r.id)}</span>
        <span>${esc(r.title)}</span>
        <span class="faint">${esc(r.severity)}</span>
        <span class="mono" style="text-align:right">${n || ""}</span>
      </div>`;
    }).join("");

    const notScored = sc.not_scored.map((t) => `<li>${esc(t)}</li>`).join("");
    const feats = sc.features.map((f) => `<span class="fchipx mono">${esc(f)}</span>`).join("");

    return `${pageHead("How it scores", `<span>Every parameter below is read from this report, not from documentation</span><span>${sc.rules.length} rules · ${sc.features.length} features · ${fired.size} rules fired here</span>`)}
    <div class="stack" style="gap:22px">

      <section class="ab-grid">
        <div class="card card-pad reveal">
          <h2>Severity and its price</h2>
          <p class="muted ab-lead">Severity is intrinsic to a finding. The weight drives session risk;
          the penalty drives the capture's posture score. They are separate numbers because one answers
          "how bad is this kind of problem" and the other "how much should the whole capture suffer for it".</p>
          <div class="trow head ab-sev"><span>SEVERITY</span><span>WEIGHT</span><span>PENALTY</span><span></span><span style="text-align:right">HERE</span></div>
          ${sevTable}
        </div>
        <div class="card card-pad reveal">
          <h2>Grade bands</h2>
          <p class="muted ab-lead">Some facts bound a grade instead of being averaged into it. Floors are
          evaluated together and only the strictest one applies, so a capture never reports a cap that did
          not decide its grade; a floor above the score the penalties already earned is not reported at all.</p>
          <div class="ab-list" style="margin-bottom:14px">
            <div>Any critical finding &rarr; caps at <b>F</b></div>
            <div>Message content crossed unencrypted &rarr; caps at <b>D</b></div>
            <div>A TLS session with no observable certificate &rarr; caps at <b>A</b></div>
          </div>
          <div class="gbands">${grades}</div>
        </div>
      </section>

      <section class="card card-pad reveal">
        <h2>The formulas</h2>
        <div class="formulas">${formulas}</div>
      </section>

      <section class="ab-grid">
        <div class="card card-pad reveal">
          <h2>Exposure by port class</h2>
          <p class="muted ab-lead">${esc(sc.exposure_note)}</p>
          <div style="display:flex;flex-direction:column;gap:12px">${exposure}</div>
        </div>
        <div class="card card-pad reveal">
          <h2>What is deliberately not scored</h2>
          <p class="muted ab-lead">A measurement tool that overstates its reach is the problem it was
          built to expose. These are reported as unknown and never guessed.</p>
          <ul class="ab-list">${notScored}</ul>
        </div>
      </section>

      <section class="card reveal" style="overflow:hidden">
        <div class="filters">
          <h2 style="margin-right:auto">Rule catalogue</h2>
          <button class="fchip" data-rf="all" aria-pressed="true">All ${sc.rules.length}</button>
          <button class="fchip" data-rf="fired" aria-pressed="false">Fired here ${fired.size}</button>
        </div>
        <div class="trow head ab-rule"><span>ID</span><span>WHAT IT DETECTS</span><span>SEVERITY</span><span style="text-align:right">HERE</span></div>
        <div id="rulelist">${ruleRows}</div>
      </section>

      <section class="card card-pad reveal">
        <h2>Model features</h2>
        <p class="muted ab-lead">The ${sc.features.length} values describing each session to the risk model
        and the isolation forest. ${rep.ml && rep.ml.enabled
          ? `Model: <code>${esc(rep.ml.model || "—")}</code>${rep.ml.holdout_r2 != null ? ` · held-out R² ${rep.ml.holdout_r2.toFixed(3)}` : ""}${rep.ml.explainer ? ` · ${esc(rep.ml.explainer)}` : ""}.`
          : "The model was skipped for this analysis: the scores above are rules and baseline only."}</p>
        <div class="fchips">${feats}</div>
      </section>
    </div>`;
  },
  init() {
    afterPaint(() => $$("[data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`)));
    const list = $("#rulelist");
    if (!list) return;
    $$(".fchip[data-rf]").forEach((b) => b.addEventListener("click", () => {
      const only = b.dataset.rf === "fired";
      $$(".fchip[data-rf]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      $$(".ab-rule", list).forEach((el) => { el.hidden = only && !el.classList.contains("fired"); });
    }));
  },
};

const tabEndpoints = {
  html(rep) {
    return `${pageHead("Endpoints", `<span>${Object.keys(rep.posture.endpoints).length} mail servers, worst first. Keyed by server IP:port, never by the banner an attacker can forge.</span>`)}
    <section class="twocol">
      <div class="card reveal" style="overflow:hidden">
        <div class="tscroll fill">
          <div class="trow head ep-row"><span>GRADE</span><span>ENDPOINT</span><span>CHANNEL</span><span>SESSIONS</span><span>ISSUES</span></div>
          ${endpointRows(rep)}
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:20px" class="reveal">
        ${protocolCard(rep)}
        ${channelCard(rep)}
        ${versionCard(rep)}
      </div>
    </section>`;
  },
  init() { afterPaint(() => $$(".hbar [data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`))); },
};

// ------------------------------------------------------------------ certificates
//
// One row per DISTINCT certificate (deduplicated by SHA-256), not per session:
// the same leaf usually appears in every session to an endpoint, and the thing
// an analyst rotates or replaces is the certificate, not the session.

function cnOf(dn) {
  const m = String(dn || "").match(/(?:^|,)\s*CN=((?:[^,\\]|\\.)*)/);
  return m ? m[1].replace(/\\(.)/g, "$1") : String(dn || "—");
}

// Every distinct certificate the capture contains, deduplicated by SHA-256 —
// leaves AND the intermediates and roots servers sent alongside them. An
// intermediate signed with SHA-1, or a root a server should not be sending at
// all, is a real finding, and listing it only inside an expanded chain meant
// nobody would see it.
const CERT_ROLES = ["leaf", "intermediate", "root"];

function collectCerts(rep) {
  const map = new Map();
  const unobservable = [];
  for (const r of rep.sessions) {
    const ch = r.certificate_chain;
    if (!ch) continue;
    if (!ch.present || !ch.certs || !ch.certs.length) {
      if (ch.reason_absent) unobservable.push({ r, reason: ch.reason_absent, kind: ch.absent_kind });
      continue;
    }
    ch.certs.forEach((cert, i) => {
      const role = i === 0 ? "leaf" : (cert.self_signed ? "root" : "intermediate");
      if (!map.has(cert.sha256)) {
        map.set(cert.sha256, {
          leaf: cert, role, chain: ch.certs, sessions: [], endpoints: new Set(), checks: [],
        });
      }
      const entry = map.get(cert.sha256);
      // A certificate can appear as a leaf in one chain and an intermediate in
      // another (cross-signing); the more privileged role wins for display.
      if (CERT_ROLES.indexOf(role) < CERT_ROLES.indexOf(entry.role)) entry.role = role;
      if (!entry.sessions.includes(r)) entry.sessions.push(r);
      entry.endpoints.add(r.session.endpoint);
      // Only a leaf carries hostname and trust-path outcomes; a CA certificate
      // is judged on its own hygiene, so it must not inherit the leaf's checks.
      if (role === "leaf") entry.checks.push(ch);
    });
  }
  const certs = [...map.values()];
  certs.forEach((c) => { c.verdict = certVerdict(c); });
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4, ok: 5 };
  certs.sort((a, b) => (CERT_ROLES.indexOf(a.role) - CERT_ROLES.indexOf(b.role))
    || (rank[a.verdict.sev] - rank[b.verdict.sev]) || (b.sessions.length - a.sessions.length));
  return { certs, unobservable };
}

const WEAK_HASH = ["md5", "sha1"];
const weakKey = (c) => (c.key_type === "RSA" && c.key_bits < 2048) ||
                       (c.key_type.startsWith("EC") && c.key_bits < 256) ||
                       (c.key_type === "DSA");

// Each entry is one verification the analyser performed, with its outcome, so the
// panel reads as a checklist rather than a verdict with no working shown.
function certChecks(entry) {
  const leaf = entry.leaf, ch = entry.checks[0];
  const isLeaf = entry.role === "leaf";
  const anyTrue = (k) => entry.checks.some((c) => c[k] === true);
  const anyFalse = (k) => entry.checks.some((c) => c[k] === false);
  const out = [];

  // --- applies to every certificate, whatever its role -----------------------
  const now = Date.now() / 1000;
  const notAfter = Date.parse(leaf.not_after) / 1000;
  const days = ch && isLeaf ? ch.days_to_expiry : Math.floor((notAfter - now) / 86400);
  const expired = isLeaf ? anyTrue("expired") : notAfter < now;
  out.push(expired
    ? ["fail", "Validity window", `expired — notAfter ${leaf.not_after.slice(0, 10)}`]
    : days != null && days < 30
      ? ["warn", "Validity window", `valid, but only ${days} days left`]
      : ["pass", "Validity window", `valid · ${leaf.not_before.slice(0, 10)} → ${leaf.not_after.slice(0, 10)}`]);

  out.push(weakKey(leaf)
    ? ["fail", "Key strength", `${leaf.key_type} ${leaf.key_bits} bits is below the minimum`]
    : ["pass", "Key strength", `${leaf.key_type} ${leaf.key_bits} bits`]);

  const sig = (leaf.signature_hash || "").toLowerCase();
  out.push(WEAK_HASH.includes(sig) && !leaf.self_signed
    ? ["fail", "Signature algorithm", `${sig.toUpperCase()} — collision attacks are practical`]
    : ["pass", "Signature algorithm", leaf.self_signed && WEAK_HASH.includes(sig)
        ? `${sig.toUpperCase()}, but self-signed: a root's own signature is never relied on`
        : (leaf.signature_hash || "unknown").toUpperCase()]);

  out.push(leaf.der_error
    ? ["warn", "DER encoding", "non-canonical: legal BER, illegal DER — stricter validators will reject it"]
    : ["pass", "DER encoding", "canonical"]);

  // --- leaf-only: identity and trust ----------------------------------------
  if (isLeaf) {
    const named = entry.checks.filter((c) => c.hostname_match != null);
    out.push(!named.length
      ? ["skip", "Hostname (RFC 6125)", "no SNI or server name to check against"]
      : anyFalse("hostname_match")
        ? ["fail", "Hostname (RFC 6125)", `does not cover '${entry.checks.find((c) => c.hostname_match === false).hostname}'`]
        : ["pass", "Hostname (RFC 6125)", `matches '${named[0].hostname}' — wildcard covers one label, SAN supersedes CN`]);

    out.push(entry.chain.length < 2
      ? ["skip", "Chain links", "only the leaf was presented; nothing to link"]
      : ch.chain_links_ok === false
        ? ["fail", "Chain links", "a certificate does not sign its predecessor — chain broken or out of order"]
        : ch.chain_links_ok == null
          ? ["skip", "Chain links", "signature algorithm too weak for the library to verify"]
          : ["pass", "Chain links", `each of the ${entry.chain.length} certificates signs the one before it`]);

    out.push(anyTrue("self_signed")
      ? ["fail", "Trust path", "self-signed — no third party vouches for this identity"]
      : ch.trusted === true
        ? ["pass", "Trust path", ch.trust_detail || "chains to a trusted root"]
        : ch.trusted === false
          ? ["fail", "Trust path", ch.trust_detail || "does not chain to a trusted root"]
          : ["skip", "Trust path", ch.trust_detail || "no trust store available"]);

    out.push(leaf.is_ca
      ? ["fail", "Usage constraints", "leaf carries BasicConstraints CA:TRUE"]
      : leaf.eku_server_auth === false
        ? ["fail", "Usage constraints", "extended key usage does not include serverAuth"]
        : ["pass", "Usage constraints", leaf.eku_server_auth ? "serverAuth, not a CA" : "not a CA"]);

    out.push(leaf.has_sct
      ? ["pass", "Certificate Transparency", "carries embedded SCTs — was submitted to public CT logs"]
      : ["warn", "Certificate Transparency",
         "no embedded SCTs — never publicly logged, which a private or interception CA cannot avoid"]);

    out.push(["skip", "Revocation",
      (ch && ch.revocation) || "unknown — a passive capture carries no OCSP or CRL response unless stapled"]);
  } else {
    // --- CA certificates are judged on their own terms ----------------------
    out.push(leaf.is_ca
      ? ["pass", "CA constraints", "BasicConstraints CA:TRUE, as a CA certificate must be"]
      : ["fail", "CA constraints", "used as a CA but BasicConstraints does not say CA:TRUE"]);
    out.push(leaf.key_usage.includes("key_cert_sign")
      ? ["pass", "Key usage", "keyCertSign present"]
      : ["warn", "Key usage", "keyCertSign is not asserted on a certificate used to sign others"]);
    if (entry.role === "root") {
      out.push(["warn", "Chain hygiene",
        "a self-signed root was sent in the chain: clients already hold their roots, so this wastes " +
        "handshake bytes and never adds trust"]);
    }
  }
  return out;
}


function certVerdict(entry) {
  const checks = certChecks(entry);
  const fails = checks.filter((c) => c[0] === "fail");
  if (!fails.length) return checks.some((c) => c[0] === "warn")
    ? { sev: "medium", label: "Verified, with notes" }
    : { sev: "ok", label: "Verified" };
  const order = ["Validity window", "Key strength", "Signature algorithm", "Hostname (RFC 6125)",
                 "Chain links", "Usage constraints", "Trust path"];
  const first = fails.slice().sort((a, b) => order.indexOf(a[1]) - order.indexOf(b[1]))[0];
  const label = { "Trust path": "Untrusted", "Validity window": "Expired", "Hostname (RFC 6125)": "Name mismatch",
                  "Key strength": "Weak key", "Signature algorithm": "Weak signature",
                  "Chain links": "Broken chain", "Usage constraints": "Wrong usage" }[first[1]] || "Failed";
  return { sev: fails.length > 1 ? "critical" : "high", label, failed: fails.length };
}

function certsFailing(rep) {
  return collectCerts(rep).certs.filter((c) => c.verdict.sev === "critical" || c.verdict.sev === "high").length;
}

const CHECK_MARK = {
  pass: '<span class="ck ck-pass" aria-label="pass">✓</span>',
  fail: '<span class="ck ck-fail" aria-label="fail">✕</span>',
  warn: '<span class="ck ck-warn" aria-label="warning">!</span>',
  skip: '<span class="ck ck-skip" aria-label="not checked">–</span>',
};

function certPanel(entry, id) {
  const leaf = entry.leaf;
  const checks = certChecks(entry);
  const sans = leaf.sans.length ? leaf.sans.join(", ") : "none — modern clients ignore CN entirely";
  const chain = entry.chain.map((c, i) => `<li><span class="mono">${esc(cnOf(c.subject))}</span>
      <span class="faint">${i === 0 ? "leaf" : c.self_signed ? "root (self-signed)" : "intermediate"} ·
      ${esc(c.key_type)} ${c.key_bits} · ${esc((c.signature_hash || "?").toUpperCase())}</span></li>`).join("");
  return `<div class="body cert-body">
    <div class="checks">${checks.map(([state, name, detail]) =>
      `<div class="check c-${state}">${CHECK_MARK[state]}<span><b>${esc(name)}</b><span>${esc(detail)}</span></span></div>`).join("")}</div>
    <dl class="kv">
      <dt>Subject</dt><dd class="mono">${esc(leaf.subject)}</dd>
      <dt>Issuer</dt><dd class="mono">${esc(leaf.issuer)}</dd>
      <dt>Serial</dt><dd class="mono">${esc(leaf.serial)}</dd>
      <dt>SAN</dt><dd class="mono">${esc(sans)}</dd>
      <dt>SHA-256</dt><dd class="mono" style="font-size:12px">${esc(leaf.sha256)}</dd>
      <dt>Key usage</dt><dd>${esc(leaf.key_usage.join(", ") || "not asserted")}</dd>
      <dt>AIA</dt><dd class="mono" style="font-size:12px">${esc(leaf.aia.join(" ") || "none — an MTA cannot complete a missing chain without it")}</dd>
      <dt>Chain</dt><dd><ol class="chainlist">${chain}</ol></dd>
      <dt>Seen on</dt><dd>${[...entry.endpoints].map((e) => `<span class="mono">${esc(e)}</span>`).join(", ")}</dd>
      <dt>Sessions</dt><dd>${entry.sessions.map((r) =>
        `<a class="mono" href="#/r/${esc(id)}/s/${esc(r.session.session_id)}">${esc(r.session.session_id)}</a>`).join(" ")}</dd>
    </dl></div>`;
}

const tabCerts = {
  html(rep, id) {
    const { certs, unobservable } = collectCerts(rep);
    const verified = certs.filter((c) => c.verdict.sev === "ok").length;
    const failing = certs.filter((c) => c.verdict.sev === "critical" || c.verdict.sev === "high").length;
    const byRole = CERT_ROLES.map((r) => [r, certs.filter((c) => c.role === r).length])
      .filter(([, n]) => n).map(([r, n]) => `${n} ${r}`).join(", ");

    if (!certs.length && !unobservable.length) {
      return `${pageHead("Certificates", "<span>No TLS handshake in this capture presented a certificate.</span>")}
        <div class="empty card">Nothing to verify — no session reached a Certificate message.</div>`;
    }

    const ROLE_LABEL = {
      leaf: ["Server certificates", "presented as the endpoint's own identity"],
      intermediate: ["Intermediate CAs", "sent by the server to complete the chain"],
      root: ["Roots sent in the chain", "clients already hold their roots; sending one adds nothing"],
    };
    const rowFor = (entry) => {
      const leaf = entry.leaf, v = entry.verdict;
      return `<details class="fd cert-item" data-sev="${esc(v.sev)}" data-role="${esc(entry.role)}">
        <summary class="cert-row">
          <span class="chip s-${v.sev === "ok" ? "ok" : esc(v.sev)}" title="${v.failed ? esc(v.failed + " checks failed") : "all checks passed"}">${esc(v.label)}${v.failed > 1 ? `<i class="more">+${v.failed - 1}</i>` : ""}</span>
          <span style="min-width:0">
            <b class="mono ellip" style="display:block;font-size:14px;font-weight:600">${esc(cnOf(leaf.subject))}<span class="rtag r-${esc(entry.role)}">${esc(entry.role)}</span></b>
            <span class="faint ellip" style="font-size:12.5px;display:block">${esc(leaf.key_type)} ${leaf.key_bits} · ${esc((leaf.signature_hash || "?").toUpperCase())} · issued by ${esc(cnOf(leaf.issuer))}</span>
          </span>
          <span class="muted col-exp" style="font-size:13px">${esc(leaf.not_after.slice(0, 10))}</span>
          <span class="mono faint col-fp" style="font-size:12.5px">${esc(shortHash(leaf.sha256))}</span>
          <span class="mono" style="font-size:13px;text-align:right">${entry.sessions.length}×</span>
        </summary>
        ${certPanel(entry, id)}
      </details>`;
    };
    const rows = CERT_ROLES.filter((role) => certs.some((c) => c.role === role)).map((role) => {
      const group = certs.filter((c) => c.role === role);
      const [title, sub] = ROLE_LABEL[role];
      return `<div class="cert-group"><span class="cg-t">${esc(title)}</span>
        <span class="cg-n">${group.length}</span><span class="cg-s">${esc(sub)}</span></div>`
        + group.map(rowFor).join("");
    }).join("");

    // Certificates that could not be recovered at all. Stated, never guessed at.
    const byReason = new Map();
    unobservable.forEach((u) => byReason.set(u.reason, (byReason.get(u.reason) || 0) + 1));
    // "encrypted", "resumed" and "genuinely absent" are three different facts;
    // only the last is a defect.
    const notObserved = byReason.size ? `<div class="card card-pad reveal" style="display:flex;flex-direction:column;gap:10px">
        <h2 style="font-size:18px">Not observable</h2>
        ${[...byReason.entries()].map(([reason, n]) =>
          `<div style="display:flex;gap:10px;align-items:baseline"><b class="mono" style="font-size:20px">${n}</b>
           <span class="muted" style="font-size:13.5px">${esc(reason)}</span></div>`).join("")}
        <p class="faint" style="margin:0;font-size:12.5px">No certificate is inferred for these sessions. A tool
        that reports what the cryptography actually did cannot then invent the part it could not see.</p>
      </div>` : "";

    return `${pageHead("Certificates", `<span>${certs.length} distinct certificate${certs.length === 1 ? "" : "s"} (${byRole}) across ${rep.sessions.length} sessions</span><span>${verified} verified · ${failing} failed verification</span>${unobservable.length ? `<span>${unobservable.length} not observable</span>` : ""}`)}
    <section class="twocol">
      <div class="card cert-card reveal" style="overflow:hidden">
        <div class="trow head cert-row"><span>VERDICT</span><span>SUBJECT</span><span class="col-exp">EXPIRES</span><span class="col-fp">FINGERPRINT</span><span style="text-align:right">SEEN</span></div>
        <div class="fill">${rows || '<div class="empty">No certificate was recoverable from this capture.</div>'}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:20px" class="reveal">
        ${hbars("Verification outcome", [
          ["Verified", verified, C.accent],
          ["With notes", certs.filter((c) => c.verdict.sev === "medium").length, C.clear],
          ["Failed", failing, C.bad],
          ["Not observable", unobservable.length, C.idle],
        ], "Each certificate is checked once and counted once, however many sessions presented it.")}
        ${notObserved}
      </div>
    </section>`;
  },
  init() { afterPaint(() => $$(".hbar [data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`))); },
};

const tabSessions = {
  html(rep, id) {
    return `${pageHead("Sessions", `<span>Highest risk first. Click a session to replay its handshake step by step.</span>`)}
    <section class="card reveal" style="overflow:hidden">
      <div class="tscroll fill">
        <div class="trow head s-row"><span>ID</span><span>CLIENT → ENDPOINT</span><span>PROTO</span><span>CHANNEL</span><span>TLS</span><span>CIPHER</span><span>WORST</span><span style="text-align:right">RISK</span></div>
        ${sessionRows(rep, id)}
      </div>
    </section>`;
  },
  init() { afterPaint(() => $$(".s-row [data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`))); },
};

function groupFindings(findings) {
  const map = new Map();
  for (const f of findings) {
    const k = `${f.rule_id}|${f.endpoint}|${f.severity}`;
    if (!map.has(k)) map.set(k, { f, sessions: [] });
    map.get(k).sessions.push(f.session_id);
  }
  return [...map.values()];
}

function findingDetails(g, id) {
  const f = g.f;
  return `<details class="fd" data-sev="${esc(f.severity)}">
    <summary>${sevChip(f.severity)}<span style="min-width:0"><b style="font-weight:600">${esc(f.title)}</b><span class="faint mono" style="font-size:12.5px;display:block;margin-top:2px">${esc(f.rule_id)} · ${esc(f.endpoint)}${g.sessions.length > 1 ? ` · ${g.sessions.length} sessions` : ""}</span></span><span class="mono faint">risk ${Math.round(f.risk || 0)}</span></summary>
    <div class="body">
      ${f.escalated_from ? `<div style="color:var(--crit-ink)">Escalated from ${esc(f.escalated_from)} by the endpoint baseline.</div>` : ""}
      <div><b style="color:var(--text);font-weight:600">Evidence</b><ul>${f.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>
      <div><b style="color:var(--text);font-weight:600">Fix</b><div>${code(f.remediation)}</div></div>
      ${f.compliance.length ? `<div class="faint" style="font-size:13px">${esc(f.compliance.join(" · "))}</div>` : ""}
      <div>${g.sessions.filter(Boolean).map((s) => `<a href="#/r/${esc(id)}/s/${esc(s)}" style="margin-right:12px;font-size:13px">Replay ${esc(s)}</a>`).join("")}</div>
    </div></details>`;
}

function endpointRows(rep) {
  const by = new Map();
  rep.sessions.forEach((r) => { const e = r.session.endpoint; if (!by.has(e)) by.set(e, []); by.get(e).push(r); });
  const rows = [...by.entries()].map(([ep, rs]) => ({ ep, rs, info: rep.posture.endpoints[ep] || { score: 100, grade: "A", findings: {} } }));
  rows.sort((a, b) => a.info.score - b.info.score);
  return rows.map(({ ep, rs, info }) => {
    const modes = [...new Set(rs.map((r) => classify(r)))].map((c) => c.label);
    const issues = SEVS.filter((s) => info.findings[s]).map((s) => `${info.findings[s]} ${s}`).join(" · ") || "none";
    return `<div class="trow ep-row">
      <span class="grade g-${esc(info.grade)}">${esc(info.grade)}</span>
      <span style="min-width:0"><span class="mono ellip" style="display:block;font-size:13.5px">${esc(ep)}</span><span class="faint" style="font-size:12.5px">${esc(rs[0].session.protocol)} · score ${info.score}</span></span>
      <span class="muted ellip" style="font-size:13px">${esc([...new Set(modes)].join(", "))}</span>
      <span class="mono" style="font-size:13.5px">${rs.length}</span>
      <span class="muted" style="font-size:13px">${esc(issues)}</span></div>`;
  }).join("");
}

function hbars(title, rows, note = "") {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  const lead = (rows.find((r) => r[1]) || rows[0] || [])[2] || "var(--accent)";
  return `<div class="card card-pad" style="display:flex;flex-direction:column;gap:16px;--sec:${lead}"><h2 style="font-size:18px">${esc(title)}</h2><div class="hbars">${rows.map(([k, n, col]) =>
    `<div class="hbar"><span class="muted">${esc(k)}</span><span class="bar" style="background:color-mix(in srgb, ${col} 12%, transparent)"><span data-w="${(100 * n) / max}" style="background:${col}"></span></span><span class="mono" style="text-align:right;color:${n ? col : "var(--faint)"}">${n}</span></div>`).join("")}</div>${note ? `<div class="faint" style="font-size:12.5px">${esc(note)}</div>` : ""}</div>`;
}

function channelCard(rep) {
  const n = (fn) => rep.sessions.filter(fn).length;
  return hbars("How the channel was set up", [
    ["Implicit TLS", n((r) => r.session.mode === "implicit"), C.accent],
    ["STARTTLS → TLS", n((r) => r.session.mode === "starttls"), C.deep],
    ["Stripped", n((r) => r.session.strip_indicators.length > 0), C.bad],
    ["Cleartext", n((r) => r.session.mode === "plaintext" && !r.session.strip_indicators.length), C.clear],
  ]);
}

function protocolCard(rep) {
  const n = (proto) => rep.sessions.filter((r) => r.session.protocol === proto).length;
  const rows = ["SMTP", "IMAP", "POP3"].map((pr) => [pr, n(pr), protoColor(pr)]).filter((r) => r[1]);
  if (!rows.length) return "";
  return hbars("Which protocols were spoken", rows,
    "Transfer (SMTP) against access (IMAP, POP3): the two carry different risks, because only " +
    "access protocols put a user's own password on the wire.");
}

function versionCard(rep) {
  const n = (v) => rep.sessions.filter((r) => (r.tls && r.tls.server_hello_seen ? r.tls.version_name : "No TLS") === v).length;
  const rows = [["TLS 1.3", C.accent], ["TLS 1.2", C.deep], ["TLS 1.1", C.clear], ["TLS 1.0", C.clear], ["SSL 3.0", C.bad], ["No TLS", C.bad]]
    .map(([v, c]) => [v, n(v), c]).filter((r) => r[1] > 0 || r[0] === "TLS 1.3");
  return hbars("What was negotiated", rows, "Version read from supported_versions (extension 43), not the legacy field.");
}

function sessionRows(rep, id) {
  const rows = [...rep.sessions].sort((a, b) => (b.risk || 0) - (a.risk || 0));
  return rows.map((r) => {
    const s = r.session, c = classify(r);
    const fs = rep.findings.filter((f) => f.session_id === s.session_id);
    const w = fs.length ? worst(fs) : null;
    const chCls = c.kind === "bad" ? "s-critical" : c.kind === "clear" ? "s-high" : "s-ok";
    const chLabel = s.mode === "implicit" ? "implicit TLS" : s.mode === "starttls" ? "STARTTLS" : s.strip_indicators.length ? "stripped" : "cleartext";
    const risk = Math.round(r.risk || 0);
    return `<a class="trow s-row" href="#/r/${esc(id)}/s/${esc(s.session_id)}">
      <span class="mono muted" style="font-size:13px">${esc(s.session_id)}</span>
      <span class="mono ellip" style="font-size:13px"><span class="faint">${esc(s.client[0])} →</span> ${esc(s.endpoint)}</span>
      <span><span class="ptag p-${esc(s.protocol.toLowerCase())}">${esc(s.protocol)}</span></span>
      <span><span class="tag ${chCls}">${esc(chLabel)}</span></span>
      <span style="font-size:13px">${esc(r.tls && r.tls.server_hello_seen ? r.tls.version_name.replace("TLS ", "") : "—")}</span>
      <span class="mono faint ellip" style="font-size:12px">${esc(r.tls && r.tls.cipher_name ? r.tls.cipher_name.replace(/^TLS_/, "") : "—")}</span>
      <span>${w ? sevChip(w) : '<span class="faint" style="font-size:13px">none</span>'}</span>
      <span style="display:flex;align-items:center;gap:8px;justify-content:flex-end"><span class="bar" style="width:56px;height:6px"><span data-w="${risk}" style="background:${risk >= 70 ? C.bad : risk >= 35 ? C.clear : C.accent}"></span></span><span class="mono" style="width:28px;text-align:right">${risk}</span></span>
    </a>`;
  }).join("");
}

// ------------------------------------------------------------------ wire replay: the capture simulation
class WireSim {
  constructor(rep, id) {
    this.rep = rep; this.id = id;
    this.stage = $("#wstage"); this.feed = $("#wfeed");
    this.sess = [...rep.sessions].sort((a, b) => a.session.start_ts - b.session.start_ts);
    this.GAP = 1.05; this.DUR = 2.8;
    this.T = (this.sess.length - 1) * this.GAP + this.DUR + 0.8;
    this.t = 0; this.speed = 1; this.playing = false; this.shown = 0;
    this.build();
    this.bind();
    this.render();
    if (REDUCED) { this.t = this.T; this.render(); return; }
    this.io = new IntersectionObserver((es) => { if (es[0].isIntersecting && !this.started) { this.started = true; this.play(); } }, { threshold: 0.35 });
    this.io.observe(this.stage);
  }

  build() {
    const clients = [...new Set(this.sess.map((r) => r.session.client[0]))];
    const servers = [...new Set(this.sess.map((r) => r.session.endpoint))];
    const W = 1000, rows = Math.max(clients.length, servers.length);
    const H = Math.max(380, 70 + rows * 30);
    const cx = 170, sx = 690, mx = (cx + sx) / 2;
    const y = (i, n) => 56 + (i + 0.5) * ((H - 80) / n);
    this.W = W; this.H = H; this.mx = mx;
    this.cPos = new Map(clients.map((c, i) => [c, [cx, y(i, clients.length)]]));
    this.sPos = new Map(servers.map((s, i) => [s, [sx, y(i, servers.length)]]));
    const ns = "http://www.w3.org/2000/svg";
    let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Animated replay of ${this.sess.length} mail sessions between ${clients.length} clients and ${servers.length} servers">
      <text x="${cx}" y="30" text-anchor="end" class="node-title">CLIENTS</text>
      <text x="${mx}" y="30" text-anchor="middle" class="node-title">NETWORK PATH</text>
      <text x="${sx}" y="30" class="node-title">MAIL SERVERS</text>
      <line x1="${mx}" y1="42" x2="${mx}" y2="${H - 14}" stroke="var(--line)" stroke-dasharray="3 6"/>`;
    this.sess.forEach((r, i) => {
      const [x1, y1] = this.cPos.get(r.session.client[0]);
      const [x2, y2] = this.sPos.get(r.session.endpoint);
      const bend = ((i % 5) - 2) * 14;
      const qx = mx, qy = (y1 + y2) / 2 + bend;
      r._geo = { x1, y1, x2, y2, qx, qy };
      r._cls = classify(r);
      const d = `M ${x1} ${y1} Q ${qx} ${qy} ${x2} ${y2}`;
      const mid = this.pt(r._geo, 0.5);
      svg += `<g class="sess" data-i="${i}" style="cursor:pointer;opacity:0">
        <path class="ln" d="${d}" fill="none" stroke="${C.idle}" stroke-width="2" stroke-linecap="round"/>
        <path d="${d}" fill="none" stroke="transparent" stroke-width="12"><title>${esc(r.session.session_id)} · ${esc(r.session.client[0])} → ${esc(r.session.endpoint)} · ${esc(r._cls.label)}</title></path>
        ${[0, 1, 2, 3].map(() => `<circle class="pk" r="3.6" fill="${C.clear}" opacity="0"/>`).join("")}
        <g class="mark" transform="translate(${mid[0]} ${mid[1]})" opacity="0">${this.markSvg(r._cls.kind)}</g>
        <text class="tag-l" x="${mid[0]}" y="${mid[1] - 18}" text-anchor="middle" font-size="12" font-family="IBM Plex Sans, sans-serif" fill="${r._cls.kind === "bad" ? "var(--crit-ink)" : "var(--muted)"}" opacity="0">${esc(r._cls.kind === "bad" ? r._cls.label : "")}</text>
      </g>`;
    });
    clients.forEach((c) => { const [x, yy] = this.cPos.get(c); svg += `<circle cx="${x}" cy="${yy}" r="5" fill="var(--s2)" stroke="var(--faint)" stroke-width="1.5"/><text x="${x - 12}" y="${yy + 4}" text-anchor="end" class="node-label">${esc(c)}</text>`; });
    servers.forEach((s) => { const [x, yy] = this.sPos.get(s); svg += `<rect x="${x - 5}" y="${yy - 5}" width="10" height="10" rx="2" fill="var(--s2)" stroke="var(--faint)" stroke-width="1.5"/><text x="${x + 12}" y="${yy + 4}" class="node-label">${esc(s)}</text>`; });
    svg += `</svg>`;
    this.stage.innerHTML = svg;
    this.groups = $$(".sess", this.stage);
    this.groups.forEach((g, i) => {
      const r = this.sess[i];
      r._el = { g, ln: $(".ln", g), pk: $$(".pk", g), mark: $(".mark", g), tag: $(".tag-l", g) };
      r._len = r._el.ln.getTotalLength();
      r._el.ln.style.strokeDasharray = `${r._len}`;
      g.addEventListener("click", () => (location.hash = `#/r/${this.id}/s/${r.session.session_id}`));
    });
    void ns;
  }

  markSvg(kind) {
    if (kind === "tls") return `<circle r="10" fill="var(--accent-bg)" stroke="${C.accent}" stroke-width="1.5"/><g transform="translate(-6 -6.5) scale(.5)" fill="none" stroke="${C.accent}" stroke-width="2.6" stroke-linecap="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></g>`;
    if (kind === "clear") return `<circle r="10" fill="var(--high-bg)" stroke="${C.clear}" stroke-width="1.5"/><g transform="translate(-6 -6.5) scale(.5)" fill="none" stroke="${C.clear}" stroke-width="2.6" stroke-linecap="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/></g>`;
    return `<circle r="16" fill="none" stroke="${C.bad}" stroke-width="1.5" class="ring-ping"><animate attributeName="r" values="10;24" dur="1.2s" repeatCount="indefinite"/><animate attributeName="opacity" values=".9;0" dur="1.2s" repeatCount="indefinite"/></circle><rect x="-9" y="-9" width="18" height="18" transform="rotate(45)" fill="var(--crit-bg)" stroke="${C.bad}" stroke-width="1.8"/><path d="M0 -5v5.5M0 4v.5" stroke="${C.bad}" stroke-width="2.2" stroke-linecap="round"/>`;
  }

  pt(g, u) {
    const a = (1 - u) * (1 - u), b = 2 * (1 - u) * u, c = u * u;
    return [a * g.x1 + b * g.qx + c * g.x2, a * g.y1 + b * g.qy + c * g.y2];
  }

  bind() {
    this.btn = $("#wplay");
    this.btn.addEventListener("click", () => (this.playing ? this.pause() : this.play()));
    $("#wrestart").addEventListener("click", () => { this.t = 0; this.shown = 0; this.feed.innerHTML = ""; this.render(); this.play(); });
    $("#wspeed").addEventListener("change", (e) => (this.speed = +e.target.value));
    this.scrub = $("#wscrub");
    this.scrub.addEventListener("input", () => { this.pause(); this.t = (this.scrub.value / 1000) * this.T; this.render(true); });
  }

  play() {
    if (this.t >= this.T) { this.t = 0; this.shown = 0; this.feed.innerHTML = ""; }
    this.playing = true;
    this.btn.innerHTML = icon.pause; this.btn.setAttribute("aria-label", "Pause");
    let last = performance.now();
    const loop = (now) => {
      if (!this.playing) return;
      this.t = Math.min(this.T, this.t + ((now - last) / 1000) * this.speed);
      last = now;
      this.render();
      if (this.t >= this.T) { this.pause(); return; }
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  pause() {
    this.playing = false;
    cancelAnimationFrame(this.raf);
    if (this.btn) { this.btn.innerHTML = icon.play; this.btn.setAttribute("aria-label", "Play"); }
  }

  destroy() { this.pause(); if (this.io) this.io.disconnect(); }

  render(rebuildFeed = false) {
    const OUT = 0.6;
    let sealed = 0, clear = 0, bad = 0, current = null;
    this.sess.forEach((r, i) => {
      const p = (this.t - i * this.GAP) / this.DUR;
      const el = r._el, kind = r._cls.kind;
      if (p <= 0) { el.g.style.opacity = 0; return; }
      current = r;
      el.g.style.opacity = p > 1.15 ? 0.5 : 1;
      el.ln.style.strokeDashoffset = String(r._len * (1 - Math.min(p / 0.18, 1)));
      const col = p < OUT ? (r.session.mode === "implicit" ? C.accent : C.idle) : kind === "tls" ? C.accent : kind === "clear" ? C.clear : C.bad;
      el.ln.setAttribute("stroke", col);
      el.ln.setAttribute("stroke-width", p >= OUT && p < 1.15 ? 2.6 : 2);
      el.pk.forEach((c, k) => {
        if (p < 0.18 || p > 1) { c.setAttribute("opacity", 0); return; }
        let u = (((p - 0.18) / 0.82) * 3 + k * 0.25) % 1;
        if (k % 2) u = 1 - u;
        const [x, y] = this.pt(r._geo, u);
        c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("opacity", 0.95);
        const pc = p < OUT ? (r.session.mode === "implicit" ? C.accent : C.clear) : kind === "tls" ? C.accent : kind === "clear" ? C.clear : C.bad;
        c.setAttribute("fill", pc);
      });
      const on = p >= OUT;
      el.mark.setAttribute("opacity", on ? 1 : 0);
      el.tag.setAttribute("opacity", on && p < 1.6 ? 1 : 0);
      if (on) { if (kind === "tls") sealed++; else if (kind === "clear") clear++; else bad++; }
    });
    // feed of completed sessions
    const done = this.sess.filter((r, i) => (this.t - i * this.GAP) / this.DUR >= OUT);
    if (rebuildFeed || done.length < this.shown) { this.feed.innerHTML = ""; this.shown = 0; }
    for (let k = this.shown; k < done.length; k++) this.feed.insertAdjacentHTML("afterbegin", this.feedItem(done[k]));
    this.shown = done.length;
    $("#tally").textContent = `${sealed} sealed · ${clear} cleartext · ${bad} attacked`;
    $("#clock").textContent = current ? `${hhmmss(current.session.start_ts)} UTC · ${current.session.session_id}` : "ready";
    this.scrub.value = String(Math.round((this.t / this.T) * 1000));
  }

  feedItem(r) {
    const fs = this.rep.findings.filter((f) => f.session_id === r.session.session_id && f.severity !== "info");
    const top = fs.sort((a, b) => (b.risk || 0) - (a.risk || 0))[0];
    const k = r._cls.kind;
    return `<a class="feed-item" href="#/r/${esc(this.id)}/s/${esc(r.session.session_id)}">
      <span class="top"><span class="mono" style="font-size:12.5px">${esc(r.session.session_id)} · ${esc(r.session.protocol)}</span>${top ? sevChip(top.severity) : `<span class="chip s-ok">${k === "tls" ? "sealed" : "clean"}</span>`}</span>
      <span style="font-weight:500">${esc(top ? top.title.replace(/ \(deviates.*\)$/, "") : `${r._cls.label}, no issues`)}</span>
      <span class="ep">${esc(r.session.client[0])} → ${esc(r.session.endpoint)}</span></a>`;
  }
}

// ================================================================== SESSION REPLAY
const EXPLAIN = {
  SYN: ["TCP handshake: SYN", "The client opens a TCP connection. SecureMailScope marks whoever sends SYN without ACK as the client."],
  "SYN/ACK": ["TCP handshake: SYN/ACK", "The server accepts. Sequence numbers from this handshake anchor the stream reassembly: offsets are (seq − ISN) mod 2³²."],
  ACK: ["TCP handshake: ACK", "The connection is open. Everything that follows is reassembled per direction: reordered, de-duplicated, overlaps trimmed."],
  banner: ["The server speaks first", "This greeting identifies the protocol. SecureMailScope reads the banner, never the port number, which is how it finds mail services hiding on odd ports."],
  caps: ["The server lists what it supports", "STARTTLS in this list is the offer to upgrade to TLS. It is sent in cleartext, before any key exists, so nothing protects it."],
  capsStripped: ["The upgrade offer was rewritten in the path", "The server's STARTTLS offer arrived as a same-length token. Stripping devices overwrite in place so they never have to fix TCP sequence numbers. The client now believes TLS is unavailable and carries on in cleartext."],
  starttlsC: ["The client asks to upgrade", "STARTTLS: from here, both sides should switch to TLS."],
  starttlsS: ["The server agrees", "From the next byte each direction switches to TLS, and they switch at different byte offsets. SecureMailScope tracks both."],
  strip: ["The upgrade did not happen", "The request was refused or ignored, so the rest of the session is cleartext. On an endpoint that normally supports TLS, a refusal like this is a classic forged reply."],
  switch: ["TLS begins here", "Two offsets, not one: the client's TLS starts at one byte and the server's at another. Slicing with a single offset is the bug that makes parsers report 'TLS present, version unknown'."],
  inject: ["Cleartext smuggled across the upgrade", "These bytes arrived after STARTTLS but before the TLS handshake. A vulnerable server buffers them and executes them as if they came through TLS (the CVE-2011-0411 class; 40+ implementations per Poddebniak et al., 2021)."],
  auth: ["Authentication in cleartext", "Anyone on the path can read this. SecureMailScope records the mechanism and username so you know whose password to rotate, then discards the secret itself."],
  data: ["A message crossed the network readable", "The body was sent outside TLS. SecureMailScope counts the bytes and never stores the content."],
  cmd: ["Cleartext command", "Before TLS, every command and reply is readable and modifiable by anyone on the path."],
  reply: ["Cleartext reply", "Before TLS, every command and reply is readable and modifiable by anyone on the path."],
  ClientHello: ["ClientHello", "The client proposes TLS versions, cipher suites and extensions. GREASE values are removed before computing the JA3 fingerprint, or it would change every connection."],
  ServerHello: ["ServerHello", "The server picks the version and cipher. The real version comes from supported_versions (extension 43): TLS 1.3 pins the legacy field to 1.2 for middlebox compatibility."],
  Certificate: ["The server's certificate", "Only visible in TLS 1.2 and below. SecureMailScope checks key size, signature hash, validity at capture time, RFC 6125 hostname rules and the chain to a trusted root."],
  CertificateSwapped: ["A different certificate than usual", "This endpoint presented one CA-issued certificate in every clean session before. This one is new and self-signed: the signature of an active man-in-the-middle."],
  ServerKeyExchange: ["Ephemeral key exchange", "Fresh (EC)DH parameters: this is where forward secrecy comes from. Diffie-Hellman groups under 2048 bits are Logjam-weak."],
  ServerHelloDone: ["ServerHelloDone", "The server's first flight is complete."],
  ClientKeyExchange: ["ClientKeyExchange", "The client's half of the key exchange. Both sides can now derive the session keys."],
  ChangeCipherSpec: ["ChangeCipherSpec", "From here this direction is encrypted."],
  Finished: ["Finished (encrypted)", "A MAC over the whole handshake transcript. If anyone had changed a single hello byte, this check would fail: TLS negotiation is tamper-evident, which is exactly what the STARTTLS offer is not."],
  enc13: ["The rest of the handshake is encrypted", "In TLS 1.3 everything after ServerHello is encrypted, including the certificate. Passive analysis cannot see it by design, so it is reported as 'not observable', never as valid."],
  appdata: ["The channel is sealed", "Commands, credentials and mail now travel inside TLS."],
  alert: ["TLS alert", "An alert ended or disrupted the handshake."],
  close: ["End of session", "Everything above crossed the network readable."],
};

const LANE = { C: 16.66, P: 50, S: 83.33 };

function buildSteps(r, rep) {
  const s = r.session, tls = r.tls, chain = r.certificate_chain, devs = r.baseline_deviations || [];
  const steps = [];
  // curFrames carries the frame numbers of the transcript entry currently being
  // turned into steps. Setting it once per iteration means the several `continue`
  // paths below cannot forget to attach provenance.
  let curFrames = null;
  const add = (o) => steps.push(Object.assign(
    { from: "C", to: "S", tone: "neutral", detail: "", key: "cmd", frames: curFrames }, o));
  // Frames for the TCP handshake are not in the transcript (it starts at the
  // banner), so they are taken from the packet table by flags.
  const sessPkts = (rep.packets || []).filter((x) => x.session === s.session_id);
  const byFlags = (re) => sessPkts.filter((x) => re.test(x.flags) && !x.len).slice(0, 1).map((x) => x.frame);
  let channel = s.mode === "implicit" ? "negotiating" : "clear";
  const stripped = s.strip_indicators.length > 0;

  if (s.stream_quality.handshake_seen) {
    add({ from: "C", to: "S", label: "SYN", pkt: "SYN", tone: "tcp", key: "SYN", channel, frames: byFlags(/^SYN$/) });
    add({ from: "S", to: "C", label: "SYN, ACK", pkt: "SYN/ACK", tone: "tcp", key: "SYN/ACK", channel, frames: byFlags(/^SYN, ACK$/) });
    add({ from: "C", to: "S", label: "ACK", pkt: "ACK", tone: "tcp", key: "ACK", channel, frames: byFlags(/^ACK$/) });
  }
  let firstData = true;
  for (const ev of s.transcript || []) {
    curFrames = ev.frames && ev.frames.length ? ev.frames : null;
    const dir = ev.dir === "C" ? ["C", "S"] : ["S", "C"];
    const word = (ev.text.split(/\s+/)[0] || "").slice(0, 14);
    if (ev.kind === "tls-switch") { channel = "negotiating"; add({ divider: true, label: ev.text, tone: "tls", key: "switch", channel }); continue; }
    if (ev.kind === "caps") {
      const mangled = (ev.caps || []).find((c) => /^X{3,}/.test(c) || (stripped && c.length === 8 && !/STARTTLS/.test(c) && /X/.test(c)));
      const offered = (ev.caps || []).includes("STARTTLS") || (ev.caps || []).includes("STLS");
      if (mangled) {
        add({ from: "S", to: "C", via: true, label: `${word} capabilities · ${mangled} where STARTTLS was`, pkt: "STARTTLS", pktAfter: mangled, tone: "bad", key: "capsStripped", caps: ev.caps, bad: mangled, channel: "stripped", mark: "strip" });
        channel = "stripped";
      } else {
        add({ from: "S", to: "C", label: `${word} capabilities${offered ? " · STARTTLS offered" : " · no STARTTLS"}`, pkt: offered ? "STARTTLS" : word, tone: offered ? "tls" : "clear", key: "caps", caps: ev.caps, channel, mark: "caps" });
      }
      continue;
    }
    let tone = channel === "stripped" ? "bad" : "clear", key = ev.kind;
    if (ev.kind === "banner") key = "banner";
    else if (ev.kind === "starttls") { key = ev.dir === "C" ? "starttlsC" : "starttlsS"; tone = "tls"; }
    else if (ev.kind === "strip") { key = "strip"; tone = "bad"; channel = channel === "negotiating" ? "stripped" : channel; }
    else if (ev.kind === "inject") {
      add({ from: "P", to: ev.dir === "C" ? "S" : "C", label: ev.text, pkt: "cleartext", tone: "bad", key: "inject", channel, mark: "inject" });
      continue;
    } else if (ev.kind === "auth") { tone = "bad"; key = "auth"; }
    else if (ev.kind === "data") { tone = "bad"; key = "data"; if (firstData) { firstData = false; } }
    else key = ev.dir === "C" ? "cmd" : "reply";
    add({ from: dir[0], to: dir[1], label: ev.text, pkt: word || "·", tone, key, channel, mark: ev.kind });
  }
  curFrames = null;

  if (tls) {
    const cf = tls.client_flow || [], sf = tls.server_flow || [];
    const v13 = tls.version === 0x0304;
    const hello = () => add({ from: "C", to: "S", label: "ClientHello", pkt: "ClientHello", tone: "tls", key: "ClientHello", channel: "negotiating", mark: "ClientHello",
      detail: `SNI ${tls.sni || "—"}\noffers ${(tls.client_supported_versions || []).length ? tls.client_supported_versions.map(vn).join(", ") : vn(tls.client_legacy_version)} · ${(tls.client_ciphers || []).length} cipher suites\nJA3 ${tls.ja3 || "—"}` });
    const tlsMsg = (from, name) => {
      if (/^encrypted/.test(name)) return;
      const to = from === "C" ? "S" : "C";
      if (/^Alert/.test(name)) return add({ from, to, label: name, pkt: "Alert", tone: "bad", key: "alert", channel, mark: "alert" });
      if (name === "ServerHello") return add({ from, to, label: `ServerHello · ${tls.version_name} · ${(tls.cipher_name || "").replace(/^TLS_/, "")}`, pkt: "ServerHello", tone: "tls", key: "ServerHello", channel: "negotiating", mark: "ServerHello",
        detail: `version ${tls.version_name} (legacy field ${hex(tls.server_legacy_version)}${v13 ? ", real version from extension 43" : ""})\ncipher ${tls.cipher_name || "—"}\ngroup ${groupName(tls.selected_group)}${tls.dh_bits ? ` · DH ${tls.dh_bits} bits` : ""}${!v13 ? ` · extended master secret ${tls.extended_master_secret ? "yes" : "no"}` : ""}\nJA3S ${tls.ja3s || "—"}` });
      if (name === "Certificate") {
        const leaf = chain && chain.certs && chain.certs[0];
        const swapped = devs.includes("cert_change");
        const det = leaf ? `${leaf.subject}\n  issued by ${leaf.issuer}${leaf.self_signed ? "  (itself: self-signed)" : ""}\n${leaf.key_type} ${leaf.key_bits} · ${String(leaf.signature_hash || "?").toUpperCase()} · ${leaf.not_before.slice(0, 10)} → ${leaf.not_after.slice(0, 10)}\nhostname ${chain.hostname || "?"}: ${chain.hostname_match === false ? "MISMATCH" : chain.hostname_match ? "match" : "not checked"} · trusted: ${chain.trusted === true ? "yes" : chain.trusted === false ? "no" : "unknown"}\nsha256 ${leaf.sha256.slice(0, 32)}…` : "";
        const bad = leaf && (leaf.self_signed || chain.expired || chain.hostname_match === false || chain.trusted === false || leaf.key_bits < 2048);
        if (swapped) return add({ from, to, via: true, label: "Certificate · self-signed, never seen for this endpoint", pkt: "CA cert", pktAfter: "self-signed", tone: "bad", key: "CertificateSwapped", channel: "negotiating", detail: det, mark: "Certificate" });
        return add({ from, to, label: `Certificate${leaf ? ` · ${leaf.subject.replace(/,.*$/, "")}` : ""}`, pkt: "Certificate", tone: bad ? "bad" : "tls", key: "Certificate", channel: "negotiating", detail: det, mark: "Certificate" });
      }
      if (name === "ServerKeyExchange") return add({ from, to, label: `ServerKeyExchange · ${tls.dh_bits ? `DH ${tls.dh_bits} bits` : groupName(tls.selected_group)}`, pkt: "KeyExchange", tone: tls.dh_bits && tls.dh_bits < 2048 ? "bad" : "tls", key: "ServerKeyExchange", channel: "negotiating", mark: "ServerKeyExchange" });
      return add({ from, to, label: name, pkt: name.replace(/ChangeCipherSpec/, "CCS").slice(0, 14), tone: "tls", key: EXPLAIN[name] ? name : "ChangeCipherSpec", channel: "negotiating", mark: name });
    };
    if (cf.length) hello();
    const sBefore = sf.slice(0, sf.indexOf("ChangeCipherSpec") >= 0 ? sf.indexOf("ChangeCipherSpec") : sf.length);
    sBefore.forEach((n) => tlsMsg("S", n));
    if (!tls.server_hello_seen) add({ from: "S", to: "C", label: "no ServerHello: the handshake failed", pkt: "✕", tone: "bad", key: "alert", channel, mark: "alert" });
    else if (v13) {
      add({ from: "S", to: "C", label: "ChangeCipherSpec · encrypted: EncryptedExtensions, Certificate, Finished", pkt: "encrypted", tone: "tls", key: "enc13", channel: "negotiating", mark: "enc13" });
      add({ from: "C", to: "S", label: "ChangeCipherSpec · Finished (encrypted)", pkt: "Finished", tone: "tls", key: "Finished", channel: "encrypted", mark: "Finished" });
    } else {
      cf.slice(1).filter((n) => !/^encrypted/.test(n)).forEach((n) => tlsMsg("C", n));
      if (cf.some((n) => /^encrypted/.test(n))) add({ from: "C", to: "S", label: "Finished (encrypted)", pkt: "Finished", tone: "tls", key: "Finished", channel: "negotiating", mark: "Finished" });
      if (sf.includes("ChangeCipherSpec")) add({ from: "S", to: "C", label: "ChangeCipherSpec · Finished (encrypted)", pkt: "Finished", tone: "tls", key: "Finished", channel: "encrypted", mark: "Finished" });
    }
    if (tls.server_hello_seen) add({ from: "C", to: "S", both: true, label: "application data · commands, credentials and mail inside TLS", pkt: "▮▮▮", tone: "tls", key: "appdata", channel: "encrypted", mark: "appdata" });
  } else if (s.mode !== "implicit") {
    add({ divider: true, label: "connection closes · nothing in this session was encrypted", tone: channel === "stripped" ? "bad" : "clear", key: "close", channel });
  }
  // attach findings to the step that triggers them
  const fs = rep.findings.filter((f) => f.session_id === s.session_id);
  const findIdx = (pred) => { const i = steps.findIndex(pred); return i < 0 ? steps.length - 1 : i; };
  const at = (f) => {
    const id = f.rule_id;
    if (/STRIP|BASE-001|PLAIN-00[123]/.test(id)) return findIdx((st) => st.key === "capsStripped" || st.key === "strip") !== steps.length - 1 ? findIdx((st) => st.key === "capsStripped" || st.key === "strip") : findIdx((st) => st.key === "caps");
    if (/CRED/.test(id)) return findIdx((st) => st.key === "auth" && /redacted/.test(st.label));
    if (/DATA/.test(id)) return findIdx((st) => st.key === "data");
    if (/INJ/.test(id)) return findIdx((st) => st.key === "inject");
    if (/CERT|BASE-002/.test(id)) return findIdx((st) => st.mark === "Certificate" || st.key === "enc13");
    if (/TLS-00[6]|TLS-011/.test(id)) return findIdx((st) => st.key === "ClientHello");
    if (/TLS|BASE-00[34]/.test(id)) return findIdx((st) => st.key === "ServerHello" || st.key === "ServerKeyExchange" && /TLS-005/.test(id));
    if (/PORT|TCP/.test(id)) return 0;
    return steps.length - 1;
  };
  fs.forEach((f) => { const i = Math.max(0, at(f)); (steps[i].findings = steps[i].findings || []).push(f); });
  return steps;
}

const vn = (v) => ({ 0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0" }[v] || (v ? `0x${v.toString(16)}` : "—"));
const hex = (v) => (v ? `0x${v.toString(16).padStart(4, "0")}` : "—");
const groupName = (g) => ({ 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048" }[g] || (g ? `group ${g}` : "—"));

async function viewSession(id, sid) {
  app.innerHTML = `<div class="empty">Loading session…</div>`;
  let rep;
  try { rep = await getReport(id); } catch (e) {
    app.innerHTML = `<div class="empty">That report is no longer in memory. <a href="#/">Start a new analysis</a>.</div>`;
    return;
  }
  const r = rep.sessions.find((x) => x.session.session_id === sid);
  if (!r) { app.innerHTML = `<div class="empty">No session ${esc(sid)} in this report. <a href="#/r/${esc(id)}">Back to the report</a>.</div>`; return; }
  const s = r.session, tls = r.tls, c = classify(r);
  const steps = buildSteps(r, rep);
  const fs = rep.findings.filter((f) => f.session_id === sid).sort((a, b) => (b.risk || 0) - (a.risk || 0));
  const hasPath = steps.some((st) => st.via || st.from === "P");
  document.title = `${sid} · ${s.endpoint} · SecureMailScope`;
  const order = rep.sessions.map((x) => x.session.session_id);
  const idx = order.indexOf(sid);
  const prev = order[idx - 1], next = order[idx + 1];

  app.innerHTML = shell(rep, id, "sessions", `
  <div class="stack" style="gap:24px">
  <section class="rep-head reveal">
    <div style="min-width:0">
      <div class="crumb"><a href="#/r/${esc(id)}/sessions">← Sessions</a></div>
      <h1><span class="faint">${esc(sid)}</span> ${esc(s.client[0])} → ${esc(s.endpoint)}</h1>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <span class="tag s-neutral">${esc(s.protocol)} · port ${s.server[1]}</span>
        <span class="tag ${c.kind === "bad" ? "s-critical" : c.kind === "clear" ? "s-high" : "s-ok"}">${esc(c.label)}</span>
        ${tls && tls.cipher_name ? `<span class="tag s-neutral mono">${esc(tls.cipher_name.replace(/^TLS_/, ""))}</span>` : ""}
        <span class="tag s-neutral">${esc(utc(s.start_ts))}</span>
      </div>
    </div>
    <div style="display:flex;gap:28px;align-items:flex-end">
      <div style="text-align:right"><div class="muted" style="font-size:13px">Session risk</div><div id="srisk" style="font-family:var(--display);font-size:48px;font-weight:600;line-height:1;margin-top:6px;color:${(r.risk || 0) >= 70 ? "var(--crit-ink)" : (r.risk || 0) >= 35 ? "var(--high-ink)" : "var(--accent-ink)"}">0</div></div>
      <div style="text-align:right"><div class="muted" style="font-size:13px">Anomaly score</div><div style="font-family:var(--display);font-size:48px;font-weight:600;line-height:1;margin-top:6px">${r.anomaly_score != null ? r.anomaly_score.toFixed(2) : "—"}</div></div>
    </div>
  </section>

  <section class="sess-grid">
    <div class="card reveal" style="overflow:hidden;animation-delay:.05s">
      <div class="replay-top">
        <h2>Handshake replay</h2>
        <span class="chanbadge" id="chan"></span>
      </div>
      <div class="lanes" aria-hidden="true">
        <div class="lane-head"><div class="box" style="color:var(--muted)">${icon.client}</div><b>Client</b><span>${esc(s.client[0])}:${s.client[1]}</span></div>
        <div class="lane-head"><div class="box" id="pathbox" style="color:var(--faint)">${icon.path}</div><b id="pathname">Network path</b><span id="pathsub">${hasPath ? "watch this" : "passive observer"}</span></div>
        <div class="lane-head"><div class="box" style="color:var(--muted)">${icon.server}</div><b>Server</b><span>${esc(s.endpoint)}</span></div>
      </div>
      <div class="ladder" id="ladder"><div class="mid"></div>${steps.map((st, i) => rungHtml(st, i)).join("")}</div>
      <div class="controls">
        <button class="btn icon" id="rrestart" aria-label="Restart">${icon.restart}</button>
        <button class="btn icon" id="rback" aria-label="Previous step">${icon.back}</button>
        <button class="btn icon primary" id="rplay" aria-label="Play">${icon.play}</button>
        <button class="btn icon" id="rfwd" aria-label="Next step">${icon.fwd}</button>
        <label class="sr" for="rspeed">Speed</label>
        <select class="speed" id="rspeed"><option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option></select>
        <label class="sr" for="rscrub">Step</label>
        <input type="range" class="scrub" id="rscrub" min="0" max="${steps.length}" value="0">
        <span class="step-n" id="stepn">0 / ${steps.length}</span>
      </div>
    </div>

    <div class="side">
      <div class="card reveal explain-card" style="animation-delay:.08s"><div class="explain" id="explain" aria-live="polite"></div></div>
      <div class="card reveal seg-card" style="animation-delay:.12s">
        <div class="seg" role="tablist" aria-label="Session details">
          <button type="button" role="tab" id="tab-f" aria-controls="panel-f" aria-selected="true" data-seg="f">Findings <span class="cnt${fs.some((f) => f.severity === "critical") ? " hot" : ""}">${fs.length}</span></button>
          <button type="button" role="tab" id="tab-w" aria-controls="panel-w" aria-selected="false" data-seg="w">Why this score</button>
          <button type="button" role="tab" id="tab-c" aria-controls="panel-c" aria-selected="false" data-seg="c">Connection</button>
          <button type="button" role="tab" id="tab-p" aria-controls="panel-p" aria-selected="false" data-seg="p">Packets <span class="cnt">${(rep.packets || []).filter((x) => x.session === sid).length}</span></button>
        </div>
        <div class="seg-body">
        <div class="seg-panel" id="panel-f" role="tabpanel" aria-labelledby="tab-f" data-panel="f">
        <div class="faint" style="font-size:12.5px">Each finding lights up when the replay reaches the step that triggers it.</div>
        ${fs.length ? fs.map((f) => `<div class="sfind dim" data-rule="${esc(f.rule_id)}">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">${sevChip(f.severity)}<span class="mono faint" style="font-size:12px">${esc(f.rule_id)} · risk ${Math.round(f.risk || 0)}</span></div>
          <h4>${esc(f.title)}</h4>
          ${f.escalated_from ? `<p style="color:var(--crit-ink)">Escalated from ${esc(f.escalated_from)} by the endpoint baseline.</p>` : ""}
          <p>${esc(f.evidence[0] || "")}</p>
          <details><summary style="cursor:pointer;font-size:13px;color:var(--accent)">Fix and compliance</summary><p style="margin-top:8px">${code(f.remediation)}</p>${f.compliance.length ? `<p class="faint" style="font-size:12.5px;margin-top:6px">${esc(f.compliance.join(" · "))}</p>` : ""}</details>
        </div>`).join("") : `<p class="muted" style="margin:0">No findings: this session is clean.</p>`}
        </div>
        <div class="seg-panel" id="panel-w" role="tabpanel" aria-labelledby="tab-w" data-panel="w" hidden>
        ${r.model_risk != null ? `<div><h3 style="font-family:var(--display);font-size:18px">The model scored it ${r.model_risk.toFixed(1)}</h3><div class="faint" style="font-size:13px;margin-top:4px">Exact Shapley values over feature groups. They add up to the score.</div></div>
        ${xbars(r.explanation)}` : `<p class="muted" style="margin:0">The risk model was skipped for this analysis (rules and baseline only).</p>`}
        </div>
        <div class="seg-panel" id="panel-c" role="tabpanel" aria-labelledby="tab-c" data-panel="c" hidden>
        <dl class="kv">
          <dt>Banner</dt><dd class="mono" style="font-size:12.5px">${esc(s.banner || (s.mode === "implicit" ? "(encrypted from byte one)" : "—"))}</dd>
          <dt>TCP stream</dt><dd>${s.stream_quality.retransmissions} retransmissions · ${s.stream_quality.out_of_order} out of order · ${s.stream_quality.overlaps_trimmed} overlaps trimmed · ${s.stream_quality.gaps} gaps</dd>
          <dt>Client role</dt><dd>${esc(s.stream_quality.client_role)}</dd>
          ${tls ? `<dt>JA3 / JA3S</dt><dd class="mono" style="font-size:12px">${esc(tls.ja3 || "—")}<br>${esc(tls.ja3s || "—")}</dd>` : ""}
          ${r.certificate_chain ? `<dt>Certificate</dt><dd>${esc(r.certificate_chain.present ? `${r.certificate_chain.certs[0].subject} · trust: ${r.certificate_chain.trust_detail || "—"}` : r.certificate_chain.reason_absent || "—")}</dd><dt>Revocation</dt><dd class="faint">${esc(r.certificate_chain.revocation)}</dd>` : ""}
          ${(r.baseline_deviations || []).length ? `<dt>Baseline</dt><dd style="color:var(--crit-ink)">${esc(r.baseline_deviations.map((d) => ({ starttls_drop: "STARTTLS vanished", cert_change: "certificate changed", downgrade: "downgraded", new_ja3s: "new server fingerprint" }[d] || d)).join(" · "))}</dd>` : ""}
          ${s.notes.length ? `<dt>Notes</dt><dd>${esc(s.notes.join(" · "))}</dd>` : ""}
        </dl>
        <div style="display:flex;justify-content:space-between;gap:12px;margin-top:4px">
          ${prev ? `<a class="btn" href="#/r/${esc(id)}/s/${esc(prev)}">← ${esc(prev)}</a>` : "<span></span>"}
          ${next ? `<a class="btn" href="#/r/${esc(id)}/s/${esc(next)}">${esc(next)} →</a>` : ""}
        </div>
        </div>
        <div class="seg-panel" id="panel-p" role="tabpanel" aria-labelledby="tab-p" data-panel="p" hidden>
        ${(() => {
          const pk = (rep.packets || []).filter((x) => x.session === sid);
          if (!pk.length) return `<p class="muted" style="margin:0">No packet rows for this session.</p>`;
          const t0 = pk[0].ts;
          return `<div class="faint" style="font-size:12.5px">The frames this session is made of. The replay
            highlights the ones carrying the current step; click any row to jump the replay to it.</div>
            <div class="pk-panel" id="sesspk">${pk.map((x) =>
              packetRowHtml(rep, x, id, { t0, compact: true, noLink: true })).join("")}</div>
            <div class="faint" style="font-size:12.5px"><a href="#/r/${esc(id)}/capture">See these in the whole capture →</a></div>`;
        })()}
        </div>
        </div>
      </div>
    </div>
  </section>
  </div>`, sid);
  const onSess = $(".side-sess a.on");
  if (onSess) onSess.scrollIntoView({ block: "nearest" });

  afterPaint(() => countUp($("#srisk"), Math.round(r.risk || 0), 1200));
  const tabs = $$(".seg [role=tab]");
  tabs.forEach((b) => b.addEventListener("click", () => {
    tabs.forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    $$(".seg-panel").forEach((pn) => (pn.hidden = pn.dataset.panel !== b.dataset.seg));
    if (b.dataset.seg === "w") afterPaint(() => $$(".xrow .track span").forEach((el) => (el.style.width = `${el.dataset.w}%`)));
  }));
  $(".seg").addEventListener("keydown", (e) => {          // arrow keys move between tabs
    const i = tabs.indexOf(document.activeElement);
    if (i < 0 || !["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    e.stopPropagation();
    const n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    n.focus(); n.click();
  });
  const player = new Replay(steps, s);
  player.bindPackets();
  player.lightPackets(steps[player.i - 1]);
  teardown.push(() => player.destroy());
}

function rungHtml(st, i) {
  if (st.divider) return `<div class="rung divider tone-${st.tone}" data-i="${i}"><div class="rule"></div><span class="lbl tone-${st.tone}">${esc(st.label)}</span></div>`;
  const a = LANE[st.via ? st.from : st.from], b = LANE[st.to];
  const left = Math.min(a, b), width = Math.abs(b - a);
  const dirCls = b > a ? "r" : "l";
  const both = st.both ? `<div class="arrow l tone-${st.tone}" style="left:${left}%;width:${width}%;top:44px;background:currentColor;opacity:.6"></div>` : "";
  return `<div class="rung" data-i="${i}" title="${esc(st.label)}">
    <span class="lbl tone-${st.tone}" style="left:${(a + b) / 2}%">${esc(st.label)}</span>
    <div class="arrow ${dirCls} tone-${st.tone}" style="left:${left}%;width:${width}%;background:currentColor"></div>${both}
  </div>`;
}

function xbars(expl) {
  if (!expl || !expl.length) return `<p class="muted" style="margin:0">No feature group moves this score by more than half a point.</p>`;
  const max = Math.max(...expl.map((e) => Math.abs(e.contribution)), 1);
  return `<div style="display:flex;flex-direction:column;gap:12px">${expl.map((e) => {
    const w = (100 * Math.abs(e.contribution)) / max, pos = e.contribution >= 0;
    return `<div class="xrow"><span class="muted">${esc(e.feature[0].toUpperCase() + e.feature.slice(1))}</span><span class="track"><span data-w="${w}" style="left:0;background:${pos ? C.bad : C.accent}"></span></span><span class="mono" style="text-align:right;color:${pos ? "var(--text)" : "var(--accent-ink)"}">${pos ? "+" : "−"}${Math.abs(e.contribution).toFixed(1)}</span></div>`;
  }).join("")}</div><div class="faint" style="font-size:12.5px">Red raises risk, mint lowers it.</div>`;
}

class Replay {
  constructor(steps, sess) {
    this.steps = steps; this.sess = sess; this.i = 0; this.playing = false; this.speed = 1;
    this.rungs = $$("#ladder .rung");
    this.ladder = $("#ladder");
    this.btn = $("#rplay");
    this.btn.addEventListener("click", () => (this.playing ? this.pause() : this.play()));
    $("#rfwd").addEventListener("click", () => { this.pause(); this.go(this.i + 1, true); });
    $("#rback").addEventListener("click", () => { this.pause(); this.go(this.i - 1, false); });
    $("#rrestart").addEventListener("click", () => { this.go(0, false); this.play(); });
    $("#rspeed").addEventListener("change", (e) => (this.speed = +e.target.value));
    $("#rscrub").addEventListener("input", (e) => { this.pause(); this.go(+e.target.value, false); });
    this.rungs.forEach((el) => el.addEventListener("click", () => { this.pause(); this.go(+el.dataset.i + 1, true); }));
    this.keys = (e) => {
      if (/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) return;
      if (e.key === "ArrowRight") { this.pause(); this.go(this.i + 1, true); }
      else if (e.key === "ArrowLeft") { this.pause(); this.go(this.i - 1, false); }
      else if (e.key === " ") { e.preventDefault(); this.playing ? this.pause() : this.play(); }
    };
    this.ladderKeys = this.keys;
    document.addEventListener("keydown", this.keys);
    this.go(0, false);
    if (REDUCED) this.go(steps.length, false);
    else this.startTimer = setTimeout(() => this.play(), 700);
  }

  destroy() { this.pause(); clearTimeout(this.startTimer); document.removeEventListener("keydown", this.keys); }

  play() {
    if (this.i >= this.steps.length) this.go(0, false);
    this.playing = true;
    this.btn.innerHTML = icon.pause; this.btn.setAttribute("aria-label", "Pause");
    this.tick();
  }

  pause() {
    this.playing = false;
    clearTimeout(this.timer);
    if (this.btn) { this.btn.innerHTML = icon.play; this.btn.setAttribute("aria-label", "Play"); }
  }

  tick() {
    if (!this.playing) return;
    if (this.i >= this.steps.length) { this.pause(); return; }
    this.go(this.i + 1, true);
    const st = this.steps[this.i - 1];
    const base = st.divider ? 900 : st.via ? 2300 : st.findings ? 2000 : 1300;
    this.timer = setTimeout(() => this.tick(), base / this.speed);
  }

  go(n, animate) {
    n = Math.max(0, Math.min(this.steps.length, n));
    this.i = n;
    this.rungs.forEach((el, k) => {
      el.classList.toggle("past", k < n - 1);
      el.classList.toggle("now", k === n - 1);
      $$(".pkt, .boom", el).forEach((x) => x.remove());
    });
    $("#rscrub").value = String(n);
    $("#stepn").textContent = `${n} / ${this.steps.length}`;
    const st = this.steps[n - 1];
    this.channel(st ? st.channel : this.sess.mode === "implicit" ? "negotiating" : "clear");
    this.pathState(n);
    this.explain(st);
    this.lightFindings(n);
    this.lightPackets(st);
    if (st && !st.divider) {
      const el = this.rungs[n - 1];
      if (animate && !REDUCED) this.fly(el, st);
      const top = el.offsetTop - this.ladder.clientHeight / 2 + 40;
      this.ladder.scrollTop = Math.max(0, top);
    }
  }

  lightPackets(st) {
    const panel = $("#sesspk");
    if (!panel) return;
    const want = new Set(st && st.frames ? st.frames : []);
    let first = null;
    $$(".pk-row", panel).forEach((el) => {
      const on = want.has(+el.dataset.frame);
      el.classList.toggle("now", on);
      if (on && !first) first = el;
    });
    // Only scroll when the panel is the visible one, so switching tabs does not
    // yank a list the analyst is reading.
    if (first && !$("#panel-p").hidden) {
      const top = first.offsetTop - panel.clientHeight / 2 + 12;
      panel.scrollTop = Math.max(0, top);
    }
  }

  bindPackets() {
    const panel = $("#sesspk");
    if (!panel) return;
    $$(".pk-row", panel).forEach((el) => {
      const frame = +el.dataset.frame;
      // Jump to the first step that names this frame.
      const i = this.steps.findIndex((st) => st.frames && st.frames.includes(frame));
      if (i < 0) { el.classList.add("nostep"); return; }
      el.classList.add("clickable");
      el.setAttribute("title", `Jump the replay to: ${this.steps[i].label}`);
      el.addEventListener("click", () => { this.pause(); this.go(i + 1, false); });
    });
  }

  fly(el, st) {
    const pkt = document.createElement("span");
    const startTone = st.via ? (st.tone === "bad" ? "clear" : st.tone) : st.tone;
    pkt.className = `pkt tone-${startTone}`;
    pkt.textContent = st.pkt || "·";
    el.appendChild(pkt);
    const a = LANE[st.from], b = LANE[st.to];
    const dur = (st.via ? 1700 : 850) / this.speed;
    if (st.via) {
      const anim = pkt.animate([{ left: `${a}%` }, { left: `${LANE.P}%`, offset: 0.45 }, { left: `${LANE.P}%`, offset: 0.6 }, { left: `${b}%` }], { duration: dur, easing: "ease-in-out", fill: "forwards" });
      this.morph = setTimeout(() => {
        pkt.textContent = st.pktAfter || st.pkt;
        pkt.className = `pkt tone-${st.tone}`;
        const boom = document.createElement("span");
        boom.className = "boom";
        el.appendChild(boom);
        $("#pathbox").classList.add("alarm");
      }, dur * 0.5);
      anim.onfinish = () => pkt.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 500, delay: 600, fill: "forwards" });
    } else if (st.both) {
      pkt.animate([{ left: `${a}%` }, { left: `${b}%` }, { left: `${a}%` }], { duration: dur * 1.8, easing: "ease-in-out", fill: "forwards" }).onfinish = () => pkt.remove();
    } else {
      pkt.animate([{ left: `${a}%`, opacity: 0 }, { opacity: 1, offset: 0.1 }, { left: `${b}%`, opacity: 1 }], { duration: dur, easing: "cubic-bezier(.4,0,.2,1)", fill: "forwards" })
        .onfinish = () => pkt.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 400, delay: 300, fill: "forwards" });
    }
  }

  channel(state) {
    const el = $("#chan");
    const map = {
      clear: ["s-high", icon.unlock, "Cleartext · readable on the path"],
      negotiating: ["s-ok", icon.lock, "Negotiating TLS"],
      encrypted: ["s-ok", icon.lock, "Encrypted"],
      stripped: ["s-critical", icon.alert, "Cleartext · upgrade stripped"],
    };
    const [cls, ic, txt] = map[state] || map.clear;
    el.className = `chanbadge ${cls}`;
    el.innerHTML = `${ic}<span>${txt}</span>`;
  }

  pathState(n) {
    const hit = this.steps.slice(0, n).find((st) => st.via || st.from === "P");
    const box = $("#pathbox");
    if (hit) {
      box.style.color = "var(--crit-ink)";
      $("#pathname").textContent = "Interceptor?";
      $("#pathname").style.color = "var(--crit-ink)";
      $("#pathsub").textContent = hit.key === "inject" ? "cleartext inserted" : hit.key === "CertificateSwapped" ? "certificate substituted" : "offer rewritten";
    } else {
      box.classList.remove("alarm");
      box.style.color = "var(--faint)";
      $("#pathname").textContent = "Network path";
      $("#pathname").style.color = "";
      $("#pathsub").textContent = "passive observer";
    }
  }

  explain(st) {
    const box = $("#explain");
    if (!st) {
      box.innerHTML = `<h3>Press play to replay this session</h3><p>Each step is reconstructed from the capture: TCP, the ${esc(this.sess.protocol)} dialogue, the STARTTLS upgrade and the TLS handshake. Use ← → or the space bar to step through.</p>`;
      return;
    }
    const [title, body] = EXPLAIN[st.key] || [st.label, ""];
    const caps = st.caps ? `<div class="capchips">${st.caps.map((c) => `<span class="${c === st.bad ? "bad" : /STARTTLS|STLS/.test(c) ? "hot" : ""}">${esc(c)}</span>`).join("")}</div>` : "";
    const det = st.detail ? `<div class="detail">${esc(st.detail)}</div>` : !st.divider ? `<div class="detail">${esc(st.label)}</div>` : "";
    const fired = st.findings ? `<div class="fired">${st.findings.map((f) => `${sevChip(f.severity)}<span style="font-size:13.5px;align-self:center">${esc(f.title.replace(/ \(deviates.*\)$/, ""))}</span>`).join('<span style="width:100%"></span>')}</div>` : "";
    box.innerHTML = `<h3>${esc(title)}</h3><p>${esc(body)}</p>${caps}${det}${fired}`;
  }

  lightFindings(n) {
    const fired = new Set(this.steps.slice(0, n).flatMap((st) => (st.findings || []).map((f) => f.rule_id)));
    const now = new Set(((this.steps[n - 1] || {}).findings || []).map((f) => f.rule_id));
    $$(".sfind").forEach((el) => {
      el.classList.toggle("dim", !fired.has(el.dataset.rule));
      el.classList.toggle("lit", now.has(el.dataset.rule));
    });
  }
}

route();
})();
