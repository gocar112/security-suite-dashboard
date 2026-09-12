/* Security Suite dashboard - vanilla JS, fed by /api/* and an SSE stream. */
"use strict";

const $ = (id) => document.getElementById(id);
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
  low: "var(--low)", info: "var(--info)",
};

let state = {
  findings: [], selected: null, paused: false, lastStats: null, feedSeeded: false,
  sensitivity: Number(localStorage.getItem("suite-sensitivity") || 72),
  focusMode: localStorage.getItem("suite-focus") === "true",
  toneEnabled: localStorage.getItem("suite-tone") === "true",
  audioContext: null,
};

/* ------------------------------------------------------------------ utils */
function esc(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function clockOf(iso) {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  return isNaN(d) ? String(iso).slice(11, 19) : d.toLocaleTimeString([], { hour12: false });
}

function bytes(n) {
  if (n === undefined || n === null) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
}

function duration(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

function shortPath(value) {
  // Collapse the middle of a long path. Folder names containing spaces
  // otherwise wrap at every space and shred the column.
  const full = String(value || "");
  if (full.length <= 48) return full;
  const sep = full.indexOf("\\") >= 0 ? "\\" : "/";
  const parts = full.split(/[\\/]/).filter(Boolean);
  if (parts.length <= 3) return full;
  return parts[0] + sep + "\u2026" + sep + parts.slice(-2).join(sep);
}

function baseName(p) {
  return String(p || "").split(/[\\/]/).pop() || String(p || "");
}

function toast(message, isError) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " err" : "");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.status + " " + res.statusText);
  return data;
}

const post = (path, payload) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });

/* -------------------------------------------------------------------- KPI */
function renderStats(stats, monitor) {
  stats = stats || {};
  state.lastStats = stats;
  $("kpi-scanned").textContent = stats.files_scanned || 0;
  $("kpi-matches").textContent = stats.matches || 0;
  $("kpi-open").textContent = stats.open_alerts || 0;
  const sev = stats.by_severity || {};
  $("kpi-sev").textContent = (sev.critical || 0) + (sev.high || 0);
  $("kpi-sev-sub").textContent = (sev.critical || 0) + " critical, " + (sev.high || 0) + " high";
  $("kpi-uptime").textContent = duration(stats.uptime_seconds);
  $("kpi-scanned-sub").textContent = stats.errors ? stats.errors + " scan errors" : "session total";
  $("kpi-uptime-sub").textContent = bytes(stats.log_size) + " logged";

  renderBreakdown(sev, stats.matches || 0);
  renderTopRules(stats.top_rules || []);
  renderBars(stats.timeline || []);
  renderPosture(stats);

  if (monitor) {
    state.paused = !!monitor.paused;
    const dot = $("mon-dot"), text = $("mon-text");
    dot.className = "dot " + (!monitor.running ? "down" : monitor.paused ? "warn" : "live");
    text.textContent = !monitor.running ? "monitor stopped"
      : monitor.paused ? "monitor paused"
      : "watching " + monitor.tracked_files + " files";
    $("btn-monitor").textContent = monitor.paused ? "Resume" : "Pause";
  }
}

function playTone(level = "info") {
  if (!state.toneEnabled) return;
  try {
    const AudioCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtor) return;
    state.audioContext = state.audioContext || new AudioCtor();
    if (state.audioContext.state === "suspended") state.audioContext.resume();
    const ctx = state.audioContext;
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    const urgent = level === "critical" || level === "high";
    osc.type = urgent ? "triangle" : "sine";
    osc.frequency.setValueAtTime(urgent ? 220 : 520, now);
    osc.frequency.exponentialRampToValueAtTime(urgent ? 110 : 760, now + .2);
    gain.gain.setValueAtTime(.0001, now);
    gain.gain.exponentialRampToValueAtTime(urgent ? .07 : .035, now + .018);
    gain.gain.exponentialRampToValueAtTime(.0001, now + .24);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now);
    osc.stop(now + .25);
  } catch (_) { /* sound is an optional operator aid */ }
}

function syncControls() {
  const range = $("sensitivity");
  if (range) {
    range.value = state.sensitivity;
    $("sensitivity-value").textContent = state.sensitivity + "%";
  }
  const focus = $("focus-mode"), tone = $("event-tone"), audio = $("audio-toggle");
  if (focus) focus.checked = state.focusMode;
  if (tone) tone.checked = state.toneEnabled;
  if (audio) {
    audio.setAttribute("aria-pressed", String(state.toneEnabled));
    $("audio-label").textContent = state.toneEnabled ? "sound on" : "sound off";
  }
  document.body.classList.toggle("focus-mode", state.focusMode);
}

async function loadIntel() {
  try {
    const data = await api("/api/intel");
    const sources = data.sources || [];
    let live = 0;
    sources.forEach((source) => {
      const card = document.querySelector('[data-source="' + source.id + '"]');
      const state = card && card.querySelector(".source-state");
      if (state) state.textContent = source.status || "linked";
      if (!card) return;
      const online = source.status === "online";
      const degraded = ["offline", "rejected", "rate limited", "syncing"].includes(source.status);
      if (online) live += 1;
      card.classList.toggle("is-online", online);
      card.classList.toggle("is-degraded", degraded);
      card.classList.toggle("is-linked", !online && !degraded && card.dataset.live !== "1");
      if (source.detail) card.title = source.detail;
    });
    const adapters = sources.filter((s) => s.id === "nvd" || s.id === "osv" || s.id === "virustotal").length;
    const linked = sources.length - adapters;
    if ($("strip-note")) {
      $("strip-note").textContent = live + " of " + adapters + " adapters online \u00b7 " +
        linked + " linked references";
    }
    if ($("meta-adapters")) {
      $("meta-adapters").textContent = live + "/" + adapters + " intel adapters live";
    }
    $("intel-status").textContent = data.status || "linked";
    $("intel-sync").textContent = "Synced " + clockOf(data.synced_at);
  } catch (_) {
    // The source lattice still renders when the optional adapter endpoint is offline.
    $("intel-status").textContent = "local mode";
    $("intel-sync").textContent = "Local adapters ready";
  }
}

function renderPosture(stats) {
  const sev = stats.by_severity || {};
  const open = Number(stats.open_alerts || 0);
  const pressure = (Number(sev.critical || 0) * 22) +
    (Number(sev.high || 0) * 11) + (Number(sev.medium || 0) * 4) + (open * 1.5);
  const score = Math.max(0, Math.min(100, Math.round(100 - pressure)));
  const arc = $("score-arc");
  if (arc) {
    const circumference = 2 * Math.PI * 86;
    arc.style.strokeDasharray = circumference.toFixed(1);
    arc.style.strokeDashoffset = (circumference * (1 - score / 100)).toFixed(1);
    arc.style.stroke = score < 45 ? "var(--coral)" : score < 75 ? "var(--amber)" : "var(--teal)";
  }
  $("mission-score").textContent = score;
  const label = score < 45 ? "fragile" : score < 75 ? "stable" : "clear";
  $("mission-label").textContent = label;
  $("mission-label").style.color = score < 45 ? "var(--coral)" : score < 75 ? "var(--amber)" : "var(--teal)";
  $("mission-context").textContent = (state.focusMode ? "focus / " : "local / ") + label;
}

function renderBreakdown(sev, total) {
  const max = Math.max(1, total || 0);
  $("sev-breakdown").innerHTML = SEVS.map((name) => {
    const count = sev[name] || 0;
    const pct = Math.round((count / max) * 100);
    return '<div class="meter"><div class="top"><span class="sev sev-' + name + '">' + name +
      '</span><span class="dim">' + count + '</span></div><div class="track"><div class="fill" style="width:' +
      pct + '%; background:' + SEV_COLOR[name] + '"></div></div></div>';
  }).join("");
}

function renderTopRules(rows) {
  const el = $("top-rules");
  if (!rows.length) { el.innerHTML = '<span class="faint">No hits yet.</span>'; return; }
  const max = rows[0][1] || 1;
  el.innerHTML = rows.map(([name, count]) =>
    '<div class="row"><span class="name">' + esc(name) + '</span>' +
    '<span class="meta">' + count + ' hit' + (count === 1 ? "" : "s") + '</span></div>' +
    '<div class="track" style="height:4px;background:var(--panel-2);border-radius:3px;overflow:hidden">' +
    '<div style="height:100%;width:' + Math.round((count / max) * 100) +
    '%;background:var(--accent)"></div></div>'
  ).join("");
}

function renderBars(timeline) {
  const max = Math.max(1, ...timeline.map((b) => b.count));
  $("bars").innerHTML = timeline.map((b) =>
    '<div class="' + (b.count ? "hot" : "") + '" style="height:' +
    Math.max(2, Math.round((b.count / max) * 100)) + '%" title="' +
    b.count + ' detection(s), ' + b.minutes_ago + 'm ago"></div>'
  ).join("");
}

/* --------------------------------------------------------------- findings */
function rowHtml(finding) {
  const sev = finding.severity || (finding.event_type === "error" ? "low" : "info");
  const rules = (finding.rule_names || (finding.matches || []).map((m) => m.rule) || []);
  const label = finding.event_type === "yara_match" ? sev
    : finding.event_type === "error" ? "error" : "clean";
  const sevClass = finding.event_type === "yara_match" ? "sev-" + sev
    : finding.event_type === "error" ? "sev-medium" : "sev-info";
  const status = finding.status || "new";
  return '<tr data-id="' + esc(finding.id) + '">' +
    '<td><span class="sev ' + sevClass + '">' + esc(label) + '</span></td>' +
    '<td class="mono dim">' + clockOf(finding.timestamp) + '</td>' +
    '<td class="file-cell"><div class="mono path">' + esc(baseName(finding.file_path)) + '</div>' +
    '<div class="faint path-full" title="' + esc(finding.file_path || "") + '">' +
      esc(shortPath(finding.file_path) || finding.message || "") + '</div></td>' +
    '<td class="rules-cell">' + (rules.length
      ? rules.map((r) => "<code>" + esc(r) + "</code>").join("")
      : '<span class="faint">-</span>') + '</td>' +
    '<td class="mono status-' + esc(status) + '">' + esc(status.replace("_", " ")) + '</td></tr>';
}

function renderRows(findings) {
  state.findings = findings;
  $("rows").innerHTML = findings.map(rowHtml).join("");
  $("empty").style.display = findings.length ? "none" : "block";
  $("findings-count").textContent = findings.length + " shown";
}

async function loadFindings() {
  const params = new URLSearchParams({
    limit: "300",
    severity: $("f-sev").value,
    status: $("f-status").value,
    type: $("f-type").value,
    q: $("q").value.trim(),
  });
  try {
    const data = await api("/api/findings?" + params.toString());
    renderRows(data.findings || []);
    if (!state.feedSeeded) {
      // Oldest first so the newest line ends up on top of the feed.
      (data.findings || []).slice(0, 25).reverse().forEach(feedLine);
      state.feedSeeded = true;
    }
  } catch (err) {
    toast("Could not load findings: " + err.message, true);
  }
}

function matchesFilters(finding) {
  const sev = $("f-sev").value, status = $("f-status").value, type = $("f-type").value;
  const q = $("q").value.trim().toLowerCase();
  if (type !== "all" && finding.event_type !== type) return false;
  if (sev !== "all" && finding.severity !== sev) return false;
  if (status !== "all" && (finding.status || "new") !== status) return false;
  if (q && !JSON.stringify(finding).toLowerCase().includes(q)) return false;
  return true;
}

/* ----------------------------------------------------------------- drawer */
function openDrawer(id) {
  const finding = state.findings.find((f) => f.id === id);
  if (!finding) return;
  state.selected = id;
  document.querySelectorAll("#rows tr").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === id));

  const matches = finding.matches || [];
  const tele = finding.telemetry || {};
  const events = tele.events || [];
  const sev = finding.severity || "info";

  const html =
    '<h3>Verdict</h3>' +
    '<div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap">' +
      '<span class="sev sev-' + sev + '">' + esc(sev) + '</span>' +
      '<span class="mono">' + esc(finding.event_type) + '</span>' +
      '<span class="faint mono">' + esc(finding.timestamp) + '</span>' +
      '<span class="faint mono">trigger: ' + esc(finding.trigger || "-") + '</span>' +
    '</div>' +
    '<h3>File</h3>' +
    '<dl class="kv">' +
      '<dt>Path</dt><dd class="mono">' + esc(finding.file_path || "-") + '</dd>' +
      '<dt>SHA-256</dt><dd class="mono">' + esc(finding.sha256 || "-") + '</dd>' +
      '<dt>Size</dt><dd>' + bytes(finding.file_size) + '</dd>' +
      '<dt>Entropy</dt><dd>' + esc(finding.entropy ?? "-") +
        (finding.entropy > 7.2 ? ' <span class="sev sev-medium">packed?</span>' : '') + '</dd>' +
      '<dt>Modified</dt><dd class="mono">' + esc(finding.modified || "-") + '</dd>' +
      '<dt>Scan time</dt><dd>' + esc(finding.scan_ms ?? "-") + ' ms</dd>' +
      '<dt>Status</dt><dd class="status-' + esc(finding.status || "new") + '">' +
        esc((finding.status || "new").replace("_", " ")) +
        (finding.triage_note ? ' &middot; ' + esc(finding.triage_note) : '') + '</dd>' +
    '</dl>' +
    (finding.message ? '<h3>Detail</h3><div class="mono">' + esc(finding.message) + '</div>' : '') +
    (matches.length ? '<h3>Rule matches (' + matches.length + ')</h3>' + matches.map((m) =>
      '<div class="match"><div class="head">' +
        '<span class="sev sev-' + esc(m.severity || "info") + '">' + esc(m.severity || "info") + '</span>' +
        '<code>' + esc(m.rule) + '</code>' +
        '<span class="faint mono">' + esc(m.namespace) + '</span>' +
        (m.tags || []).map((t) => '<span class="faint mono">#' + esc(t) + '</span>').join("") +
      '</div>' +
      (m.description ? '<div class="dim" style="font-size:12.5px;margin-bottom:6px">' +
        esc(m.description) + '</div>' : '') +
      '<div class="strings">' + (m.strings || []).map((s) =>
        '<div>' + esc(s.identifier) + ' @ 0x' + Number(s.offset).toString(16) +
        '  <span class="faint">' + esc(s.preview) + '</span></div>').join("") + '</div>' +
      '</div>').join("") : '') +
    iocSection(finding) +
    '<h3>Correlated auth telemetry</h3>' +
    '<div class="dim" style="font-size:12.5px;margin-bottom:7px">' +
      esc(tele.source || "-") + ' &middot; status ' + esc(tele.status || "n/a") +
      ' &middot; window ' + esc(tele.window_minutes ?? "-") + ' min' +
      (tele.detail ? '<br><span class="faint">' + esc(tele.detail) + '</span>' : '') +
    '</div>' +
    (events.length ? events.map((e) =>
      '<div class="tele-row"><span>' + esc(clockOf(e.timestamp)) + '</span>' +
      '<span>' + esc(e.account) + '</span>' +
      '<span class="faint">' + esc(e.type) + (e.source_ip ? ' from ' + esc(e.source_ip) : '') +
      '</span></div>').join("")
      : '<span class="faint">No authentication failures in the window.</span>');

  $("drawer-content").innerHTML = html;
  $("drawer-title").textContent = baseName(finding.file_path) || finding.event_type;
  $("drawer-wrap").style.display = "block";
}

function closeDrawer() {
  state.selected = null;
  $("drawer-wrap").style.display = "none";
  document.querySelectorAll("#rows tr.selected").forEach((tr) => tr.classList.remove("selected"));
}

async function triage(status) {
  if (!state.selected) return;
  const note = status === "false_positive" ? (prompt("Note (optional):") || "") : "";
  try {
    const updated = await post("/api/triage", { id: state.selected, status, note });
    const idx = state.findings.findIndex((f) => f.id === updated.id);
    if (idx >= 0) state.findings[idx] = updated;
    renderRows(state.findings);
    toast("Marked " + status.replace("_", " "));
    closeDrawer();
  } catch (err) {
    toast("Triage failed: " + err.message, true);
  }
}

/* ------------------------------------------------------------------ panels */
function renderTelemetry(tele) {
  $("tele-status").textContent = (tele.status || "-") + " / " + (tele.count ?? 0);
  $("kpi-auth").textContent = tele.count ?? 0;
  $("kpi-auth-sub").textContent = "last " + (tele.window_minutes ?? "-") + " min (" +
    (tele.status === "ok" ? tele.source : tele.status) + ")";
  const events = tele.events || [];
  $("telemetry").innerHTML = events.length
    ? events.slice(-12).reverse().map((e) =>
        '<div class="row"><span class="name">' + esc(e.account) + '</span>' +
        '<span class="faint">' + esc(e.source_ip || e.type) + '</span>' +
        '<span class="meta">' + clockOf(e.timestamp) + '</span></div>').join("")
    : '<span class="faint">' + esc(tele.detail || "No failed logons in the window.") + '</span>';
}

function renderRules(engine) {
  $("rules-pill").textContent = engine.rule_count + " rules";
  if ($("meta-rules")) {
    $("meta-rules").textContent = engine.rule_count + " YARA rules / " +
      (engine.rule_files || []).length + " namespaces";
  }
  $("rules-tag").textContent = (engine.rule_files || []).length + " files / " +
    engine.compile_ms + " ms";
  const warn = [];
  if (engine.using_fallback) warn.push("No rule files found - using the built-in fallback rule.");
  (engine.load_errors || []).forEach((e) => warn.push(e.file + ": " + e.error));
  $("rules-list").innerHTML =
    (warn.length ? '<div class="banner err" style="margin:-14px -16px 12px">' +
      warn.map(esc).join("<br>") + '</div>' : '') +
    (engine.rules || []).map((r) =>
      '<div class="row"><span class="name">' + esc(r.rule) + '</span>' +
      '<span class="meta">' + esc(r.namespace) +
      (r.tags && r.tags.length ? " #" + r.tags.map(esc).join(" #") : "") + '</span></div>'
    ).join("") || '<span class="faint">No rules loaded.</span>';
}

function renderSensor(data) {
  const cfg = data.config, mon = data.monitor, stats = data.stats;
  $("sensor").innerHTML =
    '<dt>Watching</dt><dd class="mono">' + cfg.watch_paths.map(esc).join("<br>") + '</dd>' +
    '<dt>Poll</dt><dd>' + cfg.poll_interval + 's, max ' + cfg.max_file_mb + ' MB/file</dd>' +
    '<dt>Window</dt><dd>' + cfg.lookback_minutes + ' min correlation</dd>' +
    '<dt>Findings</dt><dd class="mono">' + esc(stats.log_path) + '</dd>' +
    '<dt>Last sweep</dt><dd class="mono">' + esc(mon.last_sweep || "-") + '</dd>' +
    (mon.last_error ? '<dt>Error</dt><dd class="mono" style="color:var(--critical)">' +
      esc(mon.last_error) + '</dd>' : '');
}

function feedLine(event) {
  const feed = $("feed");
  const stamp = '<span class="t">' + clockOf(event.timestamp) + '</span>';
  let body;
  if (event.event_type === "yara_match") {
    body = '<span class="hit">HIT [' + esc(event.severity) + '] ' +
      esc((event.rule_names || []).join(", ")) + ' -> ' + esc(baseName(event.file_path)) + '</span>';
  } else if (event.event_type === "scan") {
    body = '<span class="ok">clean</span> ' + esc(baseName(event.file_path));
  } else if (event.event_type === "error") {
    body = '<span class="hit">error</span> ' + esc(event.message || "");
  } else {
    body = esc(event.message || event.event_type);
  }
  const line = document.createElement("div");
  line.innerHTML = stamp + body;
  feed.prepend(line);
  while (feed.childElementCount > 120) feed.lastElementChild.remove();
}


/* --------------------------------------------------------------- IOC pivot */
const IOC_CLASS = {
  url: "net", domain: "host", onion: "net", ipv4: "net",
  btc: "coin", xmr: "coin", eth: "coin",
};

async function loadIocs() {
  const type = $("ioc-type") ? $("ioc-type").value : "all";
  const external = $("ioc-external") && $("ioc-external").checked;
  const params = new URLSearchParams({ limit: "300", type });
  if (external) params.set("scope", "external");
  try {
    const data = await api("/api/iocs?" + params.toString());
    renderIocs(data);
  } catch (err) {
    const body = $("ioc-rows");
    if (body) body.innerHTML = "";
  }
}

function renderIocs(data) {
  const rows = $("ioc-rows");
  const summary = $("ioc-summary");
  if (!rows) return;
  const items = data.indicators || [];

  if (summary) {
    const byType = data.by_type || {};
    const chips = Object.keys(byType).sort((a, b) => byType[b] - byType[a]).map((k) =>
      '<span class="ioc-chip ' + (IOC_CLASS[k] === "net" ? "hot" : "") + '">' +
      esc(k) + ' <b>' + byType[k] + '</b></span>').join("");
    summary.innerHTML = chips ||
      '<span class="faint">Nothing extracted yet \u2014 indicators appear when a file trips a rule.</span>';
  }

  if ($("meta-iocs")) {
    $("meta-iocs").textContent = items.length
      ? items.length + " indicators extracted"
      : "indicator extraction";
  }

  if (!items.length) {
    rows.innerHTML = '<tr><td colspan="4" class="ioc-empty">' +
      'No indicators yet. They are pulled from files that match a rule.</td></tr>';
    return;
  }

  rows.innerHTML = items.map((i) => {
    const cls = IOC_CLASS[i.type] || "";
    const scope = i.scope && i.scope !== "external"
      ? '<span class="ioc-scope">' + esc(i.scope) + '</span>' : "";
    const files = (i.files || []).slice(0, 3).map(esc).join(", ") +
      (i.file_count > 3 ? ' +' + (i.file_count - 3) + ' more' : "");
    return '<tr>' +
      '<td><span class="ioc-type ' + cls + '">' + esc(i.type) + '</span></td>' +
      '<td class="ioc-value">' + esc(i.defanged) + scope + '</td>' +
      '<td class="ioc-files">' + files + '</td>' +
      '<td class="mono">' + i.occurrences + '</td>' +
      '</tr>';
  }).join("");
}

function iocSection(finding) {
  const block = finding.iocs || {};
  const items = block.indicators || [];
  if (!items.length) return "";
  return '<h3>Extracted indicators (' + items.length + ')</h3>' +
    '<div class="dim" style="font-size:12px;margin-bottom:6px">' +
    'Pulled from this file. Defanged \u2014 safe to paste into a ticket.</div>' +
    items.map((i) =>
      '<div class="tele-row"><span>' + esc(i.type) + '</span>' +
      '<span class="mono" style="word-break:break-all">' + esc(i.defanged) + '</span>' +
      '<span class="faint">' + esc(i.scope || "") + '</span></div>').join("");
}

/* --------------------------------------------------------------- lifecycle */
async function refresh() {
  try {
    const data = await api("/api/state");
    renderStats(data.stats, data.monitor);
    renderTelemetry(data.telemetry);
    renderRules(data.engine);
    renderSensor(data);
    loadIocs();
    $("sub-title").textContent = data.config.watch_paths.length + " path(s) monitored";
  } catch (err) {
    toast("Backend unreachable: " + err.message, true);
  }
}

function connectStream() {
  const source = new EventSource("/api/stream");
  source.addEventListener("hello", () => {
    $("stream-dot").className = "dot live";
    $("stream-text").textContent = "live";
  });
  source.addEventListener("stats", (message) => {
    const payload = JSON.parse(message.data);
    renderStats(payload.stats, payload.monitor);
  });
  source.addEventListener("event", (message) => {
    const event = JSON.parse(message.data);
    feedLine(event);
    if (event.event_type === "yara_match") playTone(event.severity);
    if (event.event_type === "yara_match" || event.event_type === "error") {
      refreshTelemetrySoon();
    }
    if (!matchesFilters(event)) return;
    state.findings.unshift(event);
    const row = document.createElement("tbody");
    row.innerHTML = rowHtml(event);
    const tr = row.firstElementChild;
    tr.classList.add("fresh");
    $("rows").prepend(tr);
    $("empty").style.display = "none";
    $("findings-count").textContent = state.findings.length + " shown";
  });
  source.onerror = () => {
    $("stream-dot").className = "dot down";
    $("stream-text").textContent = "reconnecting";
  };
}

let teleTimer = null;
function refreshTelemetrySoon() {
  clearTimeout(teleTimer);
  teleTimer = setTimeout(async () => {
    try { renderTelemetry(await api("/api/telemetry")); } catch (_) { /* ignore */ }
  }, 600);
}

function wire() {
  ["q", "f-sev", "f-status", "f-type"].forEach((id) => {
    const el = $(id);
    el.addEventListener(id === "q" ? "input" : "change", debounce(loadFindings, 220));
  });

  $("rows").addEventListener("click", (event) => {
    const tr = event.target.closest("tr");
    if (tr && tr.dataset.id) openDrawer(tr.dataset.id);
  });

  $("btn-monitor").addEventListener("click", async () => {
    try {
      const status = await post("/api/monitor", { action: state.paused ? "resume" : "pause" });
      renderStats(state.lastStats || {}, status);
      toast("Monitor " + (status.paused ? "paused" : "resumed"));
    } catch (err) { toast(err.message, true); }
  });

  $("btn-reload").addEventListener("click", async () => {
    try {
      const info = await post("/api/rules/reload", {});
      renderRules(info);
      toast("Reloaded " + info.rule_count + " rules in " + info.compile_ms + " ms");
    } catch (err) { toast(err.message, true); }
  });

  ["ioc-type", "ioc-external"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", loadIocs);
  });
  if ($("ioc-export")) {
    $("ioc-export").addEventListener("click", () => {
      const type = $("ioc-type").value;
      const external = $("ioc-external").checked;
      const params = new URLSearchParams({ limit: "5000", type, format: "csv" });
      if (external) params.set("scope", "external");
      window.open("/api/iocs?" + params.toString(), "_blank");
    });
  }

  $("btn-scan").addEventListener("click", async () => {
    const path = $("scan-path").value.trim();
    if (!path) { toast("Enter a file or folder path", true); return; }
    $("btn-scan").disabled = true;
    $("scan-result").textContent = "Scanning...";
    try {
      const result = await post("/api/scan", { path });
      $("scan-result").innerHTML = "Scanned <b>" + result.files_scanned + "</b> file(s) in " +
        result.elapsed_ms + " ms &middot; <b style='color:var(--critical)'>" +
        result.matches + "</b> detection(s).";
      loadFindings();
    } catch (err) {
      $("scan-result").innerHTML = '<span style="color:var(--critical)">' + esc(err.message) + '</span>';
    } finally {
      $("btn-scan").disabled = false;
    }
  });

  $("sensitivity").addEventListener("input", (event) => {
    state.sensitivity = Number(event.target.value);
    $("sensitivity-value").textContent = state.sensitivity + "%";
    localStorage.setItem("suite-sensitivity", String(state.sensitivity));
  });
  $("focus-mode").addEventListener("change", (event) => {
    state.focusMode = event.target.checked;
    localStorage.setItem("suite-focus", String(state.focusMode));
    document.body.classList.toggle("focus-mode", state.focusMode);
    renderPosture(state.lastStats || {});
  });
  $("event-tone").addEventListener("change", (event) => {
    state.toneEnabled = event.target.checked;
    localStorage.setItem("suite-tone", String(state.toneEnabled));
    syncControls();
    if (state.toneEnabled) playTone("info");
  });
  $("audio-toggle").addEventListener("click", () => {
    state.toneEnabled = !state.toneEnabled;
    localStorage.setItem("suite-tone", String(state.toneEnabled));
    syncControls();
    if (state.toneEnabled) playTone("info");
  });
  $("refresh-intel").addEventListener("click", async () => {
    $("intel-sync").textContent = "Syncing source cards...";
    await loadIntel();
    toast("Source lattice synced");
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
}

function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

function mountDrawer() {
  const wrap = document.createElement("div");
  wrap.id = "drawer-wrap";
  wrap.style.display = "none";
  wrap.innerHTML =
    '<div class="drawer-backdrop" id="drawer-backdrop"></div>' +
    '<div class="drawer"><header><div class="brand"><div>' +
      '<h1 id="drawer-title">Finding</h1>' +
      '<span class="faint">Detection detail &amp; triage</span></div></div>' +
      '<div class="spacer"></div><button id="drawer-close" class="ghost">Close</button></header>' +
    '<div class="content" id="drawer-content"></div>' +
    '<div class="actions">' +
      '<button class="primary" data-triage="acknowledged">Acknowledge</button>' +
      '<button data-triage="resolved">Resolve</button>' +
      '<button data-triage="false_positive">False positive</button>' +
      '<button data-triage="new" class="ghost">Reopen</button>' +
    '</div></div>';
  document.body.appendChild(wrap);
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  wrap.querySelectorAll("[data-triage]").forEach((btn) =>
    btn.addEventListener("click", () => triage(btn.dataset.triage)));
}

mountDrawer();
wire();
syncControls();
refresh();
loadFindings();
loadIntel();
connectStream();
setInterval(refresh, 15000);
