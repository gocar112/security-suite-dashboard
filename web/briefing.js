const byId = (id) => document.getElementById(id);
let briefingPaused = false;

function text(id, value) {
  const target = byId(id);
  if (target) target.textContent = String(value ?? "-");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"]/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
  }[char]));
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error("Status unavailable");
  return response.json();
}

function renderFindings(findings) {
  const rows = byId("finding-rows");
  const empty = byId("findings-empty");
  const detections = (findings || []).filter((item) => item.event_type === "yara_match").slice(0, 8);
  rows.innerHTML = detections.map((item) => {
    const severity = String(item.severity || "info").toLowerCase();
    const rules = (item.matches || []).map((match) => match.rule).filter(Boolean).join(", ") || "Rule match";
    return `<tr><td><span class="severity severity-${escapeHtml(severity)}">${escapeHtml(severity)}</span></td><td>${escapeHtml(formatTime(item.timestamp))}</td><td>${escapeHtml(rules)}</td><td>${escapeHtml(item.status || "new")}</td></tr>`;
  }).join("");
  empty.hidden = detections.length > 0;
  text("detection-status", detections.length ? `${detections.length} recent` : "Clear");
}

function renderSources(sources) {
  const list = byId("source-list");
  list.innerHTML = (sources || []).map((source) => {
    const state = String(source.status || "unknown").toLowerCase().replace(/\s+/g, "-");
    return `<div class="source ${escapeHtml(state)}"><strong>${escapeHtml(source.id)}</strong><span>${escapeHtml(source.status || "unknown")}</span></div>`;
  }).join("");
}

async function refresh() {
  if (briefingPaused) return;
  try {
    const [state, findings, intel, logs] = await Promise.all([
      getJson("/api/state"), getJson("/api/findings?limit=60"), getJson("/api/intel"), getJson("/api/logs"),
    ]);
    const stats = state.stats || {};
    const monitor = state.monitor || {};
    const behavior = logs.behavior || {};
    const engine = state.engine || {};
    text("updated", `Updated ${formatTime(state.server_time)}`);
    text("sensor-state", monitor.paused ? "Paused" : monitor.running ? "Watching" : "Unavailable");
    text("sensor-detail", monitor.last_error || `${monitor.tracked_files || 0} tracked files`);
    text("files-scanned", stats.files_scanned || 0);
    text("files-detail", `${stats.matches || 0} rule matches`);
    text("open-alerts", stats.open_alerts || 0);
    text("alerts-detail", `${stats.errors || 0} scan errors`);
    text("sources-count", (intel.sources || []).length);
    text("sources-detail", intel.status === "live" ? "Live context available" : "Local context catalog");
    text("watch-monitor", monitor.paused ? "Paused by operator" : monitor.running ? "Watching for changes" : "Monitor unavailable");
    text("watch-path", (state.config?.watch_paths || []).join(", ") || "No path configured");
    text("watch-rules", `${engine.rule_count || 0} loaded rules`);
    text("firewall-state", logs.firewall?.status === "ok" ? `${logs.firewall.source}: ${logs.firewall.blocked || 0} blocks` : "Log unavailable");
    text("destructive-actions", behavior.destructive_actions || 0);
    text("firewall-blocks", behavior.firewall_blocks || 0);
    const severity = stats.by_severity || {};
    const urgent = (severity.critical || 0) + (severity.high || 0);
    byId("briefing-review").hidden = urgent === 0;
    if (urgent) {
      text("briefing-review-title", `${urgent} high-priority finding${urgent === 1 ? "" : "s"}`);
      text("briefing-review-copy", "Open the console to inspect evidence and quarantine before considering deletion.");
    }
    renderFindings(findings.findings);
    renderSources(intel.sources);
  } catch (error) {
    text("updated", "Local status is unavailable");
    text("sensor-state", "Unavailable");
    text("detection-status", "Unavailable");
  }
}

function clearBriefing() {
  briefingPaused = true;
  ["sensor-state", "files-scanned", "open-alerts", "sources-count", "watch-monitor", "watch-path", "watch-rules", "firewall-state", "destructive-actions", "firewall-blocks"].forEach((id) => text(id, "-"));
  byId("finding-rows").innerHTML = "";
  byId("source-list").innerHTML = "";
  byId("findings-empty").hidden = false;
  byId("briefing-review").hidden = true;
  text("detection-status", "Display cleared");
  text("updated", "Display cleared; stored records were not changed");
}

byId("clear-briefing").addEventListener("click", clearBriefing);
byId("reload-briefing").addEventListener("click", () => {
  briefingPaused = false;
  refresh();
});

refresh();
setInterval(refresh, 15000);
