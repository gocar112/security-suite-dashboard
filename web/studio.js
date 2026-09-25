const studioId = (id) => document.getElementById(id);

function setStudioText(id, value) {
  const element = studioId(id);
  if (element) element.textContent = String(value ?? "-");
}

async function studioJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error("Local sensor unavailable");
  return response.json();
}

function postureScore(stats) {
  const severity = stats.by_severity || {};
  return Math.max(0, 100 - (severity.critical || 0) * 24 - (severity.high || 0) * 13 - (severity.medium || 0) * 5 - (stats.errors || 0) * 4);
}

async function loadArena() {
  try {
    const [state, settings] = await Promise.all([studioJson("/api/state"), studioJson("/api/settings")]);
    const stats = state.stats || {};
    const severity = stats.by_severity || {};
    const urgent = (severity.critical || 0) + (severity.high || 0);
    const score = postureScore(stats);
    studioId("arena-dot").className = "live";
    setStudioText("arena-state", state.monitor?.paused ? "Local sensor paused" : "Local sensor online");
    setStudioText("arena-score", score);
    setStudioText("arena-label", score >= 85 ? "stable" : score >= 60 ? "review" : "action required");
    setStudioText("arena-rules", state.engine?.rule_count || 0);
    setStudioText("arena-alerts", stats.open_alerts || 0);
    setStudioText("arena-paths", (state.config?.watch_paths || []).length);
    setStudioText("arena-keys", [settings.nvd_configured && "NVD", settings.virustotal_configured && "VirusTotal"].filter(Boolean).join(" + ") || "Optional keys not set");
    setStudioText("arena-updated", new Date(state.server_time).toLocaleTimeString());
    if (urgent > 0) {
      const strip = studioId("remediation-strip");
      strip.classList.add("alert");
      strip.querySelector("b").textContent = `${urgent} high-priority finding${urgent === 1 ? "" : "s"}`;
      strip.querySelector("small").textContent = "Review and quarantine before considering deletion.";
      setStudioText("remediation-message", `${urgent} critical or high finding${urgent === 1 ? "" : "s"} need operator review. Quarantine is the recommended first action.`);
      if (!sessionStorage.getItem("studio-remediation-dismissed")) studioId("remediation-dialog").showModal();
    }
  } catch (error) {
    setStudioText("arena-state", error.message);
    studioId("arena-dot").className = "";
  }
}

studioId("clear-arena").addEventListener("click", () => {
  for (const key of Object.keys(localStorage)) if (key.startsWith("suite-") || key.startsWith("studio-")) localStorage.removeItem(key);
  sessionStorage.removeItem("studio-remediation-dismissed");
  setStudioText("arena-state", "Local display preferences reset");
});
studioId("remediation-dialog").addEventListener("close", () => sessionStorage.setItem("studio-remediation-dismissed", "1"));
loadArena();
setInterval(loadArena, 15000);
