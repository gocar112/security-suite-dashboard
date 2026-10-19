/* Shared primitives: DOM access, escaping, formatting, fetch helpers, state.
 *
 * Everything here is imported by every view, so it must stay dependency-free
 * and side-effect-free beyond the single shared `state` object.
 */

export const $ = (id) => document.getElementById(id);
export const SEVS = ["critical", "high", "medium", "low", "info"];
export const SEV_COLOR = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
  low: "var(--low)", info: "var(--info)",
};

export const state = {
  findings: [], selected: null, paused: false, lastStats: null, feedSeeded: false,
  sensitivity: Number(localStorage.getItem("suite-sensitivity") || 72),
  focusMode: localStorage.getItem("suite-focus") === "true",
  toneEnabled: localStorage.getItem("suite-tone") === "true",
  audioContext: null,
};

/* ------------------------------------------------------------------ utils */
export function esc(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function clockOf(iso) {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  return isNaN(d) ? String(iso).slice(11, 19) : d.toLocaleTimeString([], { hour12: false });
}

export function bytes(n) {
  if (n === undefined || n === null) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
}

export function duration(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

export function shortPath(value) {
  // Collapse the middle of a long path. Folder names containing spaces
  // otherwise wrap at every space and shred the column.
  const full = String(value || "");
  if (full.length <= 48) return full;
  const sep = full.indexOf("\\") >= 0 ? "\\" : "/";
  const parts = full.split(/[\\/]/).filter(Boolean);
  if (parts.length <= 3) return full;
  return parts[0] + sep + "\u2026" + sep + parts.slice(-2).join(sep);
}

export function baseName(p) {
  return String(p || "").split(/[\\/]/).pop() || String(p || "");
}

export function targetStateLabel(finding) {
  if (!finding || finding.event_type !== "yara_match") return "";
  const target = finding.target_state || (finding.target_exists === false ? "gone" : "");
  if (!target || target === "present") return "";
  if (target === "delete") return "deleted";
  if (target === "quarantine") return "quarantined";
  return target === "gone" ? "file gone" : target;
}

export function targetStateBadge(finding) {
  const label = targetStateLabel(finding);
  if (!label) return "";
  const target = String(finding.target_state || "gone").replace(/[^a-z_]/g, "");
  return '<span class="target-badge target-' + esc(target) + '">' + esc(label) + '</span>';
}

export function toast(message, isError) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " err" : "");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

export async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || data.refused || res.status + " " + res.statusText);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const post = (path, payload) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });

