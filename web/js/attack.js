/* ATT&CK view: coverage matrix, drawer chips, technique pivots. */
import { $, esc, api } from "./core.js";

export function attackChips(match) {
  const techniques = match.attack || [];
  if (!techniques.length) return "";
  return '<span class="attack-chips">' + techniques.map((t) =>
    '<a class="attack-chip' + (t.known ? "" : " unknown") + '" href="' + esc(t.url) +
    '" target="_blank" rel="noreferrer" title="' + esc(t.name) + '">' +
    esc(t.id) + '</a>').join("") + '</span>';
}

export function attackSection(finding) {
  const seen = new Map();
  (finding.matches || []).forEach((m) => (m.attack || []).forEach((t) => {
    if (!seen.has(t.id)) seen.set(t.id, t);
  }));
  if (!seen.size) return "";
  const techniques = [...seen.values()];
  const tactics = [...new Set(techniques.flatMap((t) => t.tactics || []))];
  return '<h3>ATT&amp;CK</h3>' +
    '<div class="attack-summary">' +
      tactics.map((id) => '<span class="tactic-pill">' +
        esc(TACTIC_LABELS[id] || id) + '</span>').join("") +
    '</div>' +
    '<div class="attack-tech-list">' + techniques.map((t) =>
      '<a class="attack-tech" href="' + esc(t.url) + '" target="_blank" rel="noreferrer">' +
        '<code>' + esc(t.id) + '</code><span>' + esc(t.name) + '</span></a>').join("") +
    '</div>';
}

export const TACTIC_LABELS = {};

export async function loadAttack() {
  try {
    const data = await api("/api/attack/coverage");
    renderAttack(data);
  } catch (_) {
    const grid = $("attack-matrix");
    if (grid) grid.innerHTML = '<span class="faint">Coverage unavailable.</span>';
  }
}

export function renderAttack(data) {
  const grid = $("attack-matrix");
  if (!grid) return;
  (data.tactics || []).forEach((col) => { TACTIC_LABELS[col.id] = col.name; });
  const maxHits = Math.max(1, ...(data.tactics || []).flatMap((c) =>
    c.techniques.map((t) => t.detections)));
  grid.innerHTML = (data.tactics || []).map((col) => {
    const cells = col.techniques.map((cell) => {
      const t = cell.technique;
      // Shade by detection volume; a covered-but-silent technique stays flat.
      const heat = cell.detections ? Math.min(1, 0.25 + cell.detections / maxHits) : 0;
      const title = t.id + " " + t.name + " — " + cell.rules.length + " rule(s), " + cell.detections + " detection(s)";
      return '<button class="attack-cell' + (cell.detections ? " hot" : "") +
        '" style="--heat:' + heat.toFixed(3) + '" data-technique="' + esc(t.id) +
        '" title="' + esc(title) + '">' +
        '<code>' + esc(t.id) + '</code>' +
        '<span>' + esc(t.name.split(": ").pop()) + '</span>' +
        (cell.detections ? '<i>' + cell.detections + '</i>' : '') +
        '</button>';
    }).join("");
    return '<div class="attack-col' + (col.techniques.length ? "" : " empty") + '">' +
      '<div class="attack-col-head"><b>' + esc(col.name) + '</b>' +
      '<span class="faint mono">' + col.covered + '</span></div>' +
      (cells || '<div class="attack-none">no coverage</div>') + '</div>';
  }).join("");

  const note = $("attack-note");
  if (note) {
    note.textContent = data.covered_techniques + " techniques covered · " +
      data.detected_techniques + " seen · " + data.total_detections + " detections";
  }
  grid.querySelectorAll(".attack-cell").forEach((btn) => {
    btn.addEventListener("click", () => {
      // Pivot: filter the findings table to this technique.
      document.dispatchEvent(new CustomEvent("suite:filter", {
        detail: { query: btn.dataset.technique, view: "findings" },
      }));
    });
  });
}

