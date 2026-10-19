/* Hash router.
 *
 * Every top-level block carries data-views listing the views it belongs to
 * ("*" means always visible, e.g. the topbar). Switching a view shows and
 * hides blocks rather than re-rendering them, so the SSE stream keeps feeding
 * the findings table even while the operator is looking at the ATT&CK matrix -
 * a console that stops receiving events when you change tabs is worse than one
 * with no tabs.
 */
import { $ } from "./core.js";

/* `keywords` exist because a label is not always what someone types. Nobody
 * searching for the ATT&CK matrix types "att&ck" - they type "attack", "mitre"
 * or "matrix", none of which match the label by substring or subsequence. */
export const VIEWS = [
  { id: "overview", label: "Overview", glyph: "◈", keywords: "home dashboard summary posture" },
  { id: "findings", label: "Findings", glyph: "⚑", keywords: "detections alerts events stream triage" },
  { id: "hunt", label: "Hunt", glyph: "⌕", keywords: "search query filter kql saved" },
  { id: "indicators", label: "Indicators", glyph: "⬡", keywords: "ioc observables pivot csv domains hashes" },
  { id: "attack", label: "ATT&CK", glyph: "⊞", keywords: "attack mitre tactics techniques matrix coverage" },
  { id: "graph", label: "Graph", glyph: "⚹", keywords: "link analysis campaigns clusters relationships" },
  { id: "cases", label: "Cases", glyph: "⌸", keywords: "incidents tickets investigations report" },
  { id: "containment", label: "Containment", glyph: "⊗", keywords: "remediate quarantine delete purge restore" },
  { id: "intel", label: "Intel", glyph: "◎", keywords: "sources nvd osv virustotal kev feeds cve" },
];

const listeners = [];
let current = "overview";

export function onView(fn) {
  listeners.push(fn);
}

export function activeView() {
  return current;
}

export function showView(id, { push = true } = {}) {
  if (!VIEWS.some((v) => v.id === id)) id = "overview";
  current = id;

  document.querySelectorAll("[data-views]").forEach((block) => {
    const owns = block.dataset.views.split(/\s+/);
    block.hidden = !(owns.includes("*") || owns.includes(id));
  });
  document.querySelectorAll(".rail-item").forEach((btn) => {
    const on = btn.dataset.view === id;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-current", on ? "page" : "false");
  });

  if (push && location.hash.slice(1) !== id) location.hash = id;
  document.title = "Security Suite / " +
    (VIEWS.find((v) => v.id === id) || {}).label;
  listeners.forEach((fn) => {
    try { fn(id); } catch (_) { /* one bad listener must not break navigation */ }
  });
}

export function mountRouter() {
  const rail = $("view-rail");
  if (rail) {
    rail.innerHTML = VIEWS.map((v) =>
      '<button class="rail-item" type="button" data-view="' + v.id + '">' +
        '<span class="rail-glyph" aria-hidden="true">' + v.glyph + '</span>' +
        '<span class="rail-label">' + v.label + '</span>' +
      '</button>').join("");
    rail.querySelectorAll(".rail-item").forEach((btn) =>
      btn.addEventListener("click", () => showView(btn.dataset.view)));
  }
  window.addEventListener("hashchange", () =>
    showView(location.hash.slice(1) || "overview", { push: false }));
  showView(location.hash.slice(1) || "overview", { push: false });
}
