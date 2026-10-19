/* Hunt view: a query language over findings, with saved hunts.
 *
 * The findings search box does a substring match over the whole event. That
 * cannot express "critical, not resolved, on a PowerShell technique, excluding
 * the samples folder" - and matching `critical` as a substring also hits a
 * file named critical_report.txt. Parsing happens server-side in
 * securitysuite/hunt.py so the grammar has one implementation.
 */
import { $, esc, api, post, toast, clockOf, shortPath, baseName } from "./core.js";

const EXAMPLES = [
  ["severity:critical AND NOT status:resolved", "open criticals"],
  ["technique:T1486 OR technique:T1490", "ransomware tradecraft"],
  ["tactic:credential-access", "anything touching credentials"],
  ["rule:PowerShell* -file:*samples*", "PowerShell rules, excluding samples"],
  ["tag:webshell OR namespace:webshell", "web shells by tag or namespace"],
  ["severity:critical AND (rule:LockBit* OR rule:Conti*)", "named ransomware families"],
];

let lastResults = [];

export function huntResults() {
  return lastResults;
}

function renderRows(findings) {
  const body = $("hunt-rows");
  if (!body) return;
  if (!findings.length) {
    body.innerHTML =
      '<tr><td colspan="5" class="ioc-empty">No findings match this query.</td></tr>';
    return;
  }
  body.innerHTML = findings.map((f) => {
    const rules = (f.matches || []).map((m) => m.rule);
    const techniques = [...new Set((f.matches || [])
      .flatMap((m) => (m.attack || []).map((t) => t.id)))];
    return '<tr data-id="' + esc(f.id) + '">' +
      '<td><span class="sev sev-' + esc(f.severity || "info") + '">' +
        esc(f.severity || "info") + '</span></td>' +
      '<td class="mono">' + esc(clockOf(f.timestamp)) + '</td>' +
      '<td><b>' + esc(baseName(f.file_path)) + '</b>' +
        '<div class="faint mono">' + esc(shortPath(f.file_path)) + '</div></td>' +
      '<td>' + rules.slice(0, 3).map((r) =>
        '<code class="rule-chip">' + esc(r) + '</code>').join("") +
        (rules.length > 3 ? '<span class="faint"> +' + (rules.length - 3) + '</span>' : '') +
      '</td>' +
      '<td>' + techniques.map((t) =>
        '<span class="attack-chip">' + esc(t) + '</span>').join(" ") + '</td>' +
      '</tr>';
  }).join("");
}

export async function runHunt(query) {
  const box = $("hunt-q");
  if (box && query !== undefined) box.value = query;
  const text = (box ? box.value : query || "").trim();
  const status = $("hunt-status");

  if (!text) {
    lastResults = [];
    renderRows([]);
    if (status) { status.textContent = "Enter a query."; status.className = "hunt-status"; }
    return;
  }
  try {
    const data = await api("/api/hunt?q=" + encodeURIComponent(text) + "&limit=300");
    if (data.error) {
      // A typo that quietly returns nothing is worse than one that says so.
      lastResults = [];
      renderRows([]);
      if (status) {
        status.textContent = data.error;
        status.className = "hunt-status bad";
      }
      return;
    }
    lastResults = data.findings || [];
    renderRows(lastResults);
    if (status) {
      status.textContent = data.matched + " of " + data.scanned + " findings matched";
      status.className = "hunt-status ok";
    }
  } catch (err) {
    if (status) { status.textContent = err.message; status.className = "hunt-status bad"; }
  }
}

async function renderSaved() {
  const wrap = $("hunt-saved");
  if (!wrap) return;
  let hunts = [];
  try { hunts = (await api("/api/hunt/saved")).hunts || []; } catch (_) { /* offline */ }
  wrap.innerHTML = hunts.length
    ? hunts.map((h) =>
        '<span class="saved-hunt"><button type="button" data-query="' + esc(h.query) +
        '">' + esc(h.name) + '</button>' +
        '<i data-drop="' + esc(h.name) + '" title="Forget this hunt">×</i></span>').join("")
    : '<span class="faint">No saved hunts yet.</span>';

  wrap.querySelectorAll("button[data-query]").forEach((btn) =>
    btn.addEventListener("click", () => runHunt(btn.dataset.query)));
  wrap.querySelectorAll("i[data-drop]").forEach((x) =>
    x.addEventListener("click", async () => {
      await post("/api/hunt/saved", { name: x.dataset.drop, query: "" });
      renderSaved();
    }));
}

export function mountHunt() {
  const examples = $("hunt-examples");
  if (examples) {
    examples.innerHTML = EXAMPLES.map(([q, why]) =>
      '<button type="button" class="hunt-example" data-query="' + esc(q) + '">' +
        '<code>' + esc(q) + '</code><span>' + esc(why) + '</span></button>').join("");
    examples.querySelectorAll(".hunt-example").forEach((btn) =>
      btn.addEventListener("click", () => runHunt(btn.dataset.query)));
  }

  const box = $("hunt-q");
  if (box) {
    box.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); runHunt(); }
    });
  }
  const run = $("hunt-run");
  if (run) run.addEventListener("click", () => runHunt());

  const save = $("hunt-save");
  if (save) {
    save.addEventListener("click", async () => {
      const query = ($("hunt-q").value || "").trim();
      if (!query) return toast("Nothing to save", true);
      const name = prompt("Name this hunt:", query.slice(0, 40));
      if (!name) return;
      await post("/api/hunt/saved", { name, query });
      toast("Saved hunt: " + name);
      renderSaved();
    });
  }
  renderSaved();
}
