/* Cases view: the container triage does not have.
 *
 * Triage marks one finding acknowledged. An intrusion is not one finding, and
 * "resolved" on six rows says nothing about whether anyone understood how they
 * were related. A case holds them together with an owner, a status, notes, and
 * a report that can leave the machine.
 */
import { $, esc, api, post, toast, clockOf, baseName } from "./core.js";

const STATUSES = ["open", "investigating", "contained", "closed"];
let cases = [];
let selected = null;

function renderList() {
  const wrap = $("case-list");
  if (!wrap) return;
  if (!cases.length) {
    wrap.innerHTML = '<div class="faint">No cases yet. Select findings and open ' +
      'one, or promote a campaign from the Graph view.</div>';
    return;
  }
  wrap.innerHTML = cases.map((c) =>
    '<button class="case-row' + (selected === c.id ? " active" : "") +
      '" data-id="' + esc(c.id) + '">' +
      '<span class="sev sev-' + esc(c.severity) + '">' + esc(c.severity) + '</span>' +
      '<span class="case-title">' + esc(c.title) + '</span>' +
      '<span class="case-meta faint mono">' + esc(c.status) +
        ' · ' + esc((c.finding_ids || []).length) + ' findings' +
        (c.owner ? ' · ' + esc(c.owner) : '') + '</span>' +
    '</button>').join("");
  wrap.querySelectorAll(".case-row").forEach((btn) =>
    btn.addEventListener("click", () => openCase(btn.dataset.id)));
}

function renderDetail(payload) {
  const box = $("case-detail");
  if (!box) return;
  if (!payload) {
    box.innerHTML = '<div class="faint">Select a case to see its evidence.</div>';
    return;
  }
  const c = payload.case;
  const findings = payload.findings || [];
  const techniques = [...new Set(findings.flatMap((f) =>
    (f.matches || []).flatMap((m) => (m.attack || []).map((t) => t.id))))];

  box.innerHTML =
    '<div class="case-head">' +
      '<h3>' + esc(c.title) + '</h3>' +
      '<div class="case-controls">' +
        '<select id="case-status">' + STATUSES.map((s) =>
          '<option value="' + s + '"' + (c.status === s ? " selected" : "") + '>' +
          s + '</option>').join("") + '</select>' +
        '<a class="action-btn" href="/api/report?case=' + encodeURIComponent(c.id) +
          '" target="_blank" rel="noreferrer">Open report</a>' +
        '<a class="action-btn" href="/api/report?case=' + encodeURIComponent(c.id) +
          '&download=1">Download</a>' +
        '<button class="danger-btn" id="case-delete">Delete case</button>' +
      '</div>' +
    '</div>' +
    '<dl class="kv">' +
      '<dt>Owner</dt><dd>' + esc(c.owner || "unassigned") + '</dd>' +
      '<dt>Opened</dt><dd class="mono">' + esc(c.created_at) + '</dd>' +
      '<dt>Updated</dt><dd class="mono">' + esc(c.updated_at) + '</dd>' +
      '<dt>Findings</dt><dd>' + findings.length + '</dd>' +
      '<dt>ATT&amp;CK</dt><dd>' + (techniques.length
        ? techniques.map((t) => '<span class="attack-chip">' + esc(t) + '</span>').join("")
        : '<span class="faint">none mapped</span>') + '</dd>' +
    '</dl>' +
    (c.summary ? '<h4>Summary</h4><p class="case-summary">' + esc(c.summary) + '</p>' : '') +
    '<h4>Linked findings</h4>' +
    (findings.length
      ? '<div class="case-findings">' + findings.map((f) =>
          '<div class="case-finding">' +
            '<span class="sev sev-' + esc(f.severity || "info") + '">' +
              esc(f.severity || "info") + '</span>' +
            '<b>' + esc(baseName(f.file_path)) + '</b>' +
            '<span class="faint mono">' + esc(clockOf(f.timestamp)) + '</span>' +
            '<i data-unlink="' + esc(f.id) + '" title="Remove from case">×</i>' +
          '</div>').join("") + '</div>'
      : '<div class="faint">No findings linked yet.</div>') +
    '<h4>Notes</h4>' +
    '<div class="case-notes">' + ((c.notes || []).length
      ? c.notes.map((n) => '<div class="case-note"><b>' + esc(n.at) +
          (n.author ? ' · ' + esc(n.author) : '') + '</b><span>' +
          esc(n.text) + '</span></div>').join("")
      : '<span class="faint">No notes yet.</span>') + '</div>' +
    '<div class="case-note-add">' +
      '<input type="text" id="case-note-text" placeholder="Add a note - what you found, what you did, why it is closed">' +
      '<button class="action-btn" id="case-note-add">Add</button>' +
    '</div>';

  $("case-status").addEventListener("change", async (e) => {
    await post("/api/cases/update", { id: c.id, status: e.target.value });
    await refreshCases();
    openCase(c.id);
  });
  $("case-note-add").addEventListener("click", async () => {
    const text = $("case-note-text").value.trim();
    if (!text) return;
    await post("/api/cases/note", { id: c.id, text });
    openCase(c.id);
  });
  $("case-delete").addEventListener("click", async () => {
    if (!confirm("Delete this case? The findings and the audit trail are not touched."))
      return;
    await post("/api/cases/delete", { id: c.id, confirm: true });
    selected = null;
    await refreshCases();
    renderDetail(null);
  });
  box.querySelectorAll("i[data-unlink]").forEach((x) =>
    x.addEventListener("click", async () => {
      await post("/api/cases/link",
        { id: c.id, finding_ids: [x.dataset.unlink], detach: true });
      openCase(c.id);
    }));
}

export async function openCase(id) {
  selected = id;
  renderList();
  try {
    renderDetail(await api("/api/cases/detail?id=" + encodeURIComponent(id)));
  } catch (err) {
    toast("Could not open case: " + err.message, true);
  }
}

export async function refreshCases() {
  try {
    const data = await api("/api/cases");
    cases = data.cases || [];
    const note = $("case-note-count");
    if (note) {
      const s = data.summary || {};
      note.textContent = s.total + " cases · " + s.open + " open";
    }
    renderList();
  } catch (_) { /* cases are optional */ }
}

export async function createCase(findingIds = [], preset = {}) {
  const title = prompt("Case title:", preset.title || "New investigation");
  if (!title) return null;
  const data = await post("/api/cases", {
    title,
    owner: preset.owner || "",
    severity: preset.severity || "high",
    summary: preset.summary || "",
    finding_ids: findingIds,
  });
  toast("Case created: " + title);
  await refreshCases();
  if (data.case) openCase(data.case.id);
  return data.case;
}

export function mountCases() {
  const add = $("case-new");
  if (add) add.addEventListener("click", () => createCase([]));
  refreshCases();
}
