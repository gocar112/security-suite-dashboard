/* Four workspace views: ATT&CK coverage, hunt, link graph and casework.
 *
 * These render into the #main-{id} / #side-{id} containers console.js builds
 * from its views array, and reuse app.js's esc/api/post/toast rather than
 * carrying their own. Nothing here owns navigation: console.js already routes
 * on the hash and handles keyboard movement between views.
 */
"use strict";

window.SuiteViews = (() => {
  const el = (id) => document.getElementById(id);

  const panel = (title, html, tag) =>
    '<section class="panel"><div class="panel-head"><h2>' + title + "</h2>" +
    (tag ? '<span class="tag">' + esc(tag) + "</span>" : "") +
    '</div><div class="tool-body">' + html + "</div></section>";

  const sev = (name) =>
    '<span class="sev sev-' + esc(name || "info") + '">' + esc(name || "info") + "</span>";

  const empty = (text) => '<p class="muted">' + esc(text) + "</p>";

  /* ------------------------------------------------------------- ATT&CK */

  function attackMarkup() {
    return (
      panel(
        "Coverage",
        '<div id="attack-summary" class="attack-summary"></div>' +
          '<div id="attack-gaps" class="attack-gaps"></div>',
      ) +
      panel(
        "Tactic matrix",
        '<p class="muted">Columns run left to right the way an intrusion unfolds. ' +
          "A technique with rules but no detections is coverage; a tactic with no rules is a gap.</p>" +
          '<div id="attack-matrix" class="attack-matrix"></div>',
      )
    );
  }

  function renderAttack(data) {
    const summary = el("attack-summary");
    if (!summary) return;

    summary.innerHTML = [
      ["Techniques referenced", data.technique_count],
      ["Covered by a rule", data.covered_techniques],
      ["Seen in a detection", data.detected_techniques],
      ["Total detections", data.total_detections],
    ]
      .map(
        ([label, value]) =>
          '<div class="attack-stat"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>",
      )
      .join("");

    const gaps = el("attack-gaps");
    gaps.innerHTML = (data.uncovered_tactics || []).length
      ? '<p class="warn">No rule covers: ' +
        (data.uncovered_tactics || []).map(esc).join(", ") +
        "</p>"
      : '<p class="muted">Every tactic has at least one rule.</p>';

    /* One column per tactic. Techniques inside a column are ordered by
     * detections already, so the ones that have actually fired come first. */
    el("attack-matrix").innerHTML = (data.tactics || [])
      .map((column) => {
        const cells = (column.techniques || []).length
          ? column.techniques
              .map((cell) => {
                const technique = cell.technique || {};
                const fired = cell.detections > 0;
                return (
                  '<a class="attack-cell' +
                  (fired ? " is-fired" : "") +
                  (technique.known ? "" : " is-unmapped") +
                  '" href="' +
                  esc(technique.url) +
                  '" target="_blank" rel="noreferrer noopener" title="' +
                  esc(technique.name + " - " + (cell.rules || []).length + " rule(s)") +
                  '"><code>' +
                  esc(technique.id) +
                  "</code><span>" +
                  esc(technique.name) +
                  "</span>" +
                  (fired ? '<b class="attack-hits">' + esc(cell.detections) + "</b>" : "") +
                  "</a>"
                );
              })
              .join("")
          : '<p class="attack-none">no rules</p>';

        return (
          '<div class="attack-col' +
          (column.covered ? "" : " is-gap") +
          '"><h3>' +
          esc(column.name) +
          '</h3><div class="attack-col-meta">' +
          esc(column.covered) +
          " covered &middot; " +
          esc(column.detected) +
          " seen</div>" +
          cells +
          "</div>"
        );
      })
      .join("");
  }

  /* --------------------------------------------------------------- Hunt */

  const HUNT_EXAMPLES = [
    "severity:critical AND NOT status:resolved",
    "tactic:impact OR technique:T1486",
    'namespace:webshell file:*.php',
    "rule:PowerShell_* -status:false_positive",
  ];

  function huntMarkup() {
    return (
      panel(
        "Query",
        '<form id="hunt-form" class="hunt-form">' +
          '<input id="hunt-input" type="text" spellcheck="false" autocomplete="off" ' +
          'placeholder="severity:critical AND NOT status:resolved" aria-label="Hunt query">' +
          '<button type="submit">Run</button>' +
          "</form>" +
          '<div id="hunt-status" class="hunt-status"></div>' +
          '<div class="hunt-examples">' +
          HUNT_EXAMPLES.map(
            (q) => '<button type="button" class="hunt-example" data-query="' + esc(q) + '">' + esc(q) + "</button>",
          ).join("") +
          "</div>",
      ) +
      panel("Results", '<div id="hunt-results"></div>')
    );
  }

  function huntSideMarkup() {
    return (
      panel(
        "Save this hunt",
        '<form id="hunt-save-form" class="hunt-save">' +
          '<input id="hunt-save-name" type="text" placeholder="Name" aria-label="Hunt name" maxlength="80">' +
          '<button type="submit">Save</button>' +
          "</form>" +
          '<div id="hunt-saved"></div>',
      ) + panel("Fields", '<div id="hunt-fields" class="hunt-fields"></div>')
    );
  }

  function renderHunt(data) {
    const status = el("hunt-status");
    if (!status) return;

    if (data.error) {
      status.innerHTML = '<p class="warn">' + esc(data.error) + "</p>";
      el("hunt-results").innerHTML = "";
      return;
    }

    status.innerHTML =
      '<p class="muted">' +
      esc(data.matched) +
      " of " +
      esc(data.scanned) +
      " events matched" +
      (data.matched >= 300 ? " (showing the first 300)" : "") +
      "</p>";

    el("hunt-fields").innerHTML = (data.fields || [])
      .map((f) => '<code class="hunt-field">' + esc(f) + "</code>")
      .join("");

    const rows = data.findings || [];
    el("hunt-results").innerHTML = rows.length
      ? '<table class="data-table"><thead><tr><th>Severity</th><th>File</th><th>Rules</th>' +
        "<th>Status</th><th>When</th></tr></thead><tbody>" +
        rows
          .map(
            (f) =>
              "<tr><td>" +
              sev(f.severity) +
              '</td><td class="cell-path" title="' +
              esc(f.file_path || "") +
              '">' +
              esc(f.file_name || f.file_path || "-") +
              "</td><td>" +
              esc((f.rule_names || []).join(", ")) +
              "</td><td>" +
              esc(f.status || "new") +
              "</td><td>" +
              esc(f.timestamp || "") +
              "</td></tr>",
          )
          .join("") +
        "</tbody></table>"
      : empty("Nothing matched that query.");
  }

  function renderSavedHunts(hunts, onRun, onDelete) {
    const host = el("hunt-saved");
    if (!host) return;

    host.innerHTML = (hunts || []).length
      ? '<ul class="hunt-saved-list">' +
        hunts
          .map(
            (h) =>
              '<li><button type="button" class="hunt-run" data-query="' +
              esc(h.query) +
              '" title="' +
              esc(h.query) +
              '">' +
              esc(h.name) +
              '</button><button type="button" class="hunt-drop" data-id="' +
              esc(h.id) +
              '" aria-label="Delete ' +
              esc(h.name) +
              '">&times;</button></li>',
          )
          .join("") +
        "</ul>"
      : empty("No saved hunts yet.");

    host.querySelectorAll(".hunt-run").forEach((b) =>
      b.addEventListener("click", () => onRun(b.dataset.query)),
    );
    host.querySelectorAll(".hunt-drop").forEach((b) =>
      b.addEventListener("click", () => onDelete(b.dataset.id)),
    );
  }

  /* -------------------------------------------------------------- Graph */

  const graphState = { nodes: [], edges: [], alpha: 0, raf: 0, hover: null };

  function graphMarkup() {
    return (
      panel(
        "Link analysis",
        '<p class="muted">Findings, the indicators inside them, and the rules that fired. ' +
          "Click a node to inspect it.</p>" +
          '<div class="graph-wrap"><canvas id="graph-canvas" width="900" height="520" ' +
          'role="img" aria-label="Link analysis graph"></canvas></div>' +
          '<div id="graph-counts" class="muted"></div>',
      ) + panel("Campaigns", '<div id="graph-campaigns"></div>')
    );
  }

  function graphSideMarkup() {
    return panel("Selection", '<div id="graph-detail">' + empty("Click a node in the graph.") + "</div>");
  }

  const NODE_COLORS = { finding: "#ef8d9e", indicator: "#77c9de", rule: "#61cbbb" };

  function radiusOf(node) {
    if (node.type === "indicator") return 4 + Math.min(6, (node.shared || 1) * 1.5);
    if (node.type === "rule") return 4 + Math.min(6, (node.count || 1));
    return 6;
  }

  /* Seed deterministically. A random start makes the same data settle into a
   * different picture every refresh, which is disorienting when an analyst is
   * trying to re-find the cluster they were just looking at. */
  function seedGraph(data) {
    const width = 900;
    const height = 520;
    const index = new Map();

    graphState.nodes = (data.nodes || []).map((node, i) => {
      const angle = (i / Math.max(1, (data.nodes || []).length)) * Math.PI * 2;
      const ring = node.type === "finding" ? 0.32 : node.type === "indicator" ? 0.46 : 0.2;
      const point = {
        ...node,
        x: width / 2 + Math.cos(angle) * width * ring,
        y: height / 2 + Math.sin(angle) * height * ring,
        vx: 0,
        vy: 0,
        r: radiusOf(node),
      };
      index.set(node.id, point);
      return point;
    });

    graphState.edges = (data.edges || [])
      .map((e) => ({ source: index.get(e.source), target: index.get(e.target), kind: e.kind }))
      .filter((e) => e.source && e.target);

    graphState.alpha = 1;
  }

  /* One cooling step. alpha decays toward zero so the layout settles instead
   * of jittering forever and burning CPU on a dashboard left open all day. */
  function stepGraph() {
    const nodes = graphState.nodes;
    const width = 900;
    const height = 520;

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        if (dist > 220) continue;
        const push = (900 / (dist * dist)) * graphState.alpha;
        dx /= dist;
        dy /= dist;
        a.vx -= dx * push;
        a.vy -= dy * push;
        b.vx += dx * push;
        b.vy += dy * push;
      }
    }

    graphState.edges.forEach((edge) => {
      const dx = edge.target.x - edge.source.x;
      const dy = edge.target.y - edge.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const pull = ((dist - 70) / dist) * 0.045 * graphState.alpha;
      const ox = dx * pull;
      const oy = dy * pull;
      edge.source.vx += ox;
      edge.source.vy += oy;
      edge.target.vx -= ox;
      edge.target.vy -= oy;
    });

    nodes.forEach((node) => {
      node.vx += (width / 2 - node.x) * 0.0012 * graphState.alpha;
      node.vy += (height / 2 - node.y) * 0.0012 * graphState.alpha;
      node.x = Math.max(node.r, Math.min(width - node.r, node.x + (node.vx *= 0.82)));
      node.y = Math.max(node.r, Math.min(height - node.r, node.y + (node.vy *= 0.82)));
    });

    graphState.alpha *= 0.975;
  }

  function drawGraph() {
    const canvas = el("graph-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const styles = getComputedStyle(document.body);

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = styles.getPropertyValue("--line").trim() || "#34393e";
    ctx.lineWidth = 1;
    graphState.edges.forEach((edge) => {
      ctx.beginPath();
      ctx.moveTo(edge.source.x, edge.source.y);
      ctx.lineTo(edge.target.x, edge.target.y);
      ctx.stroke();
    });

    graphState.nodes.forEach((node) => {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fillStyle = NODE_COLORS[node.type] || "#a0aaaf";
      ctx.globalAlpha = graphState.hover && graphState.hover !== node ? 0.45 : 1;
      ctx.fill();
      ctx.globalAlpha = 1;
    });

    /* Label only what is worth reading: a label per node is unreadable at any
     * useful node count. */
    ctx.fillStyle = styles.getPropertyValue("--text").trim() || "#e3e7e9";
    ctx.font = '11px ui-monospace, "Cascadia Mono", monospace';
    graphState.nodes
      .filter((n) => n.r > 7 || n === graphState.hover)
      .forEach((node) => ctx.fillText(String(node.label || "").slice(0, 26), node.x + node.r + 4, node.y + 3));
  }

  function graphLoop() {
    if (graphState.alpha > 0.008) stepGraph();
    drawGraph();
    graphState.raf = requestAnimationFrame(graphLoop);
  }

  function stopGraph() {
    if (graphState.raf) cancelAnimationFrame(graphState.raf);
    graphState.raf = 0;
  }

  function nodeAt(px, py) {
    return graphState.nodes.find((n) => Math.hypot(n.x - px, n.y - py) <= n.r + 4) || null;
  }

  function showNode(node) {
    const host = el("graph-detail");
    if (!host) return;
    if (!node) {
      host.innerHTML = empty("Click a node in the graph.");
      return;
    }

    const rows = [["Type", node.type], ["Label", node.label]];
    if (node.severity) rows.push(["Severity", node.severity]);
    if (node.status) rows.push(["Status", node.status]);
    if (node.path) rows.push(["Path", node.path]);
    if (node.namespace) rows.push(["Rule file", node.namespace]);
    if (node.indicator_type) rows.push(["Indicator", node.indicator_type]);
    if (node.scope) rows.push(["Scope", node.scope]);
    if (node.shared) rows.push(["Seen in", node.shared + " finding(s)"]);
    if (node.count) rows.push(["Fired on", node.count + " finding(s)"]);
    if ((node.attack || []).length) rows.push(["ATT&CK", node.attack.join(", ")]);

    host.innerHTML =
      '<dl class="graph-detail">' +
      rows.map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>").join("") +
      "</dl>";
  }

  function bindGraph() {
    const canvas = el("graph-canvas");
    if (!canvas || canvas.dataset.bound === "1") return;
    canvas.dataset.bound = "1";

    const locate = (event) => {
      const rect = canvas.getBoundingClientRect();
      return nodeAt(
        ((event.clientX - rect.left) / rect.width) * canvas.width,
        ((event.clientY - rect.top) / rect.height) * canvas.height,
      );
    };

    canvas.addEventListener("click", (event) => showNode(locate(event)));
    canvas.addEventListener("mousemove", (event) => {
      graphState.hover = locate(event);
      canvas.style.cursor = graphState.hover ? "pointer" : "default";
    });
    canvas.addEventListener("mouseleave", () => {
      graphState.hover = null;
    });
  }

  function renderGraph(data) {
    if (!el("graph-canvas")) return;

    seedGraph(data);
    bindGraph();
    stopGraph();
    graphLoop();

    const counts = data.counts || {};
    el("graph-counts").textContent =
      counts.findings +
      " findings, " +
      counts.indicators +
      " indicators, " +
      counts.rules +
      " rules, " +
      counts.edges +
      " edges" +
      (data.truncated ? " (truncated to the most connected nodes)" : "");

    el("graph-campaigns").innerHTML = (data.campaigns || []).length
      ? data.campaigns
          .map(
            (c) =>
              '<div class="campaign">' +
              sev(c.severity) +
              " <b>" +
              esc(c.size) +
              " findings</b>" +
              '<div class="muted">' +
              esc(c.first_seen) +
              " &rarr; " +
              esc(c.last_seen) +
              "</div>" +
              '<div class="campaign-why">linked by ' +
              (c.linked_by || [])
                .map((l) => '<code>' + esc(l.type) + " " + esc(l.value) + "</code>")
                .join(", ") +
              "</div>" +
              '<div class="muted">' +
              esc((c.files || []).join(", ")) +
              "</div>" +
              ((c.attack || []).length
                ? '<div class="campaign-attack">' +
                  c.attack.map((t) => '<span class="chip">' + esc(t) + "</span>").join("") +
                  "</div>"
                : "") +
              "</div>",
          )
          .join("")
      : empty("No findings share a linking indicator, so there are no campaigns.");
  }

  /* -------------------------------------------------------------- Cases */

  function casesMarkup() {
    return (
      panel(
        "Open a case",
        '<form id="case-form" class="case-form">' +
          '<input id="case-title" type="text" placeholder="Title" aria-label="Case title" maxlength="160" required>' +
          '<input id="case-owner" type="text" placeholder="Owner" aria-label="Owner" maxlength="80">' +
          '<select id="case-severity" aria-label="Severity">' +
          ["critical", "high", "medium", "low", "info"]
            .map((s) => '<option value="' + s + '"' + (s === "medium" ? " selected" : "") + ">" + s + "</option>")
            .join("") +
          "</select>" +
          "<button type=\"submit\">Create</button>" +
          "</form>",
      ) + panel("Cases", '<div id="case-list"></div>')
    );
  }

  function casesSideMarkup() {
    return panel("Case detail", '<div id="case-detail">' + empty("Select a case.") + "</div>");
  }

  function renderCases(data, handlers) {
    const host = el("case-list");
    if (!host) return;

    const summary = data.summary || {};
    const cases = data.cases || [];

    host.innerHTML =
      '<p class="muted">' +
      esc(summary.total || 0) +
      " case(s), " +
      esc(summary.open || 0) +
      " not closed</p>" +
      (cases.length
        ? '<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Status</th>' +
          "<th>Findings</th><th>Updated</th><th></th></tr></thead><tbody>" +
          cases
            .map(
              (c) =>
                "<tr><td>" +
                sev(c.severity) +
                '</td><td><button type="button" class="case-open" data-id="' +
                esc(c.id) +
                '">' +
                esc(c.title) +
                "</button></td><td>" +
                esc(c.status) +
                "</td><td>" +
                esc((c.finding_ids || []).length) +
                "</td><td>" +
                esc(c.updated_at) +
                '</td><td><a class="case-report" href="/api/report?id=' +
                encodeURIComponent(c.id) +
                '">report</a></td></tr>',
            )
            .join("") +
          "</tbody></table>"
        : empty("No cases yet."));

    host.querySelectorAll(".case-open").forEach((b) =>
      b.addEventListener("click", () => handlers.open(b.dataset.id)),
    );
  }

  function renderCaseDetail(payload, handlers) {
    const host = el("case-detail");
    if (!host) return;

    const record = payload.case || {};
    const findings = payload.findings || [];

    host.innerHTML =
      "<h3>" +
      esc(record.title) +
      "</h3>" +
      '<dl class="graph-detail"><dt>Status</dt><dd>' +
      esc(record.status) +
      "</dd><dt>Severity</dt><dd>" +
      esc(record.severity) +
      "</dd><dt>Owner</dt><dd>" +
      esc(record.owner || "unassigned") +
      "</dd><dt>Opened</dt><dd>" +
      esc(record.created_at) +
      "</dd></dl>" +
      (record.summary ? "<p>" + esc(record.summary) + "</p>" : "") +
      '<div class="case-actions">' +
      ["investigating", "contained", "closed"]
        .map(
          (s) =>
            '<button type="button" class="case-status" data-status="' + s + '">' + esc(s) + "</button>",
        )
        .join("") +
      "</div>" +
      '<form id="case-note-form" class="case-note">' +
      '<textarea id="case-note-text" rows="2" placeholder="Add a note" aria-label="Case note" maxlength="4000"></textarea>' +
      "<button type=\"submit\">Add note</button></form>" +
      "<h4>Evidence</h4>" +
      (findings.length
        ? '<ul class="case-evidence">' +
          findings
            .map(
              (f) =>
                "<li>" +
                sev(f.severity) +
                " " +
                esc(f.file_name || f.file_path || "-") +
                '<button type="button" class="case-unlink" data-id="' +
                esc(f.id) +
                '" aria-label="Detach">&times;</button></li>',
            )
            .join("") +
          "</ul>"
        : empty("No findings linked yet.")) +
      "<h4>Notes</h4>" +
      ((record.notes || []).length
        ? (record.notes || [])
            .map(
              (n) =>
                '<div class="note"><b>' +
                esc(n.at) +
                (n.author ? " &middot; " + esc(n.author) : "") +
                "</b><br>" +
                esc(n.text) +
                "</div>",
            )
            .join("")
        : empty("No notes yet.")) +
      '<p><a class="case-report" href="/api/report?id=' +
      encodeURIComponent(record.id) +
      '">Download incident report</a></p>';

    host.querySelectorAll(".case-status").forEach((b) =>
      b.addEventListener("click", () => handlers.status(record.id, b.dataset.status)),
    );
    host.querySelectorAll(".case-unlink").forEach((b) =>
      b.addEventListener("click", () => handlers.unlink(record.id, b.dataset.id)),
    );
    const noteForm = el("case-note-form");
    if (noteForm) {
      noteForm.addEventListener("submit", (event) => {
        event.preventDefault();
        handlers.note(record.id, el("case-note-text").value);
      });
    }
  }

  return {
    attackMarkup,
    renderAttack,
    huntMarkup,
    huntSideMarkup,
    renderHunt,
    renderSavedHunts,
    graphMarkup,
    graphSideMarkup,
    renderGraph,
    stopGraph,
    casesMarkup,
    casesSideMarkup,
    renderCases,
    renderCaseDetail,
  };
})();
