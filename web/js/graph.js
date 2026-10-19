/* Link-analysis view: a force-directed graph on canvas, hand-rolled.
 *
 * Deliberately not a charting library. The server is loopback-bound and may be
 * running with no outbound network, the page ships under a CSP that allows no
 * third-party script, and the repo has no bundler to vendor one through. About
 * 140 lines of Verlet-ish integration is cheaper than any of those constraints.
 *
 * The simulation cools: alpha decays toward zero so the layout settles instead
 * of jittering forever, and a drag reheats it just enough to relax again.
 */
import { $, esc, api, toast } from "./core.js";

const COLORS = {
  finding: { critical: "#ff6a7a", high: "#ff9f5a", medium: "#ffd166",
             low: "#9ae66e", info: "#7aa2c7" },
  indicator: "#b79cff",
  rule: "#47e0c0",
};

let data = { nodes: [], edges: [], campaigns: [] };
let sim = { nodes: [], edges: [], alpha: 0 };
let view = { x: 0, y: 0, k: 1 };
let canvas = null, ctx = null, raf = null;
let hover = null, dragging = null;
let pointer = { x: 0, y: 0, down: false, panning: false, lastX: 0, lastY: 0 };

function colorOf(node) {
  if (node.type === "finding") return COLORS.finding[node.severity] || COLORS.finding.info;
  return COLORS[node.type] || "#7aa2c7";
}

function radiusOf(node) {
  if (node.type === "finding") return 7;
  if (node.type === "indicator") return 4 + Math.min(5, (node.shared || 1));
  return 5 + Math.min(6, (node.count || 1));
}

/* ------------------------------------------------------------- simulation */
function seed(payload) {
  const w = canvas.width, h = canvas.height;
  const byId = new Map();
  sim.nodes = payload.nodes.map((n, i) => {
    // Seed on a ring rather than at random: a deterministic start means the
    // same data lays out the same way twice, which matters when an analyst is
    // comparing two screenshots.
    const angle = (i / Math.max(1, payload.nodes.length)) * Math.PI * 2;
    const node = {
      ...n,
      x: w / 2 + Math.cos(angle) * (w / 3.4),
      y: h / 2 + Math.sin(angle) * (h / 3.4),
      vx: 0, vy: 0, r: radiusOf(n),
    };
    byId.set(n.id, node);
    return node;
  });
  sim.edges = payload.edges
    .map((e) => ({ source: byId.get(e.source), target: byId.get(e.target), kind: e.kind }))
    .filter((e) => e.source && e.target);
  sim.alpha = 1;
}

function tick() {
  const { nodes, edges } = sim;
  const w = canvas.width, h = canvas.height;
  const alpha = sim.alpha;

  // Repulsion. O(n^2), which is fine at the node ceiling the server enforces.
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { d2 = 1; dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); }
      if (d2 > 90000) continue;                 // ignore distant pairs
      const force = (1400 * alpha) / d2;
      const d = Math.sqrt(d2);
      const fx = (dx / d) * force, fy = (dy / d) * force;
      a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
    }
  }
  // Springs.
  for (const edge of edges) {
    const a = edge.source, b = edge.target;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const rest = edge.kind === "observed" ? 62 : 48;
    const force = ((d - rest) / d) * 0.045 * alpha;
    const fx = dx * force, fy = dy * force;
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  }
  // Gravity toward the middle, then integrate.
  for (const node of nodes) {
    if (node === dragging) { node.vx = 0; node.vy = 0; continue; }
    node.vx += (w / 2 - node.x) * 0.0016 * alpha;
    node.vy += (h / 2 - node.y) * 0.0016 * alpha;
    node.vx *= 0.86; node.vy *= 0.86;
    node.x += node.vx; node.y += node.vy;
  }
  sim.alpha *= 0.985;
}

/* ----------------------------------------------------------------- render */
function draw() {
  const w = canvas.width, h = canvas.height;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.translate(view.x, view.y);
  ctx.scale(view.k, view.k);

  ctx.lineWidth = 1;
  for (const edge of sim.edges) {
    const lit = hover && (edge.source === hover || edge.target === hover);
    ctx.strokeStyle = lit ? "rgba(71,224,192,.55)" : "rgba(120,150,190,.16)";
    ctx.beginPath();
    ctx.moveTo(edge.source.x, edge.source.y);
    ctx.lineTo(edge.target.x, edge.target.y);
    ctx.stroke();
  }

  for (const node of sim.nodes) {
    const lit = node === hover;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
    ctx.fillStyle = colorOf(node);
    ctx.globalAlpha = lit ? 1 : 0.88;
    ctx.fill();
    if (node.type === "finding") {
      ctx.globalAlpha = 1;
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = "rgba(7,17,31,.85)";
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }

  // Label only what the eye can actually read: the hovered node and the
  // best-connected few. Labelling 600 nodes produces a grey rectangle.
  ctx.font = "11px 'Cascadia Mono', Consolas, monospace";
  ctx.textAlign = "center";
  const labelled = new Set(sim.nodes.filter((n) => n.type === "finding").slice(0, 14));
  if (hover) labelled.add(hover);
  for (const node of labelled) {
    const text = String(node.label || "").slice(0, 26);
    ctx.fillStyle = node === hover ? "#eaf2ff" : "rgba(200,214,232,.62)";
    ctx.fillText(text, node.x, node.y - node.r - 5);
  }
}

function loop() {
  if (sim.alpha > 0.004) tick();
  draw();
  raf = requestAnimationFrame(loop);
}

/* ------------------------------------------------------------ interaction */
function toWorld(px, py) {
  return { x: (px - view.x) / view.k, y: (py - view.y) / view.k };
}

function nodeAt(px, py) {
  const p = toWorld(px, py);
  let best = null, bestD = Infinity;
  for (const node of sim.nodes) {
    const dx = node.x - p.x, dy = node.y - p.y;
    const d = dx * dx + dy * dy;
    if (d < (node.r + 5) ** 2 && d < bestD) { best = node; bestD = d; }
  }
  return best;
}

function showDetail(node) {
  const box = $("graph-detail");
  if (!box) return;
  if (!node) { box.innerHTML = '<span class="faint">Hover a node, click a finding to open it.</span>'; return; }
  if (node.type === "finding") {
    box.innerHTML = '<b>' + esc(node.label) + '</b>' +
      '<div class="mono faint">' + esc(node.path || "") + '</div>' +
      '<div><span class="sev sev-' + esc(node.severity) + '">' + esc(node.severity) +
      '</span> <span class="faint mono">' + esc(node.status) + ' &middot; ' +
      esc(node.timestamp || "") + '</span></div>';
  } else if (node.type === "indicator") {
    box.innerHTML = '<b>' + esc(node.label) + '</b>' +
      '<div class="faint mono">' + esc(node.indicator_type) +
      (node.scope ? " &middot; " + esc(node.scope) : "") +
      ' &middot; seen in ' + esc(node.shared) + ' finding(s)</div>';
  } else {
    box.innerHTML = '<b><code>' + esc(node.label) + '</code></b>' +
      '<div class="faint mono">' + esc(node.namespace || "") + ' &middot; ' +
      esc(node.count) + ' hit(s)' +
      ((node.attack || []).length ? " &middot; " + node.attack.map(esc).join(" ") : "") +
      '</div>';
  }
}

function bindCanvas() {
  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    if (dragging) {
      const p = toWorld(px, py);
      dragging.x = p.x; dragging.y = p.y;
      sim.alpha = Math.max(sim.alpha, 0.22);
      return;
    }
    if (pointer.panning) {
      view.x += px - pointer.lastX;
      view.y += py - pointer.lastY;
      pointer.lastX = px; pointer.lastY = py;
      return;
    }
    const found = nodeAt(px, py);
    if (found !== hover) {
      hover = found;
      canvas.style.cursor = found ? "pointer" : "grab";
      showDetail(found);
    }
  });
  canvas.addEventListener("mousedown", (e) => {
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    const found = nodeAt(px, py);
    if (found) { dragging = found; }
    else { pointer.panning = true; pointer.lastX = px; pointer.lastY = py; }
  });
  window.addEventListener("mouseup", () => { dragging = null; pointer.panning = false; });
  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const found = nodeAt(e.clientX - rect.left, e.clientY - rect.top);
    if (found && found.type === "finding") {
      document.dispatchEvent(new CustomEvent("suite:open-finding",
        { detail: { id: found.finding_id } }));
    }
  });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    const before = toWorld(px, py);
    view.k = Math.max(0.25, Math.min(3, view.k * (e.deltaY < 0 ? 1.12 : 0.89)));
    const after = toWorld(px, py);
    view.x += (after.x - before.x) * view.k;
    view.y += (after.y - before.y) * view.k;
  }, { passive: false });
}

function renderCampaigns() {
  const wrap = $("campaign-list");
  if (!wrap) return;
  const campaigns = data.campaigns || [];
  if (!campaigns.length) {
    wrap.innerHTML = '<span class="faint">No campaigns yet. Two findings become a ' +
      'campaign when they share a linking indicator - a C2 address, a wallet, a hash.</span>';
    return;
  }
  wrap.innerHTML = campaigns.map((c) =>
    '<div class="campaign" data-ids="' + esc((c.finding_ids || []).join(",")) + '">' +
      '<div class="campaign-head">' +
        '<span class="sev sev-' + esc(c.severity) + '">' + esc(c.severity) + '</span>' +
        '<b>' + esc(c.size) + ' findings</b>' +
        '<span class="faint mono">' + esc((c.first_seen || "").slice(11, 19)) +
          ' → ' + esc((c.last_seen || "").slice(11, 19)) + '</span>' +
        '<button class="action-btn tiny" data-case="' + esc(c.id) + '">Open case</button>' +
      '</div>' +
      '<div class="campaign-why">linked by ' + (c.linked_by || []).map((l) =>
        '<code>' + esc(l.value) + '</code>').join(", ") + '</div>' +
      '<div class="campaign-files faint mono">' +
        (c.files || []).map(esc).join(" · ") + '</div>' +
      ((c.attack || []).length ? '<div class="campaign-attack">' + c.attack.map((t) =>
        '<span class="attack-chip">' + esc(t) + '</span>').join("") + '</div>' : '') +
    '</div>').join("");

  wrap.querySelectorAll("button[data-case]").forEach((btn) =>
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const box = btn.closest(".campaign");
      document.dispatchEvent(new CustomEvent("suite:case-from-campaign", {
        detail: { finding_ids: (box.dataset.ids || "").split(",").filter(Boolean) },
      }));
    }));
}

export async function loadGraph() {
  try {
    data = await api("/api/graph?limit=800");
  } catch (err) {
    toast("Could not build graph: " + err.message, true);
    return;
  }
  const note = $("graph-note");
  if (note) {
    const c = data.counts || {};
    note.textContent = c.findings + " findings · " + c.indicators + " indicators · " +
      c.rules + " rules · " + c.edges + " edges" +
      (data.truncated ? " (truncated)" : "");
  }
  renderCampaigns();
  if (canvas) { seed(data); showDetail(null); }
}

export function mountGraph() {
  canvas = $("graph-canvas");
  if (!canvas) return;
  ctx = canvas.getContext("2d");
  const resize = () => {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = Math.max(320, rect.width - 2);
    canvas.height = Math.max(360, Math.min(620, window.innerHeight - 300));
  };
  resize();
  window.addEventListener("resize", resize);
  bindCanvas();
  const reheat = $("graph-relax");
  if (reheat) reheat.addEventListener("click", () => { seed(data); });
  if (!raf) loop();
}
