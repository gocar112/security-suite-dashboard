/* Ctrl-K command palette.
 *
 * A SOC console is used under time pressure by people who already know where
 * they are going. Nine views behind a mouse is slower than one keystroke and a
 * prefix, so navigation, saved hunts and the handful of actions that change
 * state all live behind the same fuzzy list.
 */
import { $, esc, api, post, toast } from "./core.js";
import { VIEWS, showView } from "./router.js";

let commands = [];
let filtered = [];
let cursor = 0;

function baseCommands() {
  const out = VIEWS.map((v) => ({
    label: "Go to " + v.label,
    hint: "view",
    terms: (v.label + " " + (v.keywords || "")).toLowerCase(),
    run: () => showView(v.id),
  }));
  out.push(
    {
      label: "Reload YARA rules", hint: "action", terms: "reload rules yara recompile refresh",
      run: async () => {
        const info = await post("/api/rules/reload", {});
        toast("Reloaded " + info.rule_count + " rules");
      },
    },
    {
      label: "Pause / resume monitor", hint: "action", terms: "pause resume monitor stop start watch",
      run: async () => {
        const paused = $("btn-monitor").textContent.trim().toLowerCase() === "resume";
        await post("/api/monitor", { action: paused ? "resume" : "pause" });
      },
    },
    {
      label: "Export indicators as CSV", hint: "action", terms: "export csv indicators ioc download",
      run: () => window.open("/api/iocs?format=csv&limit=1000", "_blank"),
    },
  );
  return out;
}

async function savedHuntCommands() {
  try {
    const { hunts } = await api("/api/hunt/saved");
    return (hunts || []).map((h) => ({
      label: "Hunt: " + h.name,
      hint: "saved",
      run: () => {
        showView("hunt");
        // Let the view become visible before the box is filled and fired.
        setTimeout(() => document.dispatchEvent(new CustomEvent("suite:hunt",
          { detail: { query: h.query } })), 0);
      },
    }));
  } catch (_) {
    return [];
  }
}

function score(cmd, needle) {
  // Match the label first, then its search terms, then a loose subsequence so
  // "gof" still finds "Go to Findings".
  if (!needle) return 0;
  const label = cmd.label.toLowerCase();
  if (label.includes(needle)) return 100 - label.indexOf(needle);
  const terms = cmd.terms || label;
  if (terms.includes(needle)) return 60;
  let i = 0;
  for (const ch of label) if (ch === needle[i]) i++;
  return i === needle.length ? 10 : -1;
}

function render() {
  const list = $("palette-list");
  if (!list) return;
  list.innerHTML = filtered.length
    ? filtered.map((cmd, i) =>
        '<li class="palette-item' + (i === cursor ? " active" : "") + '" data-i="' + i + '">' +
          '<span>' + esc(cmd.label) + '</span>' +
          '<i>' + esc(cmd.hint) + '</i></li>').join("")
    : '<li class="palette-empty">No matching command.</li>';
  list.querySelectorAll(".palette-item").forEach((li) =>
    li.addEventListener("click", () => choose(Number(li.dataset.i))));
}

function filter(text) {
  const needle = text.trim().toLowerCase();
  filtered = commands
    .map((cmd) => ({ cmd, s: score(cmd, needle) }))
    .filter((x) => !needle || x.s >= 0)
    .sort((a, b) => b.s - a.s)
    .map((x) => x.cmd)
    .slice(0, 12);
  cursor = 0;
  render();
}

function choose(index) {
  const cmd = filtered[index];
  close();
  if (cmd) Promise.resolve(cmd.run()).catch((e) => toast(e.message, true));
}

export function openPalette() {
  const overlay = $("palette");
  if (!overlay) return;
  overlay.hidden = false;
  const input = $("palette-input");
  input.value = "";
  filter("");
  input.focus();
}

export function close() {
  const overlay = $("palette");
  if (overlay) overlay.hidden = true;
}

export async function mountPalette() {
  commands = baseCommands();
  savedHuntCommands().then((extra) => { commands = baseCommands().concat(extra); });

  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
      return;
    }
    if (e.key === "Escape") return close();
    if (typing) return;
    // Bare "/" focuses search the way every other console does.
    if (e.key === "/" && $("q")) { e.preventDefault(); $("q").focus(); }
  });

  const input = $("palette-input");
  if (input) {
    input.addEventListener("input", () => filter(input.value));
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); cursor = Math.min(cursor + 1, filtered.length - 1); render(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); cursor = Math.max(cursor - 1, 0); render(); }
      else if (e.key === "Enter") { e.preventDefault(); choose(cursor); }
    });
  }
  const overlay = $("palette");
  if (overlay) {
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  }
}
