import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");

function idsIn(markup) {
  return new Set([
    ...[...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]),
    ...[...markup.matchAll(/\.id\s*=\s*"([^"]+)"/g)].map((match) => match[1]),
  ]);
}

function referencedIds(script, helper) {
  const patterns = {
    "$": /\$\("([^"]+)"\)/g,
    byId: /byId\("([^"]+)"\)/g,
    studioId: /studioId\("([^"]+)"\)/g,
    settingId: /settingId\("([^"]+)"\)/g,
  };
  const pattern = patterns[helper];
  assert.ok(pattern, `unknown DOM helper: ${helper}`);
  return new Set([...script.matchAll(pattern)].map((match) => match[1]));
}

function assertWiring(name, markupFile, scriptFile, helper) {
  const markup = read(markupFile);
  const script = read(scriptFile);
  // The main dashboard mounts its finding drawer from a template in app.js;
  // include those dynamic IDs alongside static HTML IDs.
  const ids = new Set([...idsIn(markup), ...idsIn(script)]);
  const missing = [...referencedIds(script, helper)].filter((id) => !ids.has(id));
  assert.deepEqual(missing, [], `${name} references missing DOM ids: ${missing.join(", ")}`);
}

assertWiring("dashboard", "web/index.html", "web/app.js", "$");
assertWiring("briefing", "web/briefing.html", "web/briefing.js", "byId");
assertWiring("studio", "web/studio.html", "web/studio.js", "studioId");
assertWiring("settings", "web/settings.html", "web/settings.js", "settingId");

for (const asset of [
  "web/briefing.css", "web/briefing.js", "web/studio.css", "web/studio.js",
  "web/settings.css", "web/settings.js", "assets/security-studio-icon.png",
  "assets/security-studio.ico",
]) {
  assert.ok(fs.existsSync(path.join(root, asset)), `missing asset: ${asset}`);
}

console.log("Frontend wiring tests passed");
