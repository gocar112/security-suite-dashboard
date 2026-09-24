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
  const pattern = helper === "$"
    ? /\$\("([^"]+)"\)/g
    : /byId\("([^"]+)"\)/g;
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

for (const asset of ["web/briefing.css", "web/briefing.js", "assets/securitysuite.png"]) {
  assert.ok(fs.existsSync(path.join(root, asset)), `missing asset: ${asset}`);
}

console.log("Frontend wiring tests passed");
