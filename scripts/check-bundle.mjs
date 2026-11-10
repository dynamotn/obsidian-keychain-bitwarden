// Portability gate for the built main.js: Obsidian mobile has no Node.js, so
// the bundle may only require "obsidian" and must not touch Node globals.
// ADR 0024 caps its size, the embedded dybw-core module included, at 1.5 MiB.
import { readFileSync, statSync } from "node:fs";

const BUDGET = 1_572_864;
const code = readFileSync("main.js", "utf8");
const size = statSync("main.js").size;
const problems = [];
if (size > BUDGET) problems.push(`is ${size} bytes, over the budget of ${BUDGET} bytes (ADR 0024)`);

const required = new Set([...code.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1]));
for (const mod of required) if (mod !== "obsidian") problems.push(`requires "${mod}"`);

for (const [label, re] of [
  ["Buffer", /\bBuffer\.(from|alloc|concat)\b/],
  ["process", /\bprocess\.(env|versions|platform|nextTick)\b/],
  ["__dirname", /\b__dirname\b/],
  ["eval", /\beval\(/],
  ["new Function", /\bnew Function\(/],
]) {
  if (re.test(code)) problems.push(`uses ${label}`);
}

const kib = (size / 1024).toFixed(1);
if (problems.length) {
  console.error(`main.js (${kib} KiB) fails the bundle check:\n  - ${problems.join("\n  - ")}`);
  process.exit(1);
}
console.log(`main.js (${size} of ${BUDGET} bytes, ${kib} KiB): requires only ${[...required].join(", ") || "nothing"}; no Node globals`);
