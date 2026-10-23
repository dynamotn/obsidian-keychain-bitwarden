// Portability gate for the built main.js: Obsidian mobile has no Node.js, so
// the bundle may only require "obsidian" and must not touch Node globals.
import { readFileSync, statSync } from "node:fs";

const code = readFileSync("main.js", "utf8");
const problems = [];

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

const kib = (statSync("main.js").size / 1024).toFixed(1);
if (problems.length) {
  console.error(`main.js (${kib} KiB) is not portable:\n  - ${problems.join("\n  - ")}`);
  process.exit(1);
}
console.log(`main.js (${kib} KiB): requires only ${[...required].join(", ") || "nothing"}; no Node globals`);
