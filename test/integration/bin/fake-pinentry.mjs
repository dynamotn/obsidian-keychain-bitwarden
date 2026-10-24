#!/usr/bin/env node
// Minimal Assuan pinentry for tests: answers GETPIN with $BW_IT_PASSWORD.
import { createInterface } from "node:readline";

const pin = process.env.BW_IT_PASSWORD ?? "";
const out = (line) => process.stdout.write(`${line}\n`);
const encode = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

out("OK fake pinentry ready");
createInterface({ input: process.stdin }).on("line", (line) => {
  const cmd = line.split(" ")[0].toUpperCase();
  if (cmd === "GETPIN") out(`D ${encode(pin)}`);
  if (cmd === "BYE") {
    out("OK");
    process.exit(0);
  }
  out("OK");
});
