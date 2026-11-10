// The dybw-core WASM module that main.js embeds as `virtual:dybw-core-wasm` (a base64 string). esbuild.config.mjs
// and every vitest config read it from here, so the tests load the very module the plugin ships.
// `node scripts/core-wasm.mjs` only checks that it was built.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const CORE_DIR = "vendor/dybw-core";
export const VIRTUAL_ID = "virtual:dybw-core-wasm";

/** The module as base64; fails with what to run when `scripts/build-core.sh` has not built it. */
export function coreWasmBase64() {
  try {
    return readFileSync(`${CORE_DIR}/dybw_core_wasm_bg.wasm`).toString("base64");
  } catch {
    throw new Error(
      `${CORE_DIR} is missing: build the dybw-core WASM module first with scripts/build-core.sh ` +
        "(DYBW_CORE_DIR=<a dybw-core checkout> to use a local one; see core.rev for the pinned commit)",
    );
  }
}

/** The Vite plugin the vitest configs use: the same virtual module as the esbuild build. */
export function coreWasm() {
  const resolved = `\0${VIRTUAL_ID}`;
  return {
    name: "dybw-core-wasm",
    resolveId: (id) => (id === VIRTUAL_ID ? resolved : undefined),
    load: (id) => (id === resolved ? `export default ${JSON.stringify(coreWasmBase64())};` : undefined),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    coreWasmBase64();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
