import esbuild from "esbuild";
import { buildArgon2Worker } from "./scripts/argon2-worker.mjs";
import { coreWasmBase64, VIRTUAL_ID } from "./scripts/core-wasm.mjs";

const production = process.argv.includes("--production");

// A plugin ships as one file, so the Argon2 worker is embedded as text and
// started from a Blob URL.
const workerSource = await buildArgon2Worker({ minify: production });
const embedWorker = {
  name: "embed-argon2-worker",
  setup(build) {
    build.onResolve({ filter: /^virtual:argon2-worker$/ }, (args) => ({ path: args.path, namespace: "argon2-worker" }));
    build.onLoad({ filter: /.*/, namespace: "argon2-worker" }, () => ({
      contents: `export default ${JSON.stringify(workerSource)};`,
      loader: "js",
    }));
  },
};

// The dybw-core module, embedded as base64 the same way; its glue is bundled as an ordinary module.
const coreWasm = coreWasmBase64();
const embedCore = {
  name: "embed-dybw-core-wasm",
  setup(build) {
    build.onResolve({ filter: /^virtual:dybw-core-wasm$/ }, (args) => ({ path: args.path, namespace: VIRTUAL_ID }));
    build.onLoad({ filter: /.*/, namespace: VIRTUAL_ID }, () => ({
      contents: `export default ${JSON.stringify(coreWasm)};`,
      loader: "js",
    }));
  },
};

await esbuild.build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  // "browser" makes the build fail on any Node built-in import, which would
  // break the plugin on Obsidian mobile.
  platform: "browser",
  format: "cjs",
  target: "es2022",
  external: ["obsidian", "electron"],
  sourcemap: production ? false : "inline",
  minify: production,
  treeShaking: true,
  logLevel: "info",
  plugins: [embedWorker, embedCore],
  outfile: "main.js",
});
