import esbuild from "esbuild";
import { buildArgon2Worker } from "./scripts/argon2-worker.mjs";

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
  plugins: [embedWorker],
  outfile: "main.js",
});
