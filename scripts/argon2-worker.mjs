// Builds the Argon2 worker as one self-contained script. The plugin embeds the
// result in main.js (esbuild.config.mjs) and starts it from a Blob URL; the
// browser tests run the very same output (test/setup/argon2-worker.ts).
import esbuild from "esbuild";

export async function buildArgon2Worker({ minify = true } = {}) {
  const result = await esbuild.build({
    entryPoints: ["src/bw/argon2.worker.ts"],
    bundle: true,
    platform: "browser",
    target: "es2022",
    format: "iife",
    minify,
    write: false,
    logLevel: "warning",
  });
  return result.outputFiles[0].text;
}
