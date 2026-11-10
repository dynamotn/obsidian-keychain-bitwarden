/** Source of the bundled Argon2 worker, embedded at build time by esbuild.config.mjs. */
declare module "virtual:argon2-worker" {
  const source: string;
  export default source;
}

/** The dybw-core WASM module as base64, embedded at build time by esbuild.config.mjs (scripts/core-wasm.mjs). */
declare module "virtual:dybw-core-wasm" {
  const base64: string;
  export default base64;
}
