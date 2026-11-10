// Loads the dybw-core WASM module that esbuild embeds in main.js as base64 (scripts/core-wasm.mjs).
import init, { type InitOutput } from "../../vendor/dybw-core/dybw_core_wasm.js";
import coreWasm from "virtual:dybw-core-wasm";

function decode(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * One loader per plugin instance: the first call decodes, compiles and instantiates the module, every later call
 * (also one made before the first finished) gets the same instance. The async `init`, not `initSync`: Chromium
 * refuses synchronous compiles of a module this size on the main thread.
 */
export function coreLoader(): () => Promise<InitOutput> {
  let loading: Promise<InitOutput> | undefined;
  return () => (loading ??= init({ module_or_path: decode(coreWasm) }));
}
