// Types for core-wasm.mjs, which the vitest configs import.
import type { Plugin } from "vite";

export const CORE_DIR: string;
export const VIRTUAL_ID: string;
export function coreWasmBase64(): string;
export function coreWasm(): Plugin;
