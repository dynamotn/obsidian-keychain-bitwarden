import { defineConfig } from "vitest/config";
import { coreWasm } from "./scripts/core-wasm.mjs";

export default defineConfig({
  plugins: [coreWasm()],
  test: {
    include: ["test/integration/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
  },
});
