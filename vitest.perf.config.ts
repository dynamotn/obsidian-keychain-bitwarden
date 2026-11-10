import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";
import { coreWasm } from "./scripts/core-wasm.mjs";

const browser = process.env.PERF_BROWSER === "1";

export default defineConfig({
  plugins: [coreWasm()],
  test: {
    include: ["test/perf/**/*.test.ts"],
    testTimeout: 120_000,
    fileParallelism: false,
    browser: browser
      ? {
          enabled: true,
          headless: true,
          provider: playwright(),
          instances: [{ browser: "webkit" }, { browser: "chromium" }],
        }
      : undefined,
  },
});
