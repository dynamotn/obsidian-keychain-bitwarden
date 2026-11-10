// Runs the unit suites inside real browser engines: WebKit stands in for
// Obsidian iOS (WKWebView), Chromium for Obsidian Android (System WebView).
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";
import { coreWasm } from "./scripts/core-wasm.mjs";

export default defineConfig({
  plugins: [coreWasm()],
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/integration/**", "test/sdk/**", "test/vectors/**"],
    globalSetup: ["test/setup/argon2-worker.ts"],
    testTimeout: 60_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "webkit" }, { browser: "chromium" }],
    },
  },
});
