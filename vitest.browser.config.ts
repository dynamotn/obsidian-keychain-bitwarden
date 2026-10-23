// Runs the unit suites inside real browser engines: WebKit stands in for
// Obsidian iOS (WKWebView), Chromium for Obsidian Android (System WebView).
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/integration/**"],
    testTimeout: 60_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "webkit" }, { browser: "chromium" }],
    },
  },
});
