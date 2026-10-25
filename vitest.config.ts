import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The conformance vectors are opt-in: `npm run test:vectors`.
    exclude: ["test/integration/**", "test/vectors/**"],
    testTimeout: 30_000,
    // `npm run test:coverage` (CI and releases) fails below 100% for the code
    // that runs without Obsidian. Left out: main.ts and ui.ts, the glue that
    // needs Obsidian's runtime; the Argon2 worker, which only a browser can
    // start (test:browser runs it against known answers); and type declarations.
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/main.ts", "src/ui.ts", "src/bw/argon2.worker.ts", "src/**/*.d.ts"],
      reporter: ["text", "json"],
      thresholds: { lines: 100, branches: 100, functions: 100, statements: 100 },
    },
  },
});
