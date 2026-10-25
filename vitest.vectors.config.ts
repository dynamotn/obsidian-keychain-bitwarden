import { defineConfig } from "vitest/config";

// The dybw conformance vectors, run on request only:
// DYBW_VECTORS_DIR=<dybw-core>/vectors npm run test:vectors
export default defineConfig({
  test: {
    include: ["test/vectors/**/*.test.ts"],
    testTimeout: 60_000,
  },
});
