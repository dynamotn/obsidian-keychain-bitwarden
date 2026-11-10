import { describe, expect, it } from "vitest";
import { coreLoader } from "../src/core/load";

describe("coreLoader", () => {
  it("the core loads once: two loads, even at the same time, share one instance", async () => {
    const load = coreLoader();
    const [first, second] = await Promise.all([load(), load()]);
    expect(first).toBe(second);
    expect(await load()).toBe(first);
    expect(first.memory).toBeInstanceOf(WebAssembly.Memory);
  });
});
