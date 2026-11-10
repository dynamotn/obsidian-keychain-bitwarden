import { describe, expect, it, vi } from "vitest";
import { coreLoader } from "../src/core/load";

describe("coreLoader", () => {
  it("the core loads once: two loads, even at the same time, share one instance", async () => {
    const load = coreLoader();
    const [first, second] = await Promise.all([load(), load()]);
    expect(first).toBe(second);
    expect(await load()).toBe(first);
    expect(first.memory).toBeInstanceOf(WebAssembly.Memory);
  });

  it("a load that fails rejects instead of throwing, and the next call tries again", async () => {
    const atob = vi.spyOn(globalThis, "atob").mockImplementationOnce(() => {
      throw new DOMException("corrupt", "InvalidCharacterError");
    });
    const load = coreLoader();
    const failed = load();
    await expect(failed).rejects.toThrow("corrupt");
    expect((await load()).memory).toBeInstanceOf(WebAssembly.Memory);
    expect(atob).toHaveBeenCalledTimes(2);
    atob.mockRestore();
  });
});
