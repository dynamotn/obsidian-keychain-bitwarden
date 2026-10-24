import { describe, expect, it } from "vitest";
import { parseDeviceState, resetDeviceState } from "../src/sync/state";

const entry = { cipherId: "c1", revisionDate: "r1", fingerprint: "f1" };

describe("parseDeviceState", () => {
  it("makes up a device id when the stored one is missing or empty", () => {
    for (const deviceId of [undefined, "", 42]) {
      const s = parseDeviceState({ version: 1, deviceId, base: { a: entry } });
      expect(s.deviceId).toMatch(/^[0-9a-f-]{36}$/);
      expect(s.base).toEqual({ a: entry });
    }
  });

  it("starts fresh from a state of another version, keeping only the device id", () => {
    const s = parseDeviceState({ version: 2, deviceId: "d1", base: { a: entry }, pendingCreates: ["b"], pendingScopes: { b: "global" } });
    expect(s).toEqual({ version: 1, deviceId: "d1", base: {}, pendingCreates: [], pendingScopes: {} });
  });

  it("drops parts that are not of the right kind", () => {
    const s = parseDeviceState({ version: 1, deviceId: "d1", base: "a", pendingCreates: "b", pendingScopes: null });
    expect(s).toEqual({ version: 1, deviceId: "d1", base: {}, pendingCreates: [], pendingScopes: {} });
  });
});

describe("resetDeviceState", () => {
  it("forgets what was synced and queued, but keeps the device id", () => {
    const s = parseDeviceState({
      version: 1,
      deviceId: "d1",
      base: { a: { ...entry, pushConfirmed: true } },
      pendingCreates: ["b"],
      pendingScopes: { b: "device:d1" },
    });
    expect(resetDeviceState(s)).toEqual({ version: 1, deviceId: "d1", base: {}, pendingCreates: [], pendingScopes: {} });
    // The state it came from is not changed.
    expect(s.pendingCreates).toEqual(["b"]);
  });
});
