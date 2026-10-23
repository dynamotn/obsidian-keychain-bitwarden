import { describe, expect, it } from "vitest";
import { BitwardenApiError, normalizeKeys, resolveServerUrls } from "../src/bw/api";
import { parseScope } from "../src/bw/vault";
import { parseDeviceState } from "../src/sync/state";

describe("resolveServerUrls", () => {
  it("maps the Bitwarden clouds and self-hosted servers", () => {
    expect(resolveServerUrls("")).toEqual({ api: "https://api.bitwarden.com", identity: "https://identity.bitwarden.com" });
    expect(resolveServerUrls("https://vault.bitwarden.eu")).toEqual({
      api: "https://api.bitwarden.eu",
      identity: "https://identity.bitwarden.eu",
    });
    expect(resolveServerUrls("https://bw.example.org/vault/")).toEqual({
      api: "https://bw.example.org/vault/api",
      identity: "https://bw.example.org/vault/identity",
    });
    expect(resolveServerUrls("http://localhost:8080").api).toBe("http://localhost:8080/api");
  });

  it("refuses plain http to remote hosts and embedded credentials", () => {
    expect(() => resolveServerUrls("http://bw.example.org")).toThrow(/https/);
    expect(() => resolveServerUrls("https://u:p@bw.example.org")).toThrow(/credentials/);
    expect(() => resolveServerUrls("not a url")).toThrow(/Invalid/);
  });
});

describe("normalizeKeys", () => {
  it("lower-cases the first letter of every key, recursively", () => {
    expect(normalizeKeys({ Profile: { Key: "k" }, Ciphers: [{ RevisionDate: "d" }] })).toEqual({
      profile: { key: "k" },
      ciphers: [{ revisionDate: "d" }],
    });
  });
});

describe("BitwardenApiError", () => {
  it("recognises out-of-date edits", () => {
    expect(new BitwardenApiError(400, "HTTP 400: The cipher you are updating is out of date.").isOutOfDate).toBe(true);
    expect(new BitwardenApiError(500, "out of date").isOutOfDate).toBe(false);
  });
});

describe("parseScope", () => {
  it("parses known scopes and rejects others", () => {
    expect(parseScope(undefined)).toEqual({ kind: "global" });
    expect(parseScope(" global ")).toEqual({ kind: "global" });
    expect(parseScope("vault:Work Notes")).toEqual({ kind: "vault", name: "Work Notes" });
    expect(parseScope("device:abc")).toEqual({ kind: "device", id: "abc" });
    expect(parseScope("vault:")).toBeNull();
    expect(parseScope("galaxy:x")).toBeNull();
  });
});

describe("parseDeviceState", () => {
  it("keeps the device id but drops malformed content", () => {
    const s = parseDeviceState({ version: 1, deviceId: "d1", base: { a: { cipherId: 1 } }, pendingCreates: ["x", 3] });
    expect(s.deviceId).toBe("d1");
    expect(s.base).toEqual({});
    expect(s.pendingCreates).toEqual(["x"]);
    expect(parseDeviceState("garbage").deviceId).toMatch(/[0-9a-f-]{36}/);
  });
});
