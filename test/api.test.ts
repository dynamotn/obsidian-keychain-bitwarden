import { describe, expect, it } from "vitest";
import { BitwardenApiError, normalizeKeys, resolveServerUrls } from "../src/bw/api";
import { parseScope } from "../src/bw/vault";
import { parseDeviceState } from "../src/sync/state";

describe("resolveServerUrls", () => {
  it("maps the Bitwarden clouds and self-hosted servers", () => {
    expect(resolveServerUrls("")).toEqual({
      api: "https://api.bitwarden.com",
      identity: "https://identity.bitwarden.com",
      notifications: "https://notifications.bitwarden.com",
    });
    expect(resolveServerUrls("https://vault.bitwarden.eu")).toEqual({
      api: "https://api.bitwarden.eu",
      identity: "https://identity.bitwarden.eu",
      notifications: "https://notifications.bitwarden.eu",
    });
    expect(resolveServerUrls("https://bw.example.org/vault/")).toEqual({
      api: "https://bw.example.org/vault/api",
      identity: "https://bw.example.org/vault/identity",
      notifications: "https://bw.example.org/vault/notifications",
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

describe("normalizeKeys from an untrusted server", () => {
  it("never lets a __proto__ key replace an object's prototype", () => {
    const out = normalizeKeys(JSON.parse('{"__proto__":{"polluted":true},"Profile":{"__proto__":{"key":"x"}}}')) as Record<
      string,
      Record<string, unknown>
    >;
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(out.polluted).toBeUndefined();
    expect(Object.getPrototypeOf(out.profile)).toBe(Object.prototype);
    expect(out.profile!.key).toBeUndefined();
    expect(Object.keys(out)).toEqual(["profile"]);
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

  it("drops ids that break the id rule or are reserved for the plugin", () => {
    const entry = { cipherId: "c", revisionDate: "r", fingerprint: "f" };
    const bad = ["Upper", "a--b", "-a", "", "keychain-bitwarden-client-secret", "bitwarden-secrets-client-id", "__proto__"];
    const raw = {
      version: 1,
      deviceId: "d1",
      base: Object.fromEntries([["ok-1", entry], ...bad.map((id) => [id, entry])]),
      pendingCreates: ["ok-2", ...bad],
      pendingScopes: Object.fromEntries([["ok-2", "global"], ...bad.map((id) => [id, "global"])]),
    };
    // As read back from localStorage, where a key named __proto__ is an own property.
    const s = parseDeviceState(JSON.parse(JSON.stringify(raw)));
    expect(Object.keys(s.base)).toEqual(["ok-1"]);
    expect(s.pendingCreates).toEqual(["ok-2"]);
    expect(Object.keys(s.pendingScopes)).toEqual(["ok-2"]);
    expect(Object.getPrototypeOf(s.base)).toBe(Object.prototype);
  });

  it("keeps a confirmation to push to an organization item, and only a true one", () => {
    const entry = { cipherId: "c", revisionDate: "r", fingerprint: "f" };
    const s = parseDeviceState({
      version: 1,
      deviceId: "d1",
      base: { a: { ...entry, pushConfirmed: true }, b: { ...entry, pushConfirmed: "yes" }, c: entry },
      pendingCreates: [],
    });
    expect(s.base.a).toEqual({ ...entry, pushConfirmed: true });
    expect(s.base.b).toEqual(entry);
    expect(s.base.c).toEqual(entry);
  });
});
