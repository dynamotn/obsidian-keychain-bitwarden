import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS, parseSettings, type PluginSettings } from "../src/settings";

// Settings may come from a file that is synced or edited elsewhere: anything
// not of the expected type or range must fall back to its default.

const VALID: PluginSettings = {
  serverUrl: "https://bw.example",
  email: "user@example.com",
  uploadFolder: "secrets",
  conflictPolicy: "prefer-local",
  rememberKey: true,
  syncOrganizations: true,
  liveSync: false,
  syncIntervalMinutes: 30,
  autoLockMinutes: 15,
};

describe("parseSettings", () => {
  it.each([undefined, null, "settings", 42, true])("uses the defaults for %j", (raw) => {
    expect(parseSettings(raw)).toEqual(DEFAULT_SETTINGS);
  });

  it("uses the defaults for an empty object", () => {
    expect(parseSettings({})).toEqual(DEFAULT_SETTINGS);
  });

  it("keeps every valid value", () => {
    expect(parseSettings({ ...VALID })).toEqual(VALID);
  });

  it("does not hand out the default object itself", () => {
    const parsed = parseSettings({});
    parsed.serverUrl = "https://changed.example";
    expect(DEFAULT_SETTINGS.serverUrl).toBe("https://vault.bitwarden.com");
  });

  it("drops unknown keys", () => {
    expect(parseSettings({ ...VALID, extra: "x" })).toEqual(VALID);
  });

  it("trims the upload folder", () => {
    expect(parseSettings({ uploadFolder: "  secrets  " }).uploadFolder).toBe("secrets");
  });

  it("keeps every conflict policy", () => {
    for (const conflictPolicy of ["ask", "prefer-remote", "prefer-local"] as const) {
      expect(parseSettings({ conflictPolicy }).conflictPolicy).toBe(conflictPolicy);
    }
  });

  it("keeps both ends of the minute ranges", () => {
    const low = parseSettings({ syncIntervalMinutes: 0, autoLockMinutes: 0 });
    const high = parseSettings({ syncIntervalMinutes: 1440, autoLockMinutes: 1440 });
    expect([low.syncIntervalMinutes, low.autoLockMinutes]).toEqual([0, 0]);
    expect([high.syncIntervalMinutes, high.autoLockMinutes]).toEqual([1440, 1440]);
  });

  const malformed: [keyof PluginSettings, unknown[]][] = [
    ["serverUrl", [1, null, true, {}, ["https://evil.example"]]],
    ["email", [1, null, false, {}]],
    ["uploadFolder", [1, null, false, []]],
    ["conflictPolicy", ["prefer-remote ", "PREFER-LOCAL", "", 1, null, ["ask"]]],
    ["rememberKey", ["true", 1, null, {}]],
    ["syncOrganizations", ["true", 1, null, {}]],
    ["liveSync", ["false", 0, null, {}]],
    ["syncIntervalMinutes", ["10", 1.5, -1, 1441, NaN, Infinity, null, true]],
    ["autoLockMinutes", ["10", 0.5, -5, 1441, NaN, -Infinity, null, false]],
  ];

  it.each(malformed)("falls back to the default for a malformed %s", (key, values) => {
    for (const value of values) {
      const parsed = parseSettings({ ...VALID, [key]: value });
      expect(parsed[key], `${key}: ${String(value)}`).toBe(DEFAULT_SETTINGS[key]);
      // The other fields are unaffected.
      expect({ ...parsed, [key]: VALID[key] }).toEqual(VALID);
    }
  });

  it("never turns remembering the key or organization sync on by default", () => {
    expect(DEFAULT_SETTINGS.rememberKey).toBe(false);
    expect(DEFAULT_SETTINGS.syncOrganizations).toBe(false);
  });
});
