// Plugin settings. They are kept in this device's vault localStorage, not in
// data.json: data.json is routinely synced or committed, and whoever can write
// it must not be able to choose the server the API key is sent to.

import type { ControllerSettings } from "./controller";
import type { ConflictPolicy } from "./sync/plan";

export interface PluginSettings extends ControllerSettings {
  syncIntervalMinutes: number;
  autoLockMinutes: number;
}

export const DEFAULT_SETTINGS: PluginSettings = {
  serverUrl: "https://vault.bitwarden.com",
  email: "",
  folderName: "obsidian",
  conflictPolicy: "ask",
  rememberKey: false,
  syncOrganizations: false,
  syncIntervalMinutes: 10,
  autoLockMinutes: 0,
};

const POLICIES: ConflictPolicy[] = ["ask", "prefer-remote", "prefer-local"];

/** Accepts only well-typed values; anything else falls back to the default. */
export function parseSettings(raw: unknown): PluginSettings {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const str = (k: keyof PluginSettings) => (typeof r[k] === "string" ? r[k] : (DEFAULT_SETTINGS[k] as string));
  const int = (k: keyof PluginSettings, max: number) => {
    const v = r[k];
    return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? v : (DEFAULT_SETTINGS[k] as number);
  };
  return {
    serverUrl: str("serverUrl"),
    email: str("email"),
    folderName: str("folderName").trim() || DEFAULT_SETTINGS.folderName,
    conflictPolicy: POLICIES.includes(r.conflictPolicy as ConflictPolicy)
      ? (r.conflictPolicy as ConflictPolicy)
      : DEFAULT_SETTINGS.conflictPolicy,
    rememberKey: typeof r.rememberKey === "boolean" ? r.rememberKey : false,
    syncOrganizations: typeof r.syncOrganizations === "boolean" ? r.syncOrganizations : false,
    syncIntervalMinutes: int("syncIntervalMinutes", 24 * 60),
    autoLockMinutes: int("autoLockMinutes", 24 * 60),
  };
}
