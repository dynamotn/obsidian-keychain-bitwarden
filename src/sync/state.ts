// Per-device sync state. It lives in the vault's localStorage on this device,
// NOT in data.json: data.json is usually synced (Obsidian Sync, Git, iCloud),
// and a base state copied to another device would make that device believe its
// (still empty) secrets were deleted or edited.

import type { BaseEntry } from "./plan";

export interface DeviceState {
  version: 1;
  deviceId: string;
  folderId: string | null;
  base: Record<string, BaseEntry>;
  pendingCreates: string[];
  /** Scope chosen when the secret was queued for upload, e.g. "device:<id>". */
  pendingScopes: Record<string, string>;
}

export function newDeviceState(): DeviceState {
  return {
    version: 1,
    deviceId: crypto.randomUUID(),
    folderId: null,
    base: {},
    pendingCreates: [],
    pendingScopes: {},
  };
}

const isStr = (v: unknown): v is string => typeof v === "string";

/** Accepts only a well-formed state; anything else starts fresh but keeps the device id. */
export function parseDeviceState(raw: unknown): DeviceState {
  const fresh = newDeviceState();
  if (!raw || typeof raw !== "object") return fresh;
  const r = raw as Record<string, unknown>;
  if (isStr(r.deviceId) && r.deviceId.length > 0) fresh.deviceId = r.deviceId;
  if (r.version !== 1) return fresh;
  const base: Record<string, BaseEntry> = {};
  if (r.base && typeof r.base === "object") {
    for (const [id, e] of Object.entries(r.base as Record<string, unknown>)) {
      const entry = e as Record<string, unknown> | null;
      if (entry && isStr(entry.cipherId) && isStr(entry.revisionDate) && isStr(entry.fingerprint)) {
        const parsed: BaseEntry = { cipherId: entry.cipherId, revisionDate: entry.revisionDate, fingerprint: entry.fingerprint };
        if (isStr(entry.scope)) parsed.scope = entry.scope;
        base[id] = parsed;
      }
    }
  }
  const pendingScopes: Record<string, string> = {};
  if (r.pendingScopes && typeof r.pendingScopes === "object") {
    for (const [id, s] of Object.entries(r.pendingScopes as Record<string, unknown>)) if (isStr(s)) pendingScopes[id] = s;
  }
  return {
    version: 1,
    deviceId: fresh.deviceId,
    folderId: isStr(r.folderId) ? r.folderId : null,
    base,
    pendingCreates: Array.isArray(r.pendingCreates) ? r.pendingCreates.filter(isStr) : [],
    pendingScopes,
  };
}

/** Forgets what was synced, but keeps the device identity. */
export function resetDeviceState(state: DeviceState): DeviceState {
  return { ...newDeviceState(), deviceId: state.deviceId };
}
