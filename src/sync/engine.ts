// Runs one sync: fetch, decrypt the folder, plan, apply, persist.

import type { BitwardenApi, SyncDto } from "../bw/api";
import { BitwardenApiError } from "../bw/api";
import { encryptString, ValueFingerprinter, type SymmetricKey } from "../bw/crypto";
import {
  findFolderIds,
  formatScope,
  newSecretRequest,
  parseScope,
  readFolder,
  scopeApplies,
  updateValueRequest,
  type SecretRecord,
  type SkippedItem,
} from "../bw/vault";
import {
  planSync,
  type Action,
  type BaseEntry,
  type ConflictKind,
  type ConflictOverride,
  type ConflictPolicy,
  type RemoteEntry,
} from "./plan";
import type { DeviceState } from "./state";

/** Secrets the plugin keeps for itself; they never leave the device. */
export const RESERVED_PREFIX = "keychain-bitwarden-";

/**
 * Prefix used before the plugin was renamed. Secret storage cannot delete, so
 * old credentials stay on the device and must stay out of sync and uploads.
 */
const LEGACY_RESERVED_PREFIX = "bitwarden-secrets-";

export function isReservedId(id: string): boolean {
  return id.startsWith(RESERVED_PREFIX) || id.startsWith(LEGACY_RESERVED_PREFIX);
}

export interface SecretStore {
  get(id: string): string | null;
  set(id: string, value: string): void;
  list(): string[];
}

export interface SyncContext {
  api: BitwardenApi;
  userKey: SymmetricKey;
  store: SecretStore;
  /** The live device state; mutated in place and persisted through saveState. */
  state: DeviceState;
  saveState: (state: DeviceState) => void;
  folderName: string;
  vaultName: string;
  policy: ConflictPolicy;
  overrides?: ReadonlyMap<string, ConflictOverride>;
  /** Checked between steps; true once the vault was locked or the plugin unloaded. */
  isCancelled?: () => boolean;
}

export interface ConflictInfo {
  id: string;
  kind: ConflictKind;
  label: string;
}

export interface SyncReport {
  pulled: string[];
  pushed: string[];
  created: string[];
  cleared: string[];
  conflicts: ConflictInfo[];
  skipped: SkippedItem[];
  errors: string[];
  passes: number;
}

export class SyncAbortedError extends Error {
  override name = "SyncAbortedError";
}

const MAX_PASSES = 3;

export async function runSync(ctx: SyncContext): Promise<SyncReport> {
  const report: SyncReport = {
    pulled: [],
    pushed: [],
    created: [],
    cleared: [],
    conflicts: [],
    skipped: [],
    errors: [],
    passes: 0,
  };
  const fp = await ValueFingerprinter.forUserKey(ctx.userKey);
  for (let pass = 1; pass <= MAX_PASSES; pass++) {
    report.passes = pass;
    report.conflicts = [];
    report.skipped = [];
    const again = await runPass(ctx, fp, report);
    if (!again) return report;
  }
  report.errors.push("Secrets kept changing during the sync; try again later.");
  return report;
}

function checkCancelled(ctx: SyncContext) {
  if (ctx.isCancelled?.()) throw new SyncAbortedError("Bitwarden was locked during the sync");
}

async function resolveFolder(ctx: SyncContext, sync: SyncDto): Promise<string | null> {
  const { state } = ctx;
  const ids = await findFolderIds(sync, ctx.userKey, ctx.folderName);
  const hasBase = Object.keys(state.base).length > 0;
  if (state.folderId && ids.includes(state.folderId)) return state.folderId;
  if (ids.length > 0 && hasBase && state.folderId) {
    throw new SyncAbortedError(
      `Bitwarden folder "${ctx.folderName}" is a different folder than the one synced before. ` +
        `Reset the sync state in the plugin settings if this is intended.`,
    );
  }
  // Duplicate names are allowed by Bitwarden; pick one deterministically so
  // every device converges on the same folder.
  if (ids.length > 0) return [...ids].sort()[0]!;
  if (hasBase) {
    // Losing the folder (renamed, deleted, wrong account) must not wipe this device.
    throw new SyncAbortedError(
      `Bitwarden folder "${ctx.folderName}" was not found, but secrets were synced from it before. ` +
        `Restore the folder, or reset the sync state in the plugin settings.`,
    );
  }
  return null;
}

/** Returns true when another pass is needed (an edit raced with this one). */
async function runPass(ctx: SyncContext, fp: ValueFingerprinter, report: SyncReport): Promise<boolean> {
  const { api, userKey, store, state } = ctx;
  const sync = await api.sync();
  checkCancelled(ctx);

  let folderId = await resolveFolder(ctx, sync);
  if (!folderId) {
    if (state.pendingCreates.length === 0) return false;
    folderId = (await api.createFolder(await encryptString(ctx.folderName, userKey))).id;
  }
  state.folderId = folderId;

  const { records, skipped, present } = await readFolder(sync, userKey, folderId);
  report.skipped.push(...skipped);

  const byId = new Map<string, SecretRecord>();
  for (const rec of records) {
    if (isReservedId(rec.id)) {
      report.skipped.push({ cipherId: rec.cipherId, reason: `id "${rec.id}" is reserved for the plugin` });
      continue;
    }
    if (!scopeApplies(rec.scope, ctx.vaultName, state.deviceId)) continue;
    const other = byId.get(rec.id);
    if (other) {
      const [keep, drop] = other.revisionDate >= rec.revisionDate ? [other, rec] : [rec, other];
      byId.set(rec.id, keep);
      report.skipped.push({ cipherId: drop.cipherId, reason: `duplicate of "${rec.id}"; the newest item is used` });
      continue;
    }
    byId.set(rec.id, rec);
  }

  // A synced secret whose item is still in the folder but cannot be used here
  // any more (newer format, renamed to an invalid id, moved to an organization,
  // re-scoped) is left alone rather than treated as deleted.
  const base = new Map<string, BaseEntry>();
  for (const [id, entry] of Object.entries(state.base)) {
    if (!byId.has(id) && present.has(entry.cipherId)) {
      report.skipped.push({ cipherId: entry.cipherId, reason: `"${id}" is kept as is: its item can no longer be used` });
      continue;
    }
    base.set(id, entry);
  }

  const remote = new Map<string, RemoteEntry>();
  for (const rec of byId.values()) {
    remote.set(rec.id, {
      id: rec.id,
      cipherId: rec.cipherId,
      revisionDate: rec.revisionDate,
      fingerprint: await fp.of(rec.id, rec.value),
    });
  }

  const localValues = new Map<string, string | null>();
  const localFingerprints = new Map<string, string | null>();
  for (const id of new Set([...remote.keys(), ...base.keys(), ...state.pendingCreates])) {
    const v = store.get(id);
    localValues.set(id, v);
    localFingerprints.set(id, v === null ? null : await fp.of(id, v));
  }

  const actions = planSync({
    remote,
    base,
    local: (id) => ({ fingerprint: localFingerprints.get(id) ?? null }),
    pendingCreates: new Set(state.pendingCreates),
    policy: ctx.policy,
    overrides: ctx.overrides,
  });

  // Clearing many secrets at once is almost always a mistake (wrong folder or
  // account, a half-finished migration, a hostile server) rather than intent.
  const clears = actions.filter((a) => a.kind === "clear-local").length;
  if (clears > 1 && clears * 2 > base.size) {
    throw new SyncAbortedError(
      `${clears} of ${base.size} synced secrets would be cleared because they disappeared from "${ctx.folderName}"; ` +
        `refusing. Restore them in Bitwarden, or reset the sync state if this is intended.`,
    );
  }

  const pass: PassData = { byId, remote, base, localValues, localFingerprints, folderId, fp };
  let again = false;
  for (const action of actions) {
    checkCancelled(ctx);
    try {
      again = (await apply(action, ctx, pass, report)) || again;
    } catch (e) {
      report.errors.push(`${action.id}: ${(e as Error).message}`);
    }
    ctx.saveState(state);
  }
  return again;
}

interface PassData {
  byId: Map<string, SecretRecord>;
  remote: Map<string, RemoteEntry>;
  base: Map<string, BaseEntry>;
  localValues: Map<string, string | null>;
  localFingerprints: Map<string, string | null>;
  folderId: string;
  fp: ValueFingerprinter;
}

/** True when the local value changed since this pass read it. */
async function localMoved(ctx: SyncContext, pass: PassData, id: string): Promise<boolean> {
  const now = ctx.store.get(id);
  const fingerprint = now === null ? null : await pass.fp.of(id, now);
  return fingerprint !== (pass.localFingerprints.get(id) ?? null);
}

async function apply(action: Action, ctx: SyncContext, pass: PassData, report: SyncReport): Promise<boolean> {
  const { api, userKey, store, state } = ctx;
  const id = action.id;
  const rec = pass.byId.get(id);
  const local = pass.localValues.get(id) ?? null;
  const localFingerprint = pass.localFingerprints.get(id) ?? null;
  const remoteBase = (): BaseEntry => {
    const r = pass.remote.get(id)!;
    return { cipherId: r.cipherId, revisionDate: r.revisionDate, fingerprint: r.fingerprint, scope: formatScope(rec!.scope) };
  };
  const dropPending = () => {
    state.pendingCreates = state.pendingCreates.filter((p) => p !== id);
    delete state.pendingScopes[id];
  };

  switch (action.kind) {
    case "pull": {
      if (!rec) return false;
      // Never overwrite an edit made while earlier network calls were in flight.
      if (await localMoved(ctx, pass, id)) return true;
      store.set(id, rec.value);
      state.base[id] = remoteBase();
      dropPending();
      report.pulled.push(id);
      return false;
    }
    case "adopt": {
      state.base[id] = remoteBase();
      dropPending();
      return false;
    }
    case "push": {
      if (!rec || local === null || localFingerprint === null) return false;
      try {
        const res = await api.updateItem(rec.cipherId, await updateValueRequest(rec, userKey, local));
        state.base[id] = {
          cipherId: res.id,
          revisionDate: res.revisionDate,
          fingerprint: localFingerprint,
          scope: formatScope(rec.scope),
        };
      } catch (e) {
        if (e instanceof BitwardenApiError && e.isOutOfDate) return true;
        throw e;
      }
      dropPending();
      report.pushed.push(id);
      return false;
    }
    case "create": {
      if (local === null || localFingerprint === null) return false;
      // Re-uploading after a remote deletion keeps the scope the item had.
      const scope = parseScope(state.pendingScopes[id] ?? pass.base.get(id)?.scope) ?? { kind: "global" as const };
      const res = await api.createItem(await newSecretRequest(userKey, pass.folderId, id, local, scope));
      state.base[id] = {
        cipherId: res.id,
        revisionDate: res.revisionDate,
        fingerprint: localFingerprint,
        scope: formatScope(scope),
      };
      dropPending();
      report.created.push(id);
      return false;
    }
    case "clear-local": {
      if (await localMoved(ctx, pass, id)) return true;
      // SecretStorage cannot delete; an empty value is the closest equivalent.
      store.set(id, "");
      delete state.base[id];
      report.cleared.push(id);
      return false;
    }
    case "forget": {
      delete state.base[id];
      dropPending();
      return false;
    }
    case "conflict": {
      report.conflicts.push({ id, kind: action.conflict, label: rec?.label ?? id });
      return false;
    }
  }
}
