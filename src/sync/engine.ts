// Runs one sync: fetch, decrypt the marked items, plan, apply, persist.

import type { BitwardenApi, SyncDto } from "../bw/api";
import { BitwardenApiError } from "../bw/api";
import { encryptString, ValueFingerprinter, type SymmetricKey } from "../bw/crypto";
import {
  findFolderIds,
  formatScope,
  newSecretRequest,
  ownerKeyFor,
  parseScope,
  readVault,
  scopeApplies,
  unlockOrganizationKeys,
  updateValueRequest,
  type OrganizationKeys,
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
  /** Folder new uploads are filed in, created if missing; "" files them in no folder. */
  uploadFolder: string;
  vaultName: string;
  /** Also sync organization items (opt-in: see the security notes). */
  organizations?: boolean;
  policy: ConflictPolicy;
  overrides?: ReadonlyMap<string, ConflictOverride>;
  /** Checked between steps; true once the vault was locked or the plugin unloaded. */
  isCancelled?: () => boolean;
}

export interface ConflictInfo {
  id: string;
  kind: ConflictKind;
  label: string;
  /** The organization the item belongs to, by name when the server sends one. */
  organization?: string;
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
  const orgKeys: OrgKeyHolder = { keys: null };
  try {
    for (let pass = 1; pass <= MAX_PASSES; pass++) {
      report.passes = pass;
      report.conflicts = [];
      report.skipped = [];
      const again = await runPass(ctx, fp, report, orgKeys);
      if (!again) return report;
    }
    report.errors.push("Secrets kept changing during the sync; try again later.");
    return report;
  } finally {
    wipeKeys(orgKeys);
  }
}

/** Organization keys of the current pass; wiped when replaced and when the run ends. */
interface OrgKeyHolder {
  keys: Map<string, SymmetricKey> | null;
}

function wipeKeys(holder: OrgKeyHolder) {
  for (const key of holder.keys?.values() ?? []) key.wipe();
  holder.keys = null;
}

async function loadOrganizationKeys(
  ctx: SyncContext,
  sync: SyncDto,
  holder: OrgKeyHolder,
  report: SyncReport,
): Promise<OrganizationKeys | null> {
  if (!ctx.organizations) return null;
  wipeKeys(holder);
  const { keys, problems } = await unlockOrganizationKeys(sync, ctx.userKey);
  holder.keys = keys;
  for (const p of problems) if (!report.errors.includes(p)) report.errors.push(p);
  return keys;
}

/**
 * Of two items claiming the same id, personal items win over organization
 * items, then the oldest, then the lowest cipher id. Creation dates never
 * change, so every device keeps choosing the same item however it is edited.
 */
function preferred(a: SecretRecord, b: SecretRecord): [keep: SecretRecord, drop: SecretRecord] {
  if (!a.organizationId !== !b.organizationId) return a.organizationId ? [b, a] : [a, b];
  // An item without a creation date (older servers) sorts last.
  const created = (r: SecretRecord) => r.cipher.creationDate || "\uffff";
  if (created(a) !== created(b)) return created(a) < created(b) ? [a, b] : [b, a];
  return a.cipherId <= b.cipherId ? [a, b] : [b, a];
}

function checkCancelled(ctx: SyncContext) {
  if (ctx.isCancelled?.()) throw new SyncAbortedError("Bitwarden was locked during the sync");
}

/** The folder for new uploads: the existing one with the lowest id, so devices agree, or a new one. */
async function uploadFolderId(ctx: SyncContext, sync: SyncDto): Promise<string | null> {
  const name = ctx.uploadFolder.trim();
  if (!name) return null;
  const ids = await findFolderIds(sync, ctx.userKey, name);
  if (ids.length > 0) return [...ids].sort()[0]!;
  return (await ctx.api.createFolder(await encryptString(name, ctx.userKey))).id;
}

/** Returns true when another pass is needed (an edit raced with this one). */
async function runPass(
  ctx: SyncContext,
  fp: ValueFingerprinter,
  report: SyncReport,
  orgKeyHolder: OrgKeyHolder,
): Promise<boolean> {
  const { api, userKey, store, state } = ctx;
  const sync = await api.sync();
  checkCancelled(ctx);
  const orgKeys = await loadOrganizationKeys(ctx, sync, orgKeyHolder, report);

  const { records, skipped, present } = await readVault(sync, userKey, orgKeys);
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
      // An organization item never takes over a personal secret: anyone who
      // holds the organization key (or a hostile server) could create one.
      const [keep, drop] = preferred(other, rec);
      byId.set(rec.id, keep);
      report.skipped.push({
        cipherId: drop.cipherId,
        reason:
          drop.organizationId && !keep.organizationId
            ? `duplicate of "${rec.id}"; the personal item is used`
            : `duplicate of "${rec.id}"; the oldest item is used`,
      });
      continue;
    }
    byId.set(rec.id, rec);
  }

  // A synced secret whose item is still marked but cannot be used here any
  // more (newer format, renamed to an invalid id, moved to an organization,
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
      organization: rec.organizationId !== null,
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

  // Clearing many secrets at once is almost always a mistake (wrong
  // account, a half-finished migration, a hostile server) rather than intent.
  const clears = actions.filter((a) => a.kind === "clear-local").length;
  if (clears > 1 && clears * 2 >= base.size) {
    throw new SyncAbortedError(
      `${clears} of ${base.size} synced secrets would be cleared because they disappeared from Bitwarden; ` +
        `refusing. Restore them in Bitwarden, or reset the sync state if this is intended.`,
    );
  }

  const pass: PassData = { sync, byId, remote, base, localValues, localFingerprints, fp, orgKeys };
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
  sync: SyncDto;
  /** Resolved on the first upload of the pass. */
  uploadFolderId?: string | null;
  byId: Map<string, SecretRecord>;
  remote: Map<string, RemoteEntry>;
  base: Map<string, BaseEntry>;
  localValues: Map<string, string | null>;
  localFingerprints: Map<string, string | null>;
  fp: ValueFingerprinter;
  orgKeys: OrganizationKeys | null;
}

const readOnlyReason = (id: string) =>
  `"${id}" changed on this device, but its organization does not let you edit it; not uploaded`;

const ORGANIZATION_NAME_MAX = 64;

/**
 * The organization's name for the conflict dialog. Its owners chose it, and
 * they are who the dialog warns about: control characters and line breaks
 * become spaces, invisible and text-reordering characters go, and a long
 * name is cut, so it cannot pass for part of the warning.
 */
function organizationName(sync: SyncDto, organizationId: string): string {
  const raw = sync.profile.organizations?.find((o) => o.id === organizationId)?.name ?? "";
  const name = raw
    .replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ")
    .replace(/\p{Cf}/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!name) return organizationId;
  const chars = [...name];
  return chars.length > ORGANIZATION_NAME_MAX ? `${chars.slice(0, ORGANIZATION_NAME_MAX - 1).join("")}…` : name;
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
    const entry: BaseEntry = { cipherId: r.cipherId, revisionDate: r.revisionDate, fingerprint: r.fingerprint, scope: formatScope(rec!.scope) };
    // A confirmation to push belongs to the one item it was given for.
    const previous = state.base[id];
    if (previous?.pushConfirmed && previous.cipherId === r.cipherId) entry.pushConfirmed = true;
    return entry;
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
      // Only an organization item this secret was already synced with is ever
      // written to; anything else would hand a personal value to its members.
      if (rec.organizationId && state.base[id]?.cipherId !== rec.cipherId) {
        throw new Error("refusing to upload to an organization item this secret was not synced with");
      }
      // Being bound is not enough: a pull binds without asking, so the user must have agreed to send values there.
      const confirmed = Boolean(rec.organizationId) && (action.confirmed === true || state.base[id]?.pushConfirmed === true);
      if (rec.organizationId && !confirmed) {
        throw new Error("refusing to upload to an organization item without your confirmation");
      }
      if (rec.readOnly) {
        report.skipped.push({ cipherId: rec.cipherId, reason: readOnlyReason(id) });
        return false;
      }
      const ownerKey = ownerKeyFor(rec.cipher, userKey, pass.orgKeys);
      // readVault read the item with this key, so it is here; refuse plainly if that ever changes.
      if (!ownerKey) throw new Error("the key of its organization is not available");
      try {
        const res = await api.updateItem(rec.cipherId, await updateValueRequest(rec, ownerKey, local));
        state.base[id] = {
          cipherId: res.id,
          revisionDate: res.revisionDate,
          fingerprint: localFingerprint,
          scope: formatScope(rec.scope),
          ...(confirmed ? { pushConfirmed: true } : {}),
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
      if (pass.uploadFolderId === undefined) pass.uploadFolderId = await uploadFolderId(ctx, pass.sync);
      const res = await api.createItem(await newSecretRequest(userKey, pass.uploadFolderId, id, local, scope));
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
      if (action.conflict === "organization-push" && rec?.readOnly) {
        report.skipped.push({ cipherId: rec.cipherId, reason: readOnlyReason(id) });
        return false;
      }
      const organization = rec?.organizationId ? organizationName(pass.sync, rec.organizationId) : undefined;
      report.conflicts.push({ id, kind: action.conflict, label: rec?.label ?? id, ...(organization ? { organization } : {}) });
      return false;
    }
  }
}
