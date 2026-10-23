// Ties the API, the keys and the sync engine together. Has no dependency on
// the obsidian module, so it is exercised directly by the integration tests.

import { BitwardenApi, resolveServerUrls, type ApiCredentials } from "./bw/api";
import { KdfAbortedError, type Argon2Runner } from "./bw/argon2";
import { decryptBytes, SymmetricKey } from "./bw/crypto";
import { fromBase64, toBase64 } from "./bw/encoding";
import type { HttpClient } from "./bw/http";
import { formatScope, SECRET_ID_PATTERN, unlockUserKey, type Scope } from "./bw/vault";
import { isReservedId, RESERVED_PREFIX, runSync, SyncAbortedError, type SecretStore, type SyncReport } from "./sync/engine";
import type { ConflictOverride, ConflictPolicy } from "./sync/plan";
import { resetDeviceState, type DeviceState } from "./sync/state";

export const SECRET_CLIENT_ID = `${RESERVED_PREFIX}client-id`;
export const SECRET_CLIENT_SECRET = `${RESERVED_PREFIX}client-secret`;
/** Identity server the API key was entered for; the key is never sent anywhere else. */
export const SECRET_API_ORIGIN = `${RESERVED_PREFIX}api-origin`;
export const SECRET_USER_KEY = `${RESERVED_PREFIX}user-key`;

export interface ControllerSettings {
  serverUrl: string;
  email: string;
  folderName: string;
  conflictPolicy: ConflictPolicy;
  rememberKey: boolean;
  /** Also sync organization items in the folder. Off by default: see the security notes. */
  syncOrganizations: boolean;
}

export interface ControllerDeps {
  http: HttpClient;
  store: SecretStore;
  settings: () => ControllerSettings;
  loadState: () => DeviceState;
  saveState: (state: DeviceState) => void;
  vaultName: string;
  deviceName: string;
  /** Where Argon2id runs; the calling thread when omitted (tests). The plugin uses a worker. */
  argon2?: Argon2Runner;
}

export type Status = "locked" | "idle" | "syncing" | "error" | "conflict";

export class SecretsController {
  private userKey: SymmetricKey | null = null;
  private api: BitwardenApi | null = null;
  private apiFor = "";
  private running: Promise<SyncReport> | null = null;
  private queued: Promise<SyncReport> | null = null;
  private queuedOverrides: Map<string, ConflictOverride> | undefined;
  /** Bumped on every lock; a sync or unlock started under an older generation stops. */
  private generation = 0;
  /** Aborts the key derivation of the unlock in progress, if any. */
  private unlocking: AbortController | null = null;
  private cachedState: DeviceState | null = null;
  private listeners = new Set<(s: Status, detail?: string) => void>();
  status: Status = "locked";

  constructor(private readonly deps: ControllerDeps) {}

  onStatus(fn: (s: Status, detail?: string) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private setStatus(s: Status, detail?: string) {
    this.status = s;
    for (const fn of this.listeners) fn(s, detail);
  }

  get isUnlocked(): boolean {
    return this.userKey !== null;
  }

  /** One live copy of the device state, so concurrent edits cannot overwrite each other. */
  private state(): DeviceState {
    this.cachedState ??= this.deps.loadState();
    return this.cachedState;
  }

  private save() {
    this.deps.saveState(this.state());
  }

  private identityOrigin(): string {
    return new URL(resolveServerUrls(this.deps.settings().serverUrl).identity).origin;
  }

  /** Saves part of the API key and binds it to the currently configured server. */
  setApiKey(part: "clientId" | "clientSecret", value: string): void {
    this.deps.store.set(part === "clientId" ? SECRET_CLIENT_ID : SECRET_CLIENT_SECRET, value.trim());
    this.deps.store.set(SECRET_API_ORIGIN, this.identityOrigin());
  }

  private credentials(): ApiCredentials {
    const clientId = this.deps.store.get(SECRET_CLIENT_ID)?.trim();
    const clientSecret = this.deps.store.get(SECRET_CLIENT_SECRET)?.trim();
    if (!clientId || !clientSecret) throw new Error("Set the Bitwarden API key in the plugin settings first");
    const boundTo = this.deps.store.get(SECRET_API_ORIGIN);
    const origin = this.identityOrigin();
    if (boundTo !== origin) {
      throw new Error(
        `The API key was saved for ${boundTo || "another server"}, not ${origin}. ` +
          `Enter the API key again in the plugin settings to use it with this server.`,
      );
    }
    return { clientId, clientSecret };
  }

  private async session(): Promise<BitwardenApi> {
    const { serverUrl } = this.deps.settings();
    const { deviceId } = this.state();
    const fingerprint = `${serverUrl}\u0000${deviceId}`;
    if (!this.api || this.apiFor !== fingerprint) {
      this.api = new BitwardenApi(resolveServerUrls(serverUrl), this.deps.http, {
        identifier: deviceId,
        name: this.deps.deviceName,
      });
      this.apiFor = fingerprint;
    }
    if (!this.api.isLoggedIn) await this.api.loginWithApiKey(this.credentials());
    return this.api;
  }

  /** Unlocks with the master password. Throws KdfAbortedError when locked or cancelled meanwhile. */
  async unlock(password: string): Promise<void> {
    const { email, rememberKey } = this.deps.settings();
    if (!email.trim()) throw new Error("Set the account email in the plugin settings first");
    this.cancelUnlock();
    const generation = this.generation;
    const abort = new AbortController();
    this.unlocking = abort;
    try {
      const api = await this.session();
      const sync = await api.sync();
      if (abort.signal.aborted) throw new KdfAbortedError();
      const key = await unlockUserKey(api, email, password, sync.profile.key, {
        argon2: this.deps.argon2,
        signal: abort.signal,
      });
      // A lock that arrived while the key was being derived wins.
      if (abort.signal.aborted || generation !== this.generation) {
        key.wipe();
        throw new KdfAbortedError();
      }
      this.setKey(key, rememberKey);
    } finally {
      if (this.unlocking === abort) this.unlocking = null;
    }
  }

  /** Stops an unlock in progress (for example when its dialog is closed). */
  cancelUnlock(): void {
    this.unlocking?.abort();
    this.unlocking = null;
  }

  /** Unlocks from a key remembered on this device, if the user opted in. Returns false when there is none. */
  async unlockFromRememberedKey(): Promise<boolean> {
    const stored = this.deps.store.get(SECRET_USER_KEY);
    if (!stored || !this.deps.settings().rememberKey) return false;
    let key: SymmetricKey;
    try {
      key = await SymmetricKey.fromBytes(fromBase64(stored));
    } catch {
      this.forgetRememberedKey();
      return false;
    }
    // The remembered key goes stale when the account key is rotated. Without
    // something to check it against, ask for the password instead of risking
    // writes under a wrong key.
    const sync = await (await this.session()).sync();
    let valid = false;
    if (sync.profile.privateKey) {
      try {
        await decryptBytes(sync.profile.privateKey, key);
        valid = true;
      } catch {
        valid = false;
      }
    }
    if (!valid) {
      key.wipe();
      this.forgetRememberedKey();
      return false;
    }
    this.setKey(key, true);
    return true;
  }

  private setKey(key: SymmetricKey, remember: boolean) {
    this.userKey?.wipe();
    this.userKey = key;
    this.deps.store.set(SECRET_USER_KEY, remember ? toBase64(key.exportBytes()) : "");
    this.setStatus("idle");
  }

  lock(): void {
    this.generation++;
    this.cancelUnlock();
    this.userKey?.wipe();
    this.userKey = null;
    this.api?.logout();
    this.setStatus("locked");
  }

  forgetRememberedKey(): void {
    this.deps.store.set(SECRET_USER_KEY, "");
  }

  /**
   * Runs a sync. A call made while one is running is queued behind it rather
   * than joined, so work queued in the meantime (uploads, conflict choices) is
   * not silently dropped.
   */
  sync(overrides?: ReadonlyMap<string, ConflictOverride>): Promise<SyncReport> {
    if (!this.running) {
      this.running = this.doSync(overrides).finally(() => {
        this.running = null;
      });
      return this.running;
    }
    if (overrides) {
      this.queuedOverrides ??= new Map();
      for (const [k, v] of overrides) this.queuedOverrides.set(k, v);
    }
    this.queued ??= this.running
      .catch(() => undefined)
      .then(() => {
        const next = this.queuedOverrides;
        this.queued = null;
        this.queuedOverrides = undefined;
        return this.sync(next);
      });
    return this.queued;
  }

  private async doSync(overrides?: ReadonlyMap<string, ConflictOverride>): Promise<SyncReport> {
    const key = this.userKey;
    if (!key) throw new Error("Bitwarden is locked");
    const generation = this.generation;
    const isCancelled = () => generation !== this.generation;
    const settings = this.deps.settings();
    this.setStatus("syncing");
    try {
      const report = await runSync({
        api: await this.session(),
        userKey: key,
        store: this.deps.store,
        state: this.state(),
        saveState: () => this.save(),
        folderName: settings.folderName.trim() || "obsidian",
        vaultName: this.deps.vaultName,
        organizations: settings.syncOrganizations,
        policy: settings.conflictPolicy,
        overrides,
        isCancelled,
      });
      if (isCancelled()) throw new SyncAbortedError("Bitwarden was locked during the sync");
      if (report.errors.length) this.setStatus("error", report.errors.join("\n"));
      else if (report.conflicts.length) this.setStatus("conflict", `${report.conflicts.length} conflict(s)`);
      else this.setStatus("idle");
      return report;
    } catch (e) {
      // Locking wipes the key under a running sync; whatever failed next is a
      // consequence of the lock, not an error to show.
      if (isCancelled()) throw new SyncAbortedError("Bitwarden was locked during the sync");
      this.setStatus("error", (e as Error).message);
      throw e;
    }
  }

  /** Secrets on this device that are not synced yet and could be uploaded. */
  uploadCandidates(): string[] {
    const state = this.state();
    return this.deps.store
      .list()
      .filter((id) => !isReservedId(id) && !state.base[id] && !state.pendingCreates.includes(id))
      .sort();
  }

  /** Queues a local secret for upload on the next sync. */
  queueUpload(id: string, scope: Scope): void {
    if (!SECRET_ID_PATTERN.test(id) || isReservedId(id)) throw new Error(`Cannot upload "${id}"`);
    if (this.deps.store.get(id) === null) throw new Error(`No local secret named "${id}"`);
    const state = this.state();
    if (!state.pendingCreates.includes(id)) state.pendingCreates.push(id);
    if (scope.kind === "device") scope = { kind: "device", id: state.deviceId };
    state.pendingScopes[id] = formatScope(scope);
    this.save();
  }

  resetState(): void {
    if (this.running) throw new Error("A sync is running; try again when it has finished");
    this.cachedState = resetDeviceState(this.state());
    this.save();
  }

  /** The notifications hub URL with a fresh token; fails while locked. */
  async notificationsHubUrl(): Promise<string> {
    if (!this.userKey) throw new Error("Bitwarden is locked");
    return (await this.session()).notificationsHubUrl();
  }

  deviceId(): string {
    return this.state().deviceId;
  }
}
