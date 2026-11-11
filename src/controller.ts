// Runs the plugin on one dybw-core WasmSession: the core logs in, unlocks and syncs; this keeps what is
// Obsidian-facing (status, the sync queue, the API-key binding, the remembered key, the hub's start and stop). Has no
// dependency on the obsidian module, so it is exercised directly by the tests.

import { WasmSession } from "../vendor/dybw-core/dybw_core_wasm.js";
import { KdfAbortedError } from "./bw/argon2";
import { InvalidError, LockedError, parseCoreError, WrongPasswordError, type Kdf } from "./core/errors";
import { coreLoader } from "./core/load";
import { hostPorts, LocalChangedError, type PortDeps } from "./core/ports";

/** Secrets the plugin keeps for itself; they never leave the device. */
export const RESERVED_PREFIX = "keychain-bitwarden-";
/** Prefix used before the plugin was renamed: old credentials stay on the device (secret storage cannot delete). */
const LEGACY_RESERVED_PREFIX = "bitwarden-secrets-";

export const SECRET_CLIENT_ID = `${RESERVED_PREFIX}client-id`;
export const SECRET_CLIENT_SECRET = `${RESERVED_PREFIX}client-secret`;
/** Identity server the API key was entered for; the key is never sent anywhere else. */
export const SECRET_API_ORIGIN = `${RESERVED_PREFIX}api-origin`;
export const SECRET_USER_KEY = `${RESERVED_PREFIX}user-key`;

// What the plugin tells the server it is; release.yml checks CLIENT_VERSION against the manifest.
const DEVICE_TYPE = 21; // DeviceType.SDK in the Bitwarden server enum.
const CLIENT_NAME = "obsidian-keychain-bitwarden";
const CLIENT_VERSION = "0.1.0";

/** Shown, and every later call refused with it, once the core trapped (a panic): only a reload recovers. */
export const TRAP_MESSAGE = "Bitwarden plugin stopped after an internal error; reload it";

const SECRET_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ORGANIZATION_NAME_MAX = 64;

export function isReservedId(id: string): boolean {
  return id.startsWith(RESERVED_PREFIX) || id.startsWith(LEGACY_RESERVED_PREFIX);
}

export interface SecretStore {
  get(id: string): string | null;
  set(id: string, value: string): void;
  list(): string[];
}

export type ConflictPolicy = "ask" | "prefer-remote" | "prefer-local";
export type ConflictKind = "both-changed" | "local-unsynced" | "deleted-remotely" | "organization-claim" | "organization-push";
export interface ConflictOverride {
  policy: Exclude<ConflictPolicy, "ask">;
  /** The conflict the choice was made for; it no longer applies once the conflict changed kind. */
  kind: ConflictKind;
}
/** ADR 0016: the question asked before a write-back that touches the item's history. */
export type HistoryQuestion = "first-write-back" | "evicts-foreign-history";
export interface HistoryAnswer {
  /** The question the answer was given for; it no longer applies to another one. */
  question: HistoryQuestion;
  answer: "write-to-login" | "keep-separate";
}
/** Where an upload is available; "device" is always this device. */
export type Scope = { kind: "global" } | { kind: "vault"; name: string } | { kind: "device" };

export interface ConflictInfo {
  id: string;
  kind: ConflictKind;
  /** The item's name, or the id when it has none. */
  label: string;
  /** The organization the item belongs to, by its sanitized name, else its id. */
  organization?: string;
}

type CipherPair = { id: string; cipherId: string };

/** The core's sync report (dybw-core README, `runSync`), with conflicts as the dialog shows them. */
export interface SyncReport {
  pulled: string[];
  pushed: string[];
  created: string[];
  cleared: string[];
  conflicts: ConflictInfo[];
  errors: { id: string; error: string }[];
  passes: number;
  keptChanging: boolean;
  questions: { id: string; label: string; question: HistoryQuestion }[];
  /** `revisionDate` is the server's, as text: accepting passes it back, so a newer rollback is shown again. */
  rollbacks: (CipherPair & { revisionDate: string })[];
  held: CipherPair[];
  readOnly: CipherPair[];
  unknownFeatures: { cipherId: string; features: string[] }[];
  unreadable: string[];
  duplicates: { id: string; kept: string; left: string[]; boundKept: boolean }[];
  skipped: { cipherId: string; reason: string }[];
  /** Values the user changed during the sync: kept over what the sync would write, resolved by the next sync. */
  kept: { id: string; reason: "local-changed" }[];
  /** The core's sentences for the notice, counts only. */
  warnings: string[];
}

/** What an unlock answers (dybw-core README). */
export interface UnlockSummary {
  userKeyId: string;
  securityVersion: number;
  orgProblems: { organization: string; reason: string }[];
  warnings: string[];
}

export interface ControllerSettings {
  serverUrl: string;
  email: string;
  /** Folder new uploads are filed in; "" for none. */
  uploadFolder: string;
  conflictPolicy: ConflictPolicy;
  rememberKey: boolean;
  /** Also sync organization items. Off by default: see the security notes. */
  syncOrganizations: boolean;
}

export interface ControllerDeps {
  /** The host the core runs on; the secret storage and the abort signals are the controller's. */
  ports: Omit<PortDeps, "secretStorage" | "kdfSignal" | "hubSignal">;
  store: SecretStore;
  settings: () => ControllerSettings;
  vaultName: string;
  deviceName: string;
  /** Told once, with TRAP_MESSAGE, when the core trapped. */
  onTrap?: (message: string) => void;
}

export type Status = "locked" | "idle" | "syncing" | "error" | "conflict";

type RawConflict = Omit<ConflictInfo, "organization"> & { organization: string | null; organizationName: string | null };

/**
 * The organization's name for the conflict dialog. Its owners chose it, and they are who the dialog warns about:
 * control characters and line breaks become spaces, invisible and text-reordering characters go, and a long name is
 * cut, so it cannot pass for part of the warning.
 */
function organizationName(raw: string | null, id: string): string {
  const name = (raw ?? "")
    .replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ")
    .replace(/\p{Cf}/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!name) return id;
  const chars = [...name];
  return chars.length > ORGANIZATION_NAME_MAX ? `${chars.slice(0, ORGANIZATION_NAME_MAX - 1).join("")}…` : name;
}

const CLOUD = ["com", "eu"];

/** The identity origin the server URL logs in at, as the core resolves it (Bitwarden cloud has its own). */
function identityOrigin(serverUrl: string): string {
  const raw = serverUrl.trim() || "https://vault.bitwarden.com";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid server URL: ${raw}`);
  }
  for (const cloud of CLOUD) {
    if (url.hostname === `vault.bitwarden.${cloud}` || url.hostname === `bitwarden.${cloud}`) {
      return `https://identity.bitwarden.${cloud}`;
    }
  }
  return url.origin;
}

/** ADR 0018: a server whose identity origin is not Bitwarden cloud's must be acknowledged on the device. */
export function isSelfHosted(serverUrl: string): boolean {
  try {
    return !CLOUD.some((cloud) => identityOrigin(serverUrl) === `https://identity.bitwarden.${cloud}`);
  } catch {
    return false;
  }
}

/** Whether a sync the user did not ask for is worth a notice: it changed something, or the core has something to say. */
export function needsNotice(report: SyncReport): boolean {
  const changed = report.pulled.length + report.pushed.length + report.created.length + report.cleared.length;
  return changed + report.conflicts.length + report.errors.length + report.kept.length + report.warnings.length > 0;
}

/** The sync notice: what changed, then the core's own sentences (held, unknown features, rollbacks, …), counts only. */
export function summarize(report: SyncReport): string {
  const parts: string[] = [];
  if (report.pulled.length) parts.push(`${report.pulled.length} updated`);
  if (report.pushed.length) parts.push(`${report.pushed.length} uploaded`);
  if (report.created.length) parts.push(`${report.created.length} added to Bitwarden`);
  if (report.cleared.length) parts.push(`${report.cleared.length} cleared`);
  if (report.conflicts.length) parts.push(`${report.conflicts.length} conflict(s)`);
  if (report.skipped.length) parts.push(`${report.skipped.length} item(s) skipped`);
  if (report.errors.length) parts.push(`${report.errors.length} error(s)`);
  parts.push(...report.warnings);
  return parts.length ? parts.join(", ") : "everything is up to date";
}

const scopeText = (scope: Scope) => (scope.kind === "vault" ? `vault:${scope.name}` : scope.kind);

export class SecretsController {
  private readonly loadCore = coreLoader();
  private session: WasmSession | null = null;
  private unlocked = false;
  private trapped = false;
  private running: Promise<SyncReport> | null = null;
  private queued: Promise<SyncReport> | null = null;
  private queuedOverrides: Map<string, ConflictOverride> | undefined;
  private queuedAnswers: Map<string, HistoryAnswer> | undefined;
  private queuedRollbacks: Map<string, string> | undefined;
  /** Calls that take the core's keys out run one after another: the core answers `busy` otherwise. */
  private tail: Promise<unknown> = Promise.resolve();
  /** Bumped on every lock; an unlock or sync started under an older generation stops. */
  private generation = 0;
  /** Bumped when an unlock finds the core unlocked and locks it first, which is a lock too, but one `generation` must not see. */
  private relocks = 0;
  /** Aborts the key derivation of the unlock in progress, if any (the Argon2 port reads it). */
  private unlocking: AbortController | null = null;
  /** Stops the running hub and ends its sleeps at once (the clock port reads it). */
  private hub: AbortController | null = null;
  /** What the running hub calls on a change, for `wake` to start it again with. */
  private hubOnChange: (() => void) | null = null;
  /** The local values the running sync was given, then what it wrote; a value typed since is never written over. */
  private snapshot: Map<string, string> | null = null;
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

  /** Changes on every lock (and unload): a question asked before is no longer wanted. */
  get lockGeneration(): number {
    return this.generation;
  }

  /** Changes on every lock and every re-unlock: an answer or a sync outcome from before is stale. */
  get answerEpoch(): number {
    return this.generation + this.relocks;
  }

  get isUnlocked(): boolean {
    return this.unlocked;
  }

  /** The session, made on first use once the core is loaded; a load that failed is tried again next time. */
  private async core(): Promise<WasmSession> {
    if (this.trapped) throw new Error(TRAP_MESSAGE);
    await this.loadCore();
    const store = this.deps.store;
    this.session ??= new WasmSession(
      hostPorts({
        ...this.deps.ports,
        secretStorage: {
          getSecret: store.get.bind(store),
          setSecret: (id, value) => {
            // A value typed during the sync wins: the core keeps its base entry and reports it in `kept`, so the next
            // sync sees the edit.
            if (this.snapshot && store.get(id) !== (this.snapshot.get(id) ?? null)) throw new LocalChangedError();
            store.set(id, value);
            this.snapshot?.set(id, value);
          },
        },
        kdfSignal: () => this.unlocking?.signal,
        hubSignal: () => this.hub?.signal,
      }),
      "obsidian",
    );
    return this.session;
  }

  /** One core call: its rejection becomes a typed error, and a trap stops the plugin. */
  private async call<T>(fn: (session: WasmSession) => T | Promise<T>): Promise<T> {
    const session = await this.core();
    try {
      return await fn(session);
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) {
        this.trap();
        throw new Error(TRAP_MESSAGE);
      }
      throw parseCoreError(e);
    }
  }

  /** `fn` once every earlier key-taking call ended. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    if (this.trapped) return Promise.reject(new Error(TRAP_MESSAGE));
    const run = this.tail.then(fn);
    this.tail = run.catch(() => undefined);
    return run;
  }

  /**
   * After a trap the instance still holds its memory, keys included: lock wipes them. Every later call is refused,
   * since only reloading the plugin loads a fresh module. The plugin also calls this for a trap it caught elsewhere.
   */
  trap(): void {
    if (this.trapped) return;
    this.trapped = true;
    try {
      this.session?.lock();
    } catch {
      // A trapped instance may trap again; nothing more can be done here.
    }
    // Never called into again (lock, cancel, unload), and work waiting on a call that will never settle is dropped.
    this.session = null;
    this.tail = Promise.resolve();
    this.running = this.queued = null;
    this.unlocked = false;
    this.unlocking?.abort();
    this.hub?.abort();
    this.setStatus("error", TRAP_MESSAGE);
    this.deps.onTrap?.(TRAP_MESSAGE);
  }

  /**
   * Saves part of the API key and binds it to the currently configured server.
   * Rebinding to another server clears the other part, so a secret entered for
   * one server is never sent to another one after only the id was re-entered.
   */
  setApiKey(part: "clientId" | "clientSecret", value: string): void {
    const origin = identityOrigin(this.deps.settings().serverUrl);
    if (this.deps.store.get(SECRET_API_ORIGIN) !== origin) {
      this.deps.store.set(part === "clientId" ? SECRET_CLIENT_SECRET : SECRET_CLIENT_ID, "");
    }
    this.deps.store.set(part === "clientId" ? SECRET_CLIENT_ID : SECRET_CLIENT_SECRET, value.trim());
    this.deps.store.set(SECRET_API_ORIGIN, origin);
  }

  /** The profile JSON (dybw-core README) and the client secret; refuses a key bound to another server. */
  private login(): [profile: string, clientSecret: string] {
    const settings = this.deps.settings();
    if (!settings.email.trim()) throw new Error("Set the account email in the plugin settings first");
    const clientId = this.deps.store.get(SECRET_CLIENT_ID)?.trim();
    const clientSecret = this.deps.store.get(SECRET_CLIENT_SECRET)?.trim();
    if (!clientId || !clientSecret) throw new Error("Set the Bitwarden API key in the plugin settings first");
    const boundTo = this.deps.store.get(SECRET_API_ORIGIN);
    const origin = identityOrigin(settings.serverUrl);
    if (boundTo !== origin) {
      // Refused, not cleared: the server URL is saved on every keystroke and
      // data.json may be synced from another device, so a passing mismatch
      // must not cost the user their key. Refusing already keeps it from
      // being sent anywhere else.
      throw new Error(
        `The API key was saved for ${boundTo || "another server"}, not ${origin}. ` +
          `Enter the API key again in the plugin settings to use it with this server.`,
      );
    }
    const profile = {
      server: settings.serverUrl,
      email: settings.email,
      deviceName: this.deps.deviceName,
      deviceType: DEVICE_TYPE,
      clientName: CLIENT_NAME,
      clientVersion: CLIENT_VERSION,
      // The core sends the key to this origin only, whatever the server URL resolves to.
      apiOrigin: boundTo,
      clientId,
      organizations: settings.syncOrganizations ? "all" : "none",
    };
    return [JSON.stringify(profile), clientSecret];
  }

  /** One unlock through `start`. A lock or a cancel meanwhile wins: KdfAbortedError, and the core is locked again. */
  private async open(start: (session: WasmSession, profile: string, clientSecret: string) => Promise<string>) {
    const [profile, clientSecret] = this.login();
    this.cancelUnlock();
    // The core locks before it unlocks: a failed or cancelled unlock leaves it locked, so say so now.
    if (this.unlocked) {
      this.relocks++;
      this.unlocked = false;
      this.stopHub();
      this.setStatus("locked");
    }
    const generation = this.generation;
    const abort = new AbortController();
    this.unlocking = abort;
    const stopped = () => abort.signal.aborted || generation !== this.generation;
    try {
      const summary = await this.call((session) => {
        if (stopped()) throw new KdfAbortedError();
        return start(session, profile, clientSecret);
      });
      if (stopped()) {
        this.session?.lock();
        throw new KdfAbortedError();
      }
      this.unlocked = true;
      this.setStatus("idle");
      return JSON.parse(summary) as UnlockSummary;
    } catch (e) {
      if (stopped() && !this.trapped) throw new KdfAbortedError();
      throw e;
    } finally {
      if (this.unlocking === abort) this.unlocking = null;
    }
  }

  /** Unlocks with the master password. Throws KdfAbortedError when locked or cancelled meanwhile. */
  async unlock(password: string): Promise<UnlockSummary> {
    const summary = await this.open((session, profile, clientSecret) => session.unlock(profile, clientSecret, password));
    const remember = this.deps.settings().rememberKey;
    this.deps.store.set(SECRET_USER_KEY, remember ? await this.call((session) => session.exportUserKey()) : "");
    return summary;
  }

  /** Stops an unlock in progress (for example when its dialog is closed): its key derivation ends, the core locks. */
  cancelUnlock(): void {
    if (!this.unlocking) return;
    this.unlocking.abort();
    this.unlocking = null;
    this.session?.lock();
  }

  /**
   * Unlocks from a key remembered on this device, if the user opted in. Returns false when there is none, or when
   * the core cannot use it (stale after a key rotation, malformed): it is then forgotten and the password asked for.
   */
  async unlockFromRememberedKey(): Promise<UnlockSummary | null> {
    const stored = this.deps.store.get(SECRET_USER_KEY);
    if (!stored || !this.deps.settings().rememberKey) return null;
    try {
      return await this.open((session, profile, clientSecret) => session.unlockWithKey(profile, clientSecret, stored));
    } catch (e) {
      if (!(e instanceof InvalidError || e instanceof WrongPasswordError)) throw e;
      this.forgetRememberedKey();
      return null;
    }
  }

  lock(): void {
    this.generation++;
    this.cancelUnlock();
    this.stopHub();
    this.session?.lock();
    this.unlocked = false;
    // After a trap the status keeps saying why, and to reload.
    if (!this.trapped) this.setStatus("locked");
  }

  /** The organizations to sync go into the profile at unlock: a change applies from the next one, so this locks. */
  organizationsChanged(): void {
    this.lock();
  }

  /** ADR 0017: the user confirmed, on this device, the weaker KDF the server offers. */
  acceptKdf(kdf: Kdf, origin: string): Promise<void> {
    return this.call((session) => session.acceptKdf(JSON.stringify(kdf), origin));
  }

  /** ADR 0019: the user confirmed, on this device, the lower security version the server offers. */
  acceptSecurityVersion(version: number): Promise<void> {
    return this.call((session) => session.acceptSecurityVersion(BigInt(version)));
  }

  /** ADR 0018: the user accepts on this device that a self-hosted server (by default the configured one) could redirect the API key. */
  acknowledgeOrigin(origin = identityOrigin(this.deps.settings().serverUrl)): Promise<void> {
    return this.call((session) => session.acknowledgeOrigin(origin));
  }

  /** Withdraws the configured server's acknowledgement; the core reads it at unlock, so this locks. */
  async forgetOrigin(): Promise<void> {
    const origin = identityOrigin(this.deps.settings().serverUrl);
    await this.call((session) => session.forgetOrigin(origin));
    this.lock();
  }

  /** Whether the configured server is acknowledged on this device. */
  async originAcknowledged(): Promise<boolean> {
    const origin = identityOrigin(this.deps.settings().serverUrl);
    const origins = JSON.parse(await this.call((session) => session.acknowledgedOrigins())) as string[];
    return origins.includes(origin);
  }

  forgetRememberedKey(): void {
    this.deps.store.set(SECRET_USER_KEY, "");
  }

  /**
   * Runs a sync. A call made while one is running is queued behind it rather
   * than joined, so work queued in the meantime (uploads, conflict choices,
   * answers) is not silently dropped. `acceptRollbacks` (cipher id → the revision shown) accepts the rollbacks the
   * user saw (ADR 0019); one that rolled back again since is held and reported again.
   */
  sync(
    overrides?: ReadonlyMap<string, ConflictOverride>,
    answers?: ReadonlyMap<string, HistoryAnswer>,
    acceptRollbacks?: ReadonlyMap<string, string>,
  ): Promise<SyncReport> {
    if (!this.running || this.trapped) {
      this.running = this.serial(() => this.doSync(overrides, answers, acceptRollbacks)).finally(() => {
        this.running = null;
      });
      return this.running;
    }
    if (overrides) {
      this.queuedOverrides ??= new Map();
      for (const [k, v] of overrides) this.queuedOverrides.set(k, v);
    }
    if (answers) {
      this.queuedAnswers ??= new Map();
      for (const [k, v] of answers) this.queuedAnswers.set(k, v);
    }
    if (acceptRollbacks) {
      this.queuedRollbacks ??= new Map();
      for (const [k, v] of acceptRollbacks) this.queuedRollbacks.set(k, v);
    }
    this.queued ??= this.running
      .catch(() => undefined)
      .then(() => {
        const [nextOverrides, nextAnswers, nextRollbacks] = [this.queuedOverrides, this.queuedAnswers, this.queuedRollbacks];
        this.queued = null;
        this.queuedOverrides = this.queuedAnswers = this.queuedRollbacks = undefined;
        return this.sync(nextOverrides, nextAnswers, nextRollbacks);
      });
    return this.queued;
  }

  private async doSync(
    overrides: ReadonlyMap<string, ConflictOverride> | undefined,
    answers: ReadonlyMap<string, HistoryAnswer> | undefined,
    acceptRollbacks: ReadonlyMap<string, string> | undefined,
  ): Promise<SyncReport> {
    const generation = this.generation;
    const epoch = this.answerEpoch;
    const settings = this.deps.settings();
    const options = JSON.stringify({
      policy: settings.conflictPolicy,
      acceptRollbacks: Object.fromEntries(acceptRollbacks ?? []),
      vaultName: this.deps.vaultName,
      uploadFolder: settings.uploadFolder,
      overrides: Object.fromEntries(overrides ?? []),
      answers: Object.fromEntries(answers ?? []),
    });
    const store = this.deps.store;
    const ids = store.list().filter((id) => !isReservedId(id) && store.get(id) !== null);
    const values = ids.map((id) => store.get(id)!);
    if (this.unlocked) this.setStatus("syncing");
    this.snapshot = new Map(ids.map((id, i) => [id, values[i]!]));
    try {
      const raw = JSON.parse(await this.call((session) => session.runSync(options, ids, values))) as Omit<SyncReport, "conflicts"> & {
        conflicts: RawConflict[];
      };
      const conflicts = raw.conflicts.map(({ organization, organizationName: name, ...c }) =>
        organization ? { ...c, organization: organizationName(name, organization) } : c,
      );
      const report: SyncReport = { ...raw, conflicts };
      if (report.errors.length) this.setStatus("error", report.errors.map((e) => `${e.id}: ${e.error}`).join("\n"));
      else if (conflicts.length) this.setStatus("conflict", `${conflicts.length} conflict(s)`);
      else this.setStatus("idle");
      return report;
    } catch (e) {
      // Locking stops a running sync; that is not an error to show.
      if (generation !== this.generation) throw new LockedError("locked", "Bitwarden was locked during the sync");
      // A re-unlock since the sync started made this rejection the old session's: not the new one's error.
      if (this.unlocked && epoch === this.answerEpoch) this.setStatus("error", (e as Error).message);
      throw e;
    } finally {
      this.snapshot = null;
    }
  }

  /** Secrets on this device that are not synced yet and could be uploaded. */
  uploadCandidates(): Promise<string[]> {
    return this.serial(async () => {
      const synced = JSON.parse(await this.call((session) => session.syncedIds())) as Record<"base" | "pendingCreates", string[]>;
      const known = new Set([...synced.base, ...synced.pendingCreates]);
      return this.deps.store
        .list()
        .filter((id) => !isReservedId(id) && !known.has(id))
        .sort();
    });
  }

  /** Queues a local secret for upload on the next sync. */
  async queueUpload(id: string, scope: Scope): Promise<void> {
    if (!SECRET_ID_PATTERN.test(id) || isReservedId(id)) throw new Error(`Cannot upload "${id}"`);
    if (this.deps.store.get(id) === null) throw new Error(`No local secret named "${id}"`);
    await this.serial(() => this.call((session) => session.queueUpload(id, scopeText(scope))));
  }

  /** Forgets what was synced on this device, keeping its id; a running sync finishes first. */
  resetState(): Promise<void> {
    return this.serial(() => this.call((session) => session.resetState()));
  }

  /**
   * Keeps the notifications hub up while unlocked, calling `onChange` when the vault changed elsewhere. Resolves once
   * it stopped (`stopHub`, `lock`), at once when locked or already running.
   */
  startHub(onChange: () => void): Promise<void> {
    if (this.hub || !this.unlocked) return Promise.resolve();
    const stop = new AbortController();
    this.hub = stop;
    this.hubOnChange = onChange;
    return this.call((session) => session.runHub(onChange, () => stop.signal.aborted))
      .catch(() => undefined)
      .finally(() => {
        if (this.hub === stop) this.hub = null;
      });
  }

  stopHub(): void {
    this.hub?.abort();
    this.hub = null;
  }

  /**
   * Starts a running hub over at once, for an app back from the background: a socket kept across a suspend can be
   * dead without saying so, and a reconnect may be waiting out a long backoff. Does nothing when no hub runs.
   */
  wake(): void {
    const onChange = this.hub && this.hubOnChange;
    if (!onChange) return;
    this.stopHub();
    void this.startHub(onChange);
  }

  deviceId(): Promise<string> {
    return this.call((session) => session.deviceId());
  }
}
