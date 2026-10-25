// Runs the plugin's real code against every `obsidian` scenario of the dybw
// conformance vectors (dybw-core `vectors/generated/obsidian/`). Opt-in:
// `npm run test:vectors`, with DYBW_VECTORS_DIR pointing at `vectors/`.
//
// - read/*: the real BitwardenApi (PascalCase normalisation included) over a
//   fake transport, readVault for items, skips and uninspectable ciphers, and
//   runSync on an empty device for the duplicate and reserved-id rules.
// - write/*: runSync on a device that knows the item (or has the id queued
//   for upload), so the plugin builds and sends the request itself; with
//   `fresh`, the first update is rejected as out of date and the engine's own
//   retry refetches and re-applies.
// - sync/*: planSync on a PlanInput built from the read items, `device` and
//   `local`, with the plugin's own value fingerprints.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BitwardenApi, resolveServerUrls, type CipherRequest, type SyncDto } from "../../src/bw/api";
import { encryptBytes, encryptString, SymmetricKey, ValueFingerprinter } from "../../src/bw/crypto";
import { fromBase64, toBase64 } from "../../src/bw/encoding";
import type { HttpClient } from "../../src/bw/http";
import { formatScope, readVault, unlockOrganizationKeys, type SecretRecord } from "../../src/bw/vault";
import { runSync, type SecretStore, type SyncReport } from "../../src/sync/engine";
import { planSync, type BaseEntry, type ConflictPolicy, type LocalEntry, type RemoteEntry } from "../../src/sync/plan";
import { newDeviceState, type DeviceState } from "../../src/sync/state";
import {
  canonicalize,
  dropToolDefined,
  duplicateOf,
  errorCode,
  NOW,
  reasonCode,
  type CanonicalRequest,
  type ScenarioKeys,
  type SentRequest,
} from "./canonical";

const NS = "obsidian";
const NOT_FOUND = "conformance vectors not found: set DYBW_VECTORS_DIR";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function vectorsDir(): string | null {
  const candidates = process.env.DYBW_VECTORS_DIR ? [process.env.DYBW_VECTORS_DIR] : [resolve(REPO_ROOT, "../core/vectors")];
  for (const dir of candidates) if (existsSync(join(dir, "generated", NS))) return resolve(dir);
  return null;
}

// --- Scenario format (dybw-core vectors/README.md) --------------------------

interface Account {
  name: string;
  email: string;
  userKey: string;
  profileKey: string;
  privateKey?: string;
  organizations?: { id: string; name: string; key: string; wrapped: string }[];
}

interface ReadExpect {
  items: { cipher: string; id: string; value: string; source: string; attributes?: Record<string, string> }[];
  skipped: { cipher: string; reason: string }[];
  uninspectable: string[];
  duplicates?: { id: string; kept: string; left: string[] }[];
}

type WriteExpect = { requests: CanonicalRequest[] } | { error: string };

type PlanExpect = { kind: string; id: string; conflict?: string }[];

type ServerCipher = Record<string, unknown>;

interface Scenario {
  id: string;
  namespace: string;
  account: string;
  options?: { organizations?: boolean; policy?: ConflictPolicy } | null;
  ciphers: ServerCipher[];
  device?: {
    base: Record<string, { cipher: string; revisionDate: string; value: string; pushConfirmed?: boolean }>;
    pendingCreates: string[];
  } | null;
  local?: Record<string, string | null> | null;
  operation?:
    | { kind: "set-value"; id: string; value: string; fresh?: ServerCipher }
    | { kind: "create"; id: string; value: string; folderId: string | null; fresh?: ServerCipher }
    | { kind: "delete"; id: string; fresh?: ServerCipher }
    | null;
  expect: { read?: ReadExpect; write?: WriteExpect; plan?: PlanExpect };
}

function listScenarios(root: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) out.push(...listScenarios(path));
    else if (name.endsWith(".json")) out.push(path);
  }
  return out;
}

function readExpectedFailures(): Map<string, string> {
  const listed = new Map<string, string>();
  const text = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "expected-failures.txt"), "utf8");
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const space = line.indexOf(" ");
    if (space < 0) throw new Error(`expected-failures.txt: no reason for ${line}`);
    listed.set(line.slice(0, space), line.slice(space + 1).trim());
  }
  return listed;
}

// --- Keys ---------------------------------------------------------------------

interface AccountKeys extends ScenarioKeys {
  account: Account;
  /** The account's private key wrapped under the user key, as `profile.privateKey`. */
  wrappedPrivateKey: string | null;
}

async function accountKeys(dir: string, name: string, organizations: boolean): Promise<AccountKeys> {
  const account = JSON.parse(readFileSync(join(dir, "accounts", `${name}.json`), "utf8")) as Account;
  const userKey = await SymmetricKey.fromBytes(fromBase64(account.userKey));
  const wrappedPrivateKey = account.privateKey ? await encryptBytes(fromBase64(account.privateKey), userKey, "pkcs8") : null;
  const orgKeys = new Map<string, SymmetricKey>();
  if (organizations && account.organizations?.length) {
    // The plugin's own unwrap (RSA-OAEP with the account's private key), checked against the plain keys.
    const { keys, problems } = await unlockOrganizationKeys(profileSync(account, wrappedPrivateKey), userKey);
    expect(problems).toEqual([]);
    for (const org of account.organizations) {
      const key = keys.get(org.id);
      expect(key && toBase64(key.exportBytes())).toBe(org.key);
      orgKeys.set(org.id, key!);
    }
  }
  return { account, userKey, orgKeys, wrappedPrivateKey };
}

function profileSync(account: Account, wrappedPrivateKey: string | null): SyncDto {
  return {
    profile: {
      id: "vectors-user",
      email: account.email,
      key: account.profileKey,
      privateKey: wrappedPrivateKey,
      organizations: (account.organizations ?? []).map((o) => ({ id: o.id, name: o.name, key: o.wrapped, enabled: true })),
    },
    folders: [],
    ciphers: [],
  };
}

// --- A fake Bitwarden server behind the plugin's real API client ---------------

const SERVER = "https://vectors.invalid";
const URLS = resolveServerUrls(SERVER);
const SERVER_REVISION = "2026-12-01T00:00:00.000Z";

class VectorServer {
  /** Cipher writes the plugin sent and the server accepted, in order. */
  readonly sent: SentRequest[] = [];
  /** Updates rejected as out of date. */
  rejected = 0;
  /** The cipher a refetch returns after the next update is rejected (data model §6.5). */
  fresh: ServerCipher | null = null;

  constructor(
    private readonly profile: SyncDto["profile"],
    private ciphers: ServerCipher[],
    private readonly folders: { id: string; name: string }[] = [],
  ) {}

  private cipherId(c: ServerCipher): unknown {
    return c.id ?? c.Id;
  }

  readonly http: HttpClient = async (req) => {
    const ok = (body: unknown) => ({ status: 200, text: JSON.stringify(body) });
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.method === "POST" && req.url === `${URLS.identity}/connect/token`) {
      return ok({ access_token: "vectors-token", expires_in: 3600 });
    }
    if (req.method === "GET" && path === "/api/sync") {
      return ok({ profile: this.profile, folders: this.folders, ciphers: this.ciphers });
    }
    if (req.method === "POST" && path === "/api/folders") {
      return ok({ id: "folder-created", name: (JSON.parse(req.body!) as { name: string }).name });
    }
    if (req.method === "POST" && path === "/api/ciphers") {
      this.sent.push({ method: "POST", cipher: null, body: JSON.parse(req.body!) as CipherRequest & Record<string, unknown> });
      return ok({ id: "cipher-created", revisionDate: SERVER_REVISION });
    }
    const trash = /^\/api\/ciphers\/([^/]+)\/delete$/.exec(path);
    if (req.method === "PUT" && trash) {
      this.sent.push({ method: "trash", cipher: decodeURIComponent(trash[1]!) });
      return { status: 200, text: "" };
    }
    const update = /^\/api\/ciphers\/([^/]+)$/.exec(path);
    if (req.method === "PUT" && update) {
      const id = decodeURIComponent(update[1]!);
      if (this.fresh) {
        const fresh = this.fresh;
        this.fresh = null;
        this.rejected++;
        const at = this.ciphers.findIndex((c) => this.cipherId(c) === this.cipherId(fresh));
        if (at >= 0) this.ciphers[at] = fresh;
        else this.ciphers = [...this.ciphers, fresh];
        return {
          status: 400,
          text: JSON.stringify({ message: "The client copy of this cipher is out of date. Resubmit with the current revision date." }),
        };
      }
      this.sent.push({ method: "PUT", cipher: id, body: JSON.parse(req.body!) as CipherRequest & Record<string, unknown> });
      return ok({ id, revisionDate: SERVER_REVISION });
    }
    return { status: 404, text: JSON.stringify({ message: `not faked: ${req.method} ${path}` }) };
  };
}

class MapStore implements SecretStore {
  readonly values = new Map<string, string>();
  get(id: string): string | null {
    return this.values.get(id) ?? null;
  }
  set(id: string, value: string): void {
    this.values.set(id, value);
  }
  list(): string[] {
    return [...this.values.keys()];
  }
}

interface Harness {
  keys: AccountKeys;
  server: VectorServer;
  api: BitwardenApi;
  organizations: boolean;
}

async function harness(
  dir: string,
  s: Scenario,
  folders: { id: string; name: string }[] = [],
): Promise<Harness> {
  const organizations = s.options?.organizations === true;
  const keys = await accountKeys(dir, s.account, organizations);
  const server = new VectorServer(profileSync(keys.account, keys.wrappedPrivateKey).profile, s.ciphers, folders);
  const api = new BitwardenApi(URLS, server.http, { identifier: "vectors-device", name: "vectors" });
  await api.loginWithApiKey({ clientId: "vectors", clientSecret: "vectors" });
  return { keys, server, api, organizations };
}

function syncContext(h: Harness, store: SecretStore, state: DeviceState, extra: { uploadFolder?: string; policy?: ConflictPolicy } = {}) {
  return {
    api: h.api,
    userKey: h.keys.userKey,
    store,
    state,
    saveState: () => {},
    uploadFolder: extra.uploadFolder ?? "",
    vaultName: "vectors",
    organizations: h.organizations,
    policy: extra.policy ?? "ask",
  };
}

// --- read -----------------------------------------------------------------------

interface ReadOutcome {
  /** The records the engine keeps: one per id, duplicates and reserved ids left out. */
  kept: SecretRecord[];
  read: ReadExpect & { engineErrors?: string[] };
}

async function readScenario(h: Harness): Promise<ReadOutcome> {
  const sync = await h.api.sync();
  const { records, skipped, present } = await readVault(sync, h.keys.userKey, h.organizations ? h.keys.orgKeys : null);

  // The duplicate (§7) and reserved-id rules live in the engine: a first sync
  // on an empty device pulls every id it keeps and reports the others.
  const state = newDeviceState();
  const report: SyncReport = await runSync(syncContext(h, new MapStore(), state));
  const kept = records.filter((r) => state.base[r.id]?.cipherId === r.cipherId);

  const duplicates = new Map<string, string[]>();
  const skippedOut: { cipher: string; reason: string }[] = [];
  for (const s of report.skipped) {
    const dup = duplicateOf(s.reason);
    if (dup !== null) duplicates.set(dup, [...(duplicates.get(dup) ?? []), s.cipherId]);
    else skippedOut.push({ cipher: s.cipherId, reason: reasonCode(s.reason) });
  }

  const inspected = new Set([...records.map((r) => r.cipherId), ...skipped.map((s) => s.cipherId)]);
  const read: ReadOutcome["read"] = {
    items: kept
      .map((r) => ({
        cipher: r.cipherId,
        id: r.id,
        value: r.value,
        source:
          r.source.kind === "field" ? "field" : r.source.kind === "notes" ? "notes" : r.cipher.type === 1 ? "login-password" : "note-body",
      }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    skipped: sortSkipped(skippedOut),
    uninspectable: [...present].filter((c) => !inspected.has(c)).sort(),
    duplicates: [...duplicates]
      .map(([id, left]) => ({ id, kept: state.base[id]?.cipherId ?? "<none>", left: [...left].sort() }))
      .sort((a, b) => (a.id < b.id ? -1 : 1)),
  };
  if (report.errors.length) read.engineErrors = report.errors;
  return { kept, read };
}

function sortSkipped(list: { cipher: string; reason: string }[]) {
  return [...list].sort((a, b) => (a.cipher < b.cipher ? -1 : a.cipher > b.cipher ? 1 : a.reason < b.reason ? -1 : 1));
}

function normalizeReadExpect(e: ReadExpect): ReadExpect {
  return {
    items: e.items,
    skipped: sortSkipped(e.skipped),
    uninspectable: [...e.uninspectable].sort(),
    duplicates: (e.duplicates ?? []).map((d) => ({ ...d, left: [...d.left].sort() })).sort((a, b) => (a.id < b.id ? -1 : 1)),
  };
}

// --- write ----------------------------------------------------------------------

const UPLOAD_FOLDER = "obsidian-vectors";

async function writeScenario(dir: string, s: Scenario): Promise<WriteExpect & { engineErrors?: string[] }> {
  const op = s.operation;
  if (!op) throw new Error("write scenario without an operation");
  if (op.kind === "delete") throw new Error("the plugin has no delete operation (secret storage cannot delete)");
  if (op.value.startsWith("base64:")) throw new Error("the plugin writes text only; binary values are not supported");

  // The folder new items are filed in, found by its (encrypted) name.
  const keysForFolder = await accountKeys(dir, s.account, false);
  const folders =
    op.kind === "create" && op.folderId !== null
      ? [{ id: op.folderId, name: await encryptString(UPLOAD_FOLDER, keysForFolder.userKey) }]
      : [];
  const h = await harness(dir, s, folders);
  const fp = await ValueFingerprinter.forUserKey(h.keys.userKey);
  const store = new MapStore();
  const state = newDeviceState();

  if (op.kind === "set-value") {
    // The device synced the item as it is in `ciphers`, and the user then set a new value.
    const { kept } = await readScenario(h);
    const rec = kept.find((r) => r.id === op.id);
    if (!rec) throw new Error(`"${op.id}" is not a readable item of the scenario`);
    state.base[op.id] = {
      cipherId: rec.cipherId,
      revisionDate: rec.revisionDate,
      fingerprint: await fp.of(op.id, rec.value),
      scope: formatScope(rec.scope),
      // Every confirmation the data model asks for was answered "go ahead" (§9).
      ...(rec.organizationId ? { pushConfirmed: true } : {}),
    };
  } else {
    state.pendingCreates = [op.id];
  }
  store.set(op.id, op.value);
  h.server.sent.length = 0;
  h.server.fresh = op.fresh ?? null;

  const report = await runSync(syncContext(h, store, state, { uploadFolder: op.kind === "create" && op.folderId !== null ? UPLOAD_FOLDER : "" }));
  if (op.fresh) expect(h.server.rejected, "the first write is rejected as out of date").toBe(1);

  const errors = report.errors.filter((e) => e.startsWith(`${op.id}: `)).map((e) => e.slice(op.id.length + 2));
  const others = report.errors.filter((e) => !e.startsWith(`${op.id}: `));
  const out: WriteExpect & { engineErrors?: string[] } =
    errors.length > 0
      ? { error: errorCode(errors[0]!) }
      : { requests: await Promise.all(h.server.sent.map(async (r) => dropToolDefined(await canonicalize(r, h.keys), NS))) };
  if (others.length || errors.length > 1) out.engineErrors = report.errors;
  return out;
}

function normalizeWriteExpect(e: WriteExpect): WriteExpect {
  return "error" in e ? e : { requests: e.requests.map((r) => dropToolDefined(r, NS)) };
}

// --- sync -----------------------------------------------------------------------

async function planScenario(dir: string, s: Scenario): Promise<PlanExpect> {
  const h = await harness(dir, s);
  const { kept } = await readScenario(h);
  const fp = await ValueFingerprinter.forUserKey(h.keys.userKey);

  const remote = new Map<string, RemoteEntry>();
  for (const r of kept) {
    remote.set(r.id, {
      id: r.id,
      cipherId: r.cipherId,
      revisionDate: r.revisionDate,
      fingerprint: await fp.of(r.id, r.value),
      organization: r.organizationId !== null,
    });
  }
  const base = new Map<string, BaseEntry>();
  for (const [id, e] of Object.entries(s.device?.base ?? {})) {
    base.set(id, {
      cipherId: e.cipher,
      revisionDate: e.revisionDate,
      fingerprint: await fp.of(id, e.value),
      ...(e.pushConfirmed ? { pushConfirmed: true } : {}),
    });
  }
  // An absent id and null both mean no local value; "" is a value.
  const local = new Map<string, LocalEntry>();
  for (const [id, v] of Object.entries(s.local ?? {})) local.set(id, { fingerprint: v === null ? null : await fp.of(id, v) });

  const actions = planSync({
    remote,
    base,
    local: (id) => local.get(id) ?? { fingerprint: null },
    pendingCreates: new Set(s.device?.pendingCreates ?? []),
    policy: s.options?.policy ?? "ask",
  });
  // The `confirmed` marker is not part of the plan (vectors/README.md).
  return actions.map((a) => (a.kind === "conflict" ? { kind: a.kind, id: a.id, conflict: a.conflict } : { kind: a.kind, id: a.id }));
}

// --- Registration ---------------------------------------------------------------

const dir = vectorsDir();

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"], now: new Date(NOW) });
});
afterEach(() => {
  vi.useRealTimers();
});

if (!dir) {
  it("conformance vectors", () => {
    throw new Error(NOT_FOUND);
  });
} else {
  const expectedFailures = readExpectedFailures();
  const files = listScenarios(join(dir, "generated", NS));
  const ids = new Set<string>();

  describe(`dybw conformance vectors (${NS})`, () => {
    for (const file of files) {
      const s = JSON.parse(readFileSync(file, "utf8")) as Scenario;
      ids.add(s.id);
      const run = async () => {
        expect(s.namespace).toBe(NS);
        expect(relative(join(dir, "generated", NS), file)).toBe(`${s.id}.json`);
        if (s.expect.read) {
          const h = await harness(dir, s);
          expect((await readScenario(h)).read).toEqual(normalizeReadExpect(s.expect.read));
        }
        if (s.expect.write) expect(await writeScenario(dir, s)).toEqual(normalizeWriteExpect(s.expect.write));
        if (s.expect.plan) expect(await planScenario(dir, s)).toEqual(s.expect.plan);
      };
      // A listed vector that passes fails the run, so the list stays honest.
      if (expectedFailures.has(s.id)) it.fails(s.id, run);
      else it(s.id, run);
    }

    it("expected-failures.txt lists only existing vectors", () => {
      expect([...expectedFailures.keys()].filter((id) => !ids.has(id))).toEqual([]);
    });
  });
}
