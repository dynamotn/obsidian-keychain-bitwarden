// Maps the plugin's real outputs to the language-neutral shapes of the dybw
// conformance vectors (dybw-core `vectors/README.md`): the canonical write
// body, the shared skip reason codes and the write error codes.

import type { CipherRequest } from "../../src/bw/api";
import { decryptString, unwrapKey, type SymmetricKey } from "../../src/bw/crypto";

export interface CanonicalField {
  name: string | null;
  value: string | null;
  type: number;
}

export interface CanonicalLogin {
  username: string | null;
  password: string | null;
  uris: (string | null)[];
  totp: string | null;
  passwordHistory: (string | null)[];
}

export type CanonicalRequest =
  | {
      method: "POST" | "PUT";
      cipher: string | null;
      type: number;
      name?: string | null;
      notes: string | null;
      login: CanonicalLogin | null;
      fields: CanonicalField[];
      organizationId: string | null;
      folderId: string | null;
      lastKnownRevisionDate: string | null;
      hasItemKey: boolean;
      extra: Record<string, unknown>;
    }
  | { method: "trash"; cipher: string };

/** A cipher write as the plugin sent it over HTTP. */
export type SentRequest =
  | { method: "POST" | "PUT"; cipher: string | null; body: CipherRequest & Record<string, unknown> }
  | { method: "trash"; cipher: string };

export interface ScenarioKeys {
  userKey: SymmetricKey;
  orgKeys: ReadonlyMap<string, SymmetricKey>;
}

/**
 * Unknown properties passed through: only the `x` convention keys, as in a
 * cipher (vectors/README.md, canonical body). Any other key is ignored.
 */
const EXTRA_KEY = /^x[A-Za-z0-9]+$/;

/** The date the tests freeze the clock at; a date equal to it was written by the tool. */
export const NOW = "2099-09-09T09:09:09.999Z";

/** Replaces every string equal to `NOW` by the literal `<now>` of the vectors. */
function markNow<T>(value: T): T {
  if (value === NOW) return "<now>" as T;
  if (Array.isArray(value)) return value.map(markNow) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, markNow(v)])) as T;
  }
  return value;
}

/** Decrypts the plugin's real request body with the scenario's keys (the item key when the body has one). */
export async function canonicalize(sent: SentRequest, keys: ScenarioKeys): Promise<CanonicalRequest> {
  if (sent.method === "trash") return { method: "trash", cipher: sent.cipher };
  const body = sent.body;
  const ownerKey = body.organizationId ? keys.orgKeys.get(body.organizationId) : keys.userKey;
  if (!ownerKey) throw new Error(`no key for organization ${body.organizationId}`);
  const key = body.key ? await unwrapKey(body.key, ownerKey) : ownerKey;
  const dec = async (v: unknown): Promise<string | null> => {
    if (v === null || v === undefined) return null;
    if (typeof v !== "string") throw new Error(`expected an EncString, got ${JSON.stringify(v)}`);
    return decryptString(v, key);
  };

  // `fields`, `uris` and `passwordHistory` read null as [] because the canonical body types them as arrays.
  const rawLogin = body.login as Record<string, unknown> | null | undefined;
  let login: CanonicalLogin | null = null;
  if (rawLogin) {
    const uris = (rawLogin.uris as { uri?: unknown }[] | null | undefined) ?? [];
    const history = body.passwordHistory ?? [];
    login = {
      username: await dec(rawLogin.username),
      password: await dec(rawLogin.password),
      uris: await Promise.all(uris.map((u) => dec(u.uri))),
      totp: await dec(rawLogin.totp),
      passwordHistory: await Promise.all(history.map((h) => dec(h.password))),
    };
  }

  const fields: CanonicalField[] = [];
  for (const f of body.fields ?? []) {
    fields.push({ name: await dec(f.name), value: await dec(f.value), type: f.type });
  }

  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) if (EXTRA_KEY.test(k)) extra[k] = v;

  return markNow({
    method: sent.method,
    cipher: sent.cipher,
    type: body.type,
    name: await dec(body.name),
    notes: await dec(body.notes),
    login,
    fields,
    organizationId: body.organizationId ?? null,
    folderId: body.folderId ?? null,
    lastKnownRevisionDate: body.lastKnownRevisionDate ?? null,
    hasItemKey: Boolean(body.key),
    extra,
  });
}

/**
 * Rule R16: the data model leaves a new item's name and the tool's other
 * fields open (§6.2), so a `POST` is compared without its name and without
 * every `{ns}:*` field but `{ns}:id` and `{ns}:password`. Applied to both sides.
 */
export function dropToolDefined(req: CanonicalRequest, ns: string): CanonicalRequest {
  if (req.method !== "POST") return req;
  const { name: _name, ...rest } = req;
  const kept = new Set([`${ns}:id`, `${ns}:password`]);
  return { ...rest, fields: rest.fields.filter((f) => !f.name?.startsWith(`${ns}:`) || kept.has(f.name)) };
}

/** `SkippedItem.reason` texts of the plugin, mapped to the shared reason codes. */
const REASON_CODES: [RegExp, string][] = [
  [/^only login and secure note items are synced$/, "wrong-type"],
  [/^the organization hides this item's password from you$/, "view-password-hidden"],
  [/^"obsidian:id" must be lowercase letters, digits and dashes$/, "invalid-id"],
  [/^id ".*" is reserved for the plugin$/, "reserved-id"],
  [/^"obsidian:encoding" is not supported by this plugin$/, "unknown-encoding"],
  [/^unknown "obsidian:location" value$/, "unknown-location"],
];

/** The shared code, or the plugin's own text marked as unmapped (which never equals a code). */
export function reasonCode(reason: string): string {
  return REASON_CODES.find(([re]) => re.test(reason))?.[1] ?? `unmapped: ${reason}`;
}

/** The engine's `duplicate of "<id>"; ...` skip, which the vectors list under `duplicates`. */
export function duplicateOf(reason: string): string | null {
  return /^duplicate of "(.+)"; the (personal|oldest) item is used$/.exec(reason)?.[1] ?? null;
}

/** Write errors (ValueTooLongError messages) mapped to the vectors' error codes. */
const ERROR_CODES: [RegExp, string][] = [
  [/too long for a field .*and the notes hold your own text$/, "notes-hold-user-text"],
  [/^the value is too long for /, "too-long"],
];

export function errorCode(message: string): string {
  return ERROR_CODES.find(([re]) => re.test(message))?.[1] ?? `unmapped: ${message}`;
}
