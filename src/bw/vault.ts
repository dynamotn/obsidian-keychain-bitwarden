// Maps the Bitwarden items marked with an `obsidian:id` field to Obsidian
// secrets, and back.

import { encryptedPrivateKeyOf, type BitwardenApi, type CipherDto, type CipherRequest, type FieldDto, type SyncDto } from "./api";
import {
  AccountPrivateKey,
  decryptString,
  deriveMasterKey,
  encryptString,
  stretchMasterKey,
  SymmetricKey,
  unwrapKey,
  type DeriveOptions,
} from "./crypto";

export const CipherType = { Login: 1, SecureNote: 2 } as const;
/** Marks an item as an Obsidian secret and names it; items without it are ignored. */
export const FIELD_ID = "obsidian:id";
export const FIELD_SCOPE = "obsidian:scope";
/** Holds the secret instead of the login password or the note's text, when present. */
export const FIELD_PASSWORD = "obsidian:password";

/** Same rule as SecretStorage.setSecret: lowercase alphanumerics with optional dashes. */
export const SECRET_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export type Scope = { kind: "global" } | { kind: "vault"; name: string } | { kind: "device"; id: string };

export interface SecretRecord {
  id: string;
  cipherId: string;
  revisionDate: string;
  label: string;
  value: string;
  scope: Scope;
  /** Index in `cipher.fields` of the `obsidian:password` field holding the value; null for the default place. */
  valueField: number | null;
  /** Set for organization items; such items are encrypted with the organization's key. */
  organizationId: string | null;
  /** The organization does not let this user change the item. */
  readOnly: boolean;
  /** Kept to re-encrypt edits without disturbing the parts of the item this plugin does not own. */
  cipher: CipherDto;
}

/** Organization keys by organization id. */
export type OrganizationKeys = ReadonlyMap<string, SymmetricKey>;

export interface SkippedItem {
  cipherId: string;
  reason: string;
}

export function parseScope(raw: string | null | undefined): Scope | null {
  const v = (raw ?? "").trim();
  if (v === "" || v === "global") return { kind: "global" };
  if (v.startsWith("vault:") && v.length > 6) return { kind: "vault", name: v.slice(6) };
  if (v.startsWith("device:") && v.length > 7) return { kind: "device", id: v.slice(7) };
  return null;
}

export function formatScope(scope: Scope): string {
  if (scope.kind === "vault") return `vault:${scope.name}`;
  if (scope.kind === "device") return `device:${scope.id}`;
  return "global";
}

export function scopeApplies(scope: Scope, vaultName: string, deviceId: string): boolean {
  if (scope.kind === "vault") return scope.name === vaultName;
  if (scope.kind === "device") return scope.id === deviceId;
  return true;
}

/**
 * Derives the user key from the master password and the account key in the
 * sync response. The KDF parameters are looked up by email; the master key's
 * salt is usually the email too, but may differ (see `masterKeySaltOf`).
 */
export async function unlockUserKey(
  api: BitwardenApi,
  email: string,
  password: string,
  encryptedUserKey: string,
  options: DeriveOptions & { salt?: string } = {},
): Promise<SymmetricKey> {
  const kdf = await api.prelogin(email);
  const masterKey = await deriveMasterKey(password, options.salt ?? email, kdf, options);
  const stretched = await stretchMasterKey(masterKey);
  masterKey.fill(0);
  try {
    // A legacy 64-byte key, or a COSE key on accounts using the newer encryption.
    return await unwrapKey(encryptedUserKey, stretched);
  } finally {
    stretched.wipe();
  }
}

/** Finds the ids of every folder with this (encrypted) name; Bitwarden allows duplicates. */
export async function findFolderIds(sync: SyncDto, userKey: SymmetricKey, folderName: string): Promise<string[]> {
  const ids: string[] = [];
  for (const f of sync.folders) {
    try {
      if ((await decryptString(f.name, userKey)) === folderName) ids.push(f.id);
    } catch {
      // A folder we cannot decrypt is not ours.
    }
  }
  return ids;
}

/**
 * Unwraps the keys of the organizations this account is a confirmed member
 * of. An organization whose key cannot be unwrapped is reported, not fatal:
 * its items are skipped.
 */
export async function unlockOrganizationKeys(
  sync: SyncDto,
  userKey: SymmetricKey,
): Promise<{ keys: Map<string, SymmetricKey>; problems: string[] }> {
  const keys = new Map<string, SymmetricKey>();
  const problems: string[] = [];
  const orgs = (sync.profile.organizations ?? []).filter((o) => o.key && o.enabled !== false);
  if (orgs.length === 0) return { keys, problems };
  const wrapped = encryptedPrivateKeyOf(sync);
  if (!wrapped) return { keys, problems: ["the account has no private key to read organization keys"] };
  const privateKey = await AccountPrivateKey.unwrap(wrapped, userKey);
  try {
    for (const org of orgs) {
      try {
        const raw = await privateKey.decrypt(org.key!);
        try {
          keys.set(org.id, await SymmetricKey.fromBytes(raw));
        } finally {
          raw.fill(0);
        }
      } catch (e) {
        problems.push(`organization ${org.id}: ${(e as Error).message}`);
      }
    }
  } finally {
    privateKey.wipe();
  }
  return { keys, problems };
}

/** The key an item is encrypted under: the organization's for organization items, else the user key. */
export function ownerKeyFor(
  cipher: Pick<CipherDto, "organizationId">,
  userKey: SymmetricKey,
  orgKeys: OrganizationKeys | null,
): SymmetricKey | undefined {
  return cipher.organizationId ? orgKeys?.get(cipher.organizationId) : userKey;
}

async function itemKeyFor(cipher: CipherDto, ownerKey: SymmetricKey): Promise<SymmetricKey> {
  return cipher.key ? unwrapKey(cipher.key, ownerKey) : ownerKey;
}

async function decryptField(value: string | null | undefined, key: SymmetricKey): Promise<string | null> {
  return value ? decryptString(value, key) : null;
}

/**
 * Decrypts the non-deleted login and secure-note items of the whole vault that
 * carry an `obsidian:id` field. Only field names are decrypted to look for the
 * marker; names and values of other items stay encrypted. Organization items
 * are read only when `orgKeys` is given (the user opted in).
 */
export async function readVault(
  sync: SyncDto,
  userKey: SymmetricKey,
  orgKeys: OrganizationKeys | null = null,
): Promise<{ records: SecretRecord[]; skipped: SkippedItem[]; present: Set<string> }> {
  const records: SecretRecord[] = [];
  const skipped: SkippedItem[] = [];
  // Every live item that is marked, or that could not be inspected: an item
  // that merely became unreadable must not look deleted.
  const present = new Set<string>();
  for (const cipher of sync.ciphers) {
    if (cipher.deletedDate) continue;
    const ownerKey = cipher.organizationId && !orgKeys ? undefined : ownerKeyFor(cipher, userKey, orgKeys);
    if (!ownerKey) {
      present.add(cipher.id);
      continue;
    }
    let key = ownerKey;
    try {
      let fields: Map<string, { index: number; value: string | null | undefined }>;
      try {
        key = await itemKeyFor(cipher, ownerKey);
        fields = await obsidianFields(cipher, key);
      } catch {
        present.add(cipher.id);
        continue;
      }
      const idField = fields.get(FIELD_ID);
      if (!idField) continue;
      present.add(cipher.id);
      if (cipher.type !== CipherType.SecureNote && cipher.type !== CipherType.Login) {
        skipped.push({ cipherId: cipher.id, reason: "only login and secure note items are synced" });
        continue;
      }
      if (cipher.organizationId && cipher.viewPassword === false) {
        skipped.push({ cipherId: cipher.id, reason: "the organization hides this item's password from you" });
        continue;
      }
      const id = ((await decryptField(idField.value, key)) ?? "").trim();
      if (!SECRET_ID_PATTERN.test(id)) {
        skipped.push({ cipherId: cipher.id, reason: `"${FIELD_ID}" must be lowercase letters, digits and dashes` });
        continue;
      }
      const scopeField = fields.get(FIELD_SCOPE);
      const scope = parseScope(scopeField ? await decryptField(scopeField.value, key) : null);
      if (!scope) {
        skipped.push({ cipherId: cipher.id, reason: `unknown "${FIELD_SCOPE}" value` });
        continue;
      }
      const valueField = fields.get(FIELD_PASSWORD) ?? null;
      const rawValue = valueField
        ? valueField.value
        : cipher.type === CipherType.Login
          ? (cipher.login?.password as string | null | undefined)
          : cipher.notes;
      const value = (await decryptField(rawValue, key)) ?? "";
      records.push({
        id,
        cipherId: cipher.id,
        revisionDate: cipher.revisionDate,
        label: (await decryptField(cipher.name, key)) ?? "",
        value,
        scope,
        valueField: valueField?.index ?? null,
        organizationId: cipher.organizationId ?? null,
        readOnly: Boolean(cipher.organizationId) && cipher.edit === false,
        cipher,
      });
    } catch (e) {
      skipped.push({ cipherId: cipher.id, reason: (e as Error).message });
    } finally {
      if (key !== ownerKey) key.wipe();
    }
  }
  return { records, skipped, present };
}

/** The `obsidian:*` custom fields of an item by name, values still encrypted; the first of duplicates wins. */
async function obsidianFields(
  cipher: CipherDto,
  key: SymmetricKey,
): Promise<Map<string, { index: number; value: string | null | undefined }>> {
  const found = new Map<string, { index: number; value: string | null | undefined }>();
  const list = cipher.fields ?? [];
  for (let index = 0; index < list.length; index++) {
    const f = list[index]!;
    const name = await decryptField(f.name, key);
    if (name?.startsWith("obsidian:") && !found.has(name)) found.set(name, { index, value: f.value });
  }
  return found;
}

/**
 * Builds a request for a new secure note holding one secret. The value goes
 * into an `obsidian:password` field, never the notes: notes and passwords are
 * the user's, and a new item must leave them free.
 */
export async function newSecretRequest(
  userKey: SymmetricKey,
  folderId: string | null,
  id: string,
  value: string,
  scope: Scope,
): Promise<CipherRequest> {
  const fields: FieldDto[] = [
    { type: 0, name: await encryptString(FIELD_ID, userKey), value: await encryptString(id, userKey) },
    {
      type: 1,
      name: await encryptString(FIELD_PASSWORD, userKey),
      value: value === "" ? null : await encryptString(value, userKey),
    },
  ];
  if (scope.kind !== "global") {
    fields.push({
      type: 0,
      name: await encryptString(FIELD_SCOPE, userKey),
      value: await encryptString(formatScope(scope), userKey),
    });
  }
  return {
    type: CipherType.SecureNote,
    folderId,
    organizationId: null,
    name: await encryptString(id, userKey),
    notes: null,
    fields,
    favorite: false,
    reprompt: 0,
    key: null,
    secureNote: { type: 0 },
  };
}

/**
 * Builds an update that changes only the secret value and passes every other
 * part of the item through untouched (still encrypted). `ownerKey` is the key
 * the item is encrypted under: the user key, or its organization's key.
 */
export async function updateValueRequest(
  record: SecretRecord,
  ownerKey: SymmetricKey,
  value: string,
  now: Date = new Date(),
): Promise<CipherRequest> {
  const c = record.cipher;
  const key = await itemKeyFor(c, ownerKey);
  try {
    const encValue = value === "" ? null : await encryptString(value, key);
    // Start from the item as the server sent it so that properties this plugin
    // does not know about (newer item types, archive state, ...) survive the
    // edit; drop only the response-only metadata.
    const {
      id: _id,
      revisionDate: _rev,
      creationDate: _created,
      deletedDate: _deleted,
      object: _object,
      edit: _edit,
      viewPassword: _view,
      permissions: _perm,
      collectionIds: _collections,
      attachments: _attachments,
      organizationUseTotp: _orgTotp,
      data: _legacy,
      ...passthrough
    } = c as CipherDto & Record<string, unknown>;
    const req: CipherRequest = {
      ...(passthrough as Partial<CipherRequest>),
      type: c.type,
      folderId: c.folderId,
      // An edit never moves an item in or out of its organization.
      organizationId: c.organizationId ?? null,
      name: c.name,
      notes: c.notes,
      fields: c.fields ?? [],
      favorite: c.favorite ?? false,
      reprompt: c.reprompt ?? 0,
      key: c.key ?? null,
      // The server replaces the history with whatever the request carries, so
      // it must always be sent back.
      passwordHistory: c.passwordHistory ?? null,
      lastKnownRevisionDate: c.revisionDate,
    };
    if (record.valueField !== null) {
      // The value lives in the obsidian:password field; the rest of the item is untouched.
      req.fields = req.fields.map((f, i) => (i === record.valueField ? { ...f, value: encValue } : f));
    } else if (c.type === CipherType.Login) {
      const previous = c.login?.password as string | null | undefined;
      if (previous) {
        // Like the official clients: keep the replaced password, newest first, at most 5.
        req.passwordHistory = [{ password: previous, lastUsedDate: now.toISOString() }, ...(c.passwordHistory ?? [])].slice(
          0,
          5,
        );
      }
      req.login = { ...(c.login ?? {}), password: encValue, passwordRevisionDate: now.toISOString() };
    } else {
      req.notes = encValue;
      req.secureNote = c.secureNote ?? { type: 0 };
    }
    return req;
  } finally {
    if (key !== ownerKey) key.wipe();
  }
}
