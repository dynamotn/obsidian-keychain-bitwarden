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
/** `notes` when the plugin moved a value too long for a field into the notes. */
export const FIELD_LOCATION = "obsidian:location";
/**
 * Not implemented: secret storage holds text only, so an item storing base64
 * of binary data is skipped, never misread.
 */
const FIELD_ENCODING = "obsidian:encoding";

/** Bitwarden's limits, in encrypted characters, for a field value or login password, and for the notes. */
export const FIELD_LIMIT = 5_000;
export const NOTES_LIMIT = 10_000;

/** A value too long for the place it has to go; the message never contains the value. */
export class ValueTooLongError extends Error {
  override name = "ValueTooLongError";
}

/** Where a marked item's value lives, in the order of the dybw data model. */
export type ValueSource =
  /** `obsidian:password`; every index lists the field and its duplicates, the first holds the value. */
  | { kind: "field"; indexes: number[] }
  /** The notes, which hold this plugin's value (`obsidian:location=notes`). */
  | { kind: "notes" }
  /** The user's own login password, or the secure note's own text. */
  | { kind: "default" };

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
  source: ValueSource;
  /** Indexes of every `obsidian:location` field, whatever its value; the first one counts. */
  locationFields: number[];
  /** `notes` only when that field says the notes hold this plugin's value; an empty field claims nothing. */
  location: "notes" | null;
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
    // Blob-encrypted items keep name and fields inside `data`, which cannot be read yet: hold, never a record.
    if (isBlobCipher(cipher)) {
      present.add(cipher.id);
      continue;
    }
    const ownerKey = cipher.organizationId && !orgKeys ? undefined : ownerKeyFor(cipher, userKey, orgKeys);
    if (!ownerKey) {
      present.add(cipher.id);
      continue;
    }
    let key = ownerKey;
    try {
      let fields: Map<string, ToolField>;
      let id: string;
      try {
        key = await itemKeyFor(cipher, ownerKey);
        fields = await obsidianFields(cipher, key);
        const idField = fields.get(FIELD_ID);
        id = idField ? ((await decryptField(idField.value, key)) ?? "").trim() : "";
      } catch {
        present.add(cipher.id);
        continue;
      }
      // A missing or blank obsidian:id leaves the item unmarked (data model §2, §4).
      if (id === "") continue;
      present.add(cipher.id);
      if (cipher.type !== CipherType.SecureNote && cipher.type !== CipherType.Login) {
        skipped.push({ cipherId: cipher.id, reason: "only login and secure note items are synced" });
        continue;
      }
      if (cipher.organizationId && cipher.viewPassword === false) {
        skipped.push({ cipherId: cipher.id, reason: "the organization hides this item's password from you" });
        continue;
      }
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
      // A blank obsidian:encoding means no encoding (data model §3.2).
      const encodingField = fields.get(FIELD_ENCODING);
      if (encodingField && ((await decryptField(encodingField.value, key)) ?? "").trim() !== "") {
        skipped.push({ cipherId: cipher.id, reason: `"${FIELD_ENCODING}" is not supported by this plugin` });
        continue;
      }
      const locationField = fields.get(FIELD_LOCATION) ?? null;
      const location = locationField ? ((await decryptField(locationField.value, key)) ?? "").trim() : "";
      if (location !== "" && location !== "notes") {
        skipped.push({ cipherId: cipher.id, reason: `unknown "${FIELD_LOCATION}" value` });
        continue;
      }
      const passwordField = fields.get(FIELD_PASSWORD);
      const source: ValueSource = passwordField
        ? { kind: "field", indexes: passwordField.indexes }
        : location === "notes"
          ? { kind: "notes" }
          : { kind: "default" };
      const rawValue =
        source.kind === "field"
          ? passwordField!.value
          : source.kind === "notes" || cipher.type === CipherType.SecureNote
            ? cipher.notes
            : (cipher.login?.password as string | null | undefined);
      const value = (await decryptField(rawValue, key)) ?? "";
      records.push({
        id,
        cipherId: cipher.id,
        revisionDate: cipher.revisionDate,
        label: (await decryptField(cipher.name, key)) ?? "",
        value,
        scope,
        source,
        locationFields: locationField?.indexes ?? [],
        location: location === "notes" ? "notes" : null,
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

/**
 * Mirrors the gate in bitwarden-vault/src/cipher/blob/sealed.rs `from_opaque_string` (sdk-internal 3d16437):
 * `data` parses as a JSON object with its own `format_version` key (`hasOwn`, like serde's `contains_key`;
 * `in` would trust a prototype another plugin set). The SDK's struct deserialization step is skipped on
 * purpose, so a malformed object with `format_version` is held too: the SDK cannot read it either.
 */
function isBlobCipher(cipher: CipherDto): boolean {
  if (!cipher.data) return false;
  try {
    const d: unknown = JSON.parse(cipher.data);
    return typeof d === "object" && d !== null && !Array.isArray(d) && Object.hasOwn(d, "format_version");
  } catch {
    return false;
  }
}

interface ToolField {
  /** The first field of that name, which counts. */
  index: number;
  /** Still encrypted. */
  value: string | null | undefined;
  /** Every field of that name, the first included. */
  indexes: number[];
}

/** The `obsidian:*` custom fields of an item by name; the first of duplicates counts. */
async function obsidianFields(cipher: CipherDto, key: SymmetricKey): Promise<Map<string, ToolField>> {
  const found = new Map<string, ToolField>();
  const list = cipher.fields ?? [];
  for (let index = 0; index < list.length; index++) {
    const f = list[index]!;
    const name = await decryptField(f.name, key);
    if (!name?.startsWith("obsidian:")) continue;
    const seen = found.get(name);
    if (seen) seen.indexes.push(index);
    else found.set(name, { index, value: f.value, indexes: [index] });
  }
  return found;
}

function checkLength(enc: string | null, limit: number, place: string) {
  const length = enc?.length ?? 0;
  if (length > limit) {
    throw new ValueTooLongError(
      `the value is too long for ${place}: ${length.toLocaleString("en")} encrypted characters, ` +
        `at most ${limit.toLocaleString("en")} fit`,
    );
  }
}

async function locationField(key: SymmetricKey): Promise<FieldDto> {
  return { type: 0, name: await encryptString(FIELD_LOCATION, key), value: await encryptString("notes", key) };
}

/**
 * Builds a request for a new secure note holding one secret. The value goes
 * into an `obsidian:password` field, never the user's notes. A value too long
 * for a field goes into the (still empty) notes with `obsidian:location=notes`.
 */
export async function newSecretRequest(
  userKey: SymmetricKey,
  folderId: string | null,
  id: string,
  value: string,
  scope: Scope,
): Promise<CipherRequest> {
  const enc = value === "" ? null : await encryptString(value, userKey);
  const inNotes = (enc?.length ?? 0) > FIELD_LIMIT;
  if (inNotes) checkLength(enc, NOTES_LIMIT, "the notes");
  const fields: FieldDto[] = [
    { type: 0, name: await encryptString(FIELD_ID, userKey), value: await encryptString(id, userKey) },
    inNotes ? await locationField(userKey) : { type: 1, name: await encryptString(FIELD_PASSWORD, userKey), value: enc },
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
    notes: inNotes ? enc : null,
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
      // A marked item always has fields: its obsidian:id is one of them.
      fields: c.fields!,
      favorite: c.favorite ?? false,
      reprompt: c.reprompt ?? 0,
      key: c.key ?? null,
      // The server replaces the history with whatever the request carries, so
      // it must always be sent back.
      passwordHistory: c.passwordHistory ?? null,
      lastKnownRevisionDate: c.revisionDate,
    };
    const source = record.source;
    if (source.kind === "field") {
      if ((encValue?.length ?? 0) <= FIELD_LIMIT) {
        // The value lives in the obsidian:password field; the rest of the item is untouched.
        req.fields = req.fields.map((f, i) => (i === source.indexes[0] ? { ...f, value: encValue } : f));
        if (record.location === "notes") {
          // The notes are marked as this plugin's, so they hold an older copy of the secret: drop it and the mark.
          req.notes = null;
          req.fields = req.fields.filter((_, i) => !record.locationFields.includes(i));
        }
      } else {
        // Too long for a field: the notes may take it only if they hold nothing of the user's.
        // Decrypted, since empty notes ("") still encrypt to a non-empty string (data model §6.4).
        if (record.location !== "notes" && (await decryptField(c.notes, key))) {
          throw new ValueTooLongError(
            `the value is too long for a field (${encValue!.length.toLocaleString("en")} encrypted characters, ` +
              `at most ${FIELD_LIMIT.toLocaleString("en")}), and the notes hold your own text`,
          );
        }
        checkLength(encValue, NOTES_LIMIT, "the notes");
        req.notes = encValue;
        // Every obsidian:password goes, or a duplicate would become the value
        // source; so does every obsidian:location but the first, which is set.
        const [first, ...duplicates] = record.locationFields;
        const kept = req.fields.filter((_, i) => !source.indexes.includes(i) && !duplicates.includes(i));
        if (first === undefined) kept.push(await locationField(key));
        else kept[kept.indexOf(req.fields[first]!)] = await locationField(key);
        req.fields = kept;
      }
    } else if (source.kind === "notes") {
      checkLength(encValue, NOTES_LIMIT, "the notes");
      req.notes = encValue;
    } else if (c.type === CipherType.Login) {
      checkLength(encValue, FIELD_LIMIT, "a login password");
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
      checkLength(encValue, NOTES_LIMIT, "the notes");
      req.notes = encValue;
      req.secureNote = c.secureNote ?? { type: 0 };
    }
    return req;
  } finally {
    if (key !== ownerKey) key.wipe();
  }
}
