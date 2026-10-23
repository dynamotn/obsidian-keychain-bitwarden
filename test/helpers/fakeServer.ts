// In-memory stand-in for the parts of the Bitwarden server the plugin uses.
// Behaves like the real one where it matters: revision checks on update,
// soft delete, server-assigned ids and revision dates.

import type { CipherDto, CipherRequest, FolderDto, OrganizationDto } from "../../src/bw/api";
import {
  deriveMasterKey,
  encryptBytes,
  encryptString,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  unwrapKey,
  wrapKey,
  type KdfParams,
  type KeyAlgorithm,
} from "../../src/bw/crypto";
import { toBase64, utf8Encode } from "../../src/bw/encoding";
import type { HttpClient, HttpRequest } from "../../src/bw/http";

export const SERVER = "https://bw.test";

/** Legacy account keys, and both kinds of COSE ("v2") account keys Bitwarden creates. */
export const ACCOUNT_KINDS = ["aes256-cbc-hmac", "xaes256gcm", "xchacha20poly1305"] as const satisfies readonly KeyAlgorithm[];

export interface Account {
  email: string;
  password: string;
  clientId: string;
  clientSecret: string;
  userKey: SymmetricKey;
}

export class FakeBitwardenServer {
  folders: FolderDto[] = [];
  ciphers: CipherDto[] = [];
  organizations: OrganizationDto[] = [];
  /** Organization keys by id, as the organization's members hold them. */
  readonly orgKeys = new Map<string, SymmetricKey>();
  /** Real RSA key pair, made on first use: only organization tests need one. */
  private rsa: CryptoKeyPair | null = null;
  requests: HttpRequest[] = [];
  private tokens = new Set<string>();
  private clock = Date.parse("2026-01-01T00:00:00Z");
  /** Runs before an update is applied; lets tests simulate a concurrent edit. */
  beforeUpdate: ((id: string) => void) | null = null;

  private constructor(
    readonly account: Account,
    private readonly kdf: KdfParams,
    private readonly protectedKey: string,
    private privateKey: string,
    private readonly shape: { newSyncShape: boolean; salt?: string } = { newSyncShape: false },
  ) {}

  /**
   * `userKey` picks the account's encryption: legacy keys, or a COSE ("v2")
   * account key. `newSyncShape` answers sync like newer servers do, with the
   * keys in `userDecryption` and `accountKeys` only, and `salt` gives the
   * master key a salt other than the email.
   */
  static async create(
    kdf: KdfParams = { type: KdfType.PBKDF2, iterations: 5000 },
    {
      userKey: userKeyAlgorithm = "aes256-cbc-hmac",
      newSyncShape = false,
      salt,
    }: { userKey?: KeyAlgorithm; newSyncShape?: boolean; salt?: string } = {},
  ): Promise<FakeBitwardenServer> {
    const email = "user@example.com";
    const password = "master password";
    const userKey = await SymmetricKey.generate(userKeyAlgorithm);
    const stretched = await stretchMasterKey(await deriveMasterKey(password, salt ?? email, kdf));
    const protectedKey = await wrapKey(userKey, stretched);
    const privateKey = await encryptBytes(utf8Encode("not really a private key"), userKey, "pkcs8");
    return new FakeBitwardenServer(
      { email, password, clientId: "user.1234", clientSecret: "s3cret", userKey },
      kdf,
      protectedKey,
      privateKey,
      { newSyncShape, salt },
    );
  }

  nextRevision(): string {
    this.clock += 1000;
    return new Date(this.clock).toISOString();
  }

  /**
   * Adds an organization this account is a confirmed member of. Its key is
   * wrapped to the account's public key with RSA-OAEP, as Bitwarden does:
   * EncString type 4 (SHA-1) or 3 (SHA-256).
   */
  async addOrganization(opts: { keyType?: 3 | 4; key?: string | null } = {}): Promise<string> {
    if (!this.rsa) {
      this.rsa = await crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
        true,
        ["encrypt", "decrypt"],
      );
      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", this.rsa.privateKey));
      this.privateKey = await encryptBytes(pkcs8, this.account.userKey, "pkcs8");
    }
    const id = `org-${this.organizations.length + 1}`;
    const orgKey = await SymmetricKey.generate();
    this.orgKeys.set(id, orgKey);
    const type = opts.keyType ?? 4;
    const spki = await crypto.subtle.exportKey("spki", this.rsa.publicKey);
    const pub = await crypto.subtle.importKey("spki", spki, { name: "RSA-OAEP", hash: type === 4 ? "SHA-1" : "SHA-256" }, false, [
      "encrypt",
    ]);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, orgKey.exportBytes()));
    this.organizations.push({ id, key: opts.key === undefined ? `${type}.${toBase64(wrapped)}` : opts.key, enabled: true });
    return id;
  }

  /** The key an item is encrypted under: its organization's, or the user key. */
  async ownerKey(cipher: Pick<CipherDto, "organizationId">): Promise<SymmetricKey> {
    return cipher.organizationId ? this.orgKeys.get(cipher.organizationId)! : this.account.userKey;
  }

  /** Adds an item the way another Bitwarden client would. */
  async addItem(opts: {
    folder: string;
    name: string;
    value: string;
    type?: 1 | 2;
    id?: string;
    scope?: string;
    itemKey?: boolean;
    /** Makes it an item of this organization, encrypted with the organization's key. */
    organization?: string;
    edit?: boolean;
    viewPassword?: boolean;
  }): Promise<CipherDto> {
    const folderId = this.folders.find((f) => f.id === opts.folder)?.id ?? (await this.addFolder(opts.folder)).id;
    const ownerKey = await this.ownerKey({ organizationId: opts.organization ?? null });
    let key = ownerKey;
    let wrappedKey: string | null = null;
    if (opts.itemKey) {
      key = await SymmetricKey.generate();
      wrappedKey = await wrapKey(key, ownerKey);
    }
    const fields = [];
    if (opts.id) fields.push({ type: 0, name: await encryptString("obsidian-id", key), value: await encryptString(opts.id, key) });
    if (opts.scope) {
      fields.push({ type: 0, name: await encryptString("obsidian-scope", key), value: await encryptString(opts.scope, key) });
    }
    fields.push({ type: 1, name: await encryptString("unrelated", key), value: await encryptString("keep me", key) });
    const encValue = await encryptString(opts.value, key);
    const type = opts.type ?? 2;
    const cipher: CipherDto = {
      id: crypto.randomUUID(),
      type,
      folderId,
      organizationId: opts.organization ?? null,
      name: await encryptString(opts.name, key),
      notes: type === 2 ? encValue : await encryptString("login notes", key),
      fields,
      login: type === 1 ? { username: await encryptString("me", key), password: encValue, uris: [] } : null,
      secureNote: type === 2 ? { type: 0 } : null,
      key: wrappedKey,
      revisionDate: this.nextRevision(),
      deletedDate: null,
      ...(opts.organization ? { edit: opts.edit ?? true, viewPassword: opts.viewPassword ?? true } : {}),
    };
    this.ciphers.push(cipher);
    return cipher;
  }

  async addFolder(name: string): Promise<FolderDto> {
    const folder = { id: name, name: await encryptString(name, this.account.userKey) };
    this.folders.push(folder);
    return folder;
  }

  async editValue(cipherId: string, value: string): Promise<void> {
    const c = this.ciphers.find((x) => x.id === cipherId)!;
    let key = await this.ownerKey(c);
    if (c.key) key = await unwrapKey(c.key, key);
    const enc = await encryptString(value, key);
    if (c.type === 1) c.login = { ...c.login, password: enc };
    else c.notes = enc;
    c.revisionDate = this.nextRevision();
  }

  readonly http: HttpClient = async (req) => {
    this.requests.push(req);
    const url = new URL(req.url);
    const json = (status: number, body: unknown) => ({ status, text: JSON.stringify(body) });
    const path = url.pathname;

    if (path === "/identity/accounts/prelogin") {
      const k = this.kdf;
      return json(200, {
        Kdf: k.type,
        KdfIterations: k.iterations,
        KdfMemory: k.type === KdfType.Argon2id ? k.memory : null,
        KdfParallelism: k.type === KdfType.Argon2id ? k.parallelism : null,
      });
    }
    if (path === "/identity/connect/token") {
      const form = new URLSearchParams(req.body);
      if (
        form.get("grant_type") !== "client_credentials" ||
        form.get("client_id") !== this.account.clientId ||
        form.get("client_secret") !== this.account.clientSecret ||
        !form.get("deviceIdentifier")
      ) {
        return json(400, { error: "invalid_client", error_description: "invalid client" });
      }
      const token = crypto.randomUUID();
      this.tokens.add(token);
      return json(200, { access_token: token, expires_in: 3600, token_type: "Bearer" });
    }

    const auth = req.headers?.Authorization?.replace(/^Bearer /, "");
    if (!auth || !this.tokens.has(auth)) return json(401, { message: "Unauthorized" });
    const body = req.body ? (JSON.parse(req.body) as CipherRequest) : null;
    if (body && path.startsWith("/api/ciphers") && body.encryptedFor !== "u1") {
      return json(422, { message: "missing field `encryptedFor`" });
    }

    if (path === "/api/sync" && req.method === "GET") {
      return json(200, {
        profile: this.shape.newSyncShape
          ? {
              id: "u1",
              email: this.account.email,
              accountKeys: { publicKeyEncryptionKeyPair: { wrappedPrivateKey: this.privateKey } },
              organizations: this.organizations,
            }
          : {
              id: "u1",
              email: this.account.email,
              key: this.protectedKey,
              privateKey: this.privateKey,
              organizations: this.organizations,
            },
        ...(this.shape.newSyncShape
          ? {
              userDecryption: {
                masterPasswordUnlock: { masterKeyEncryptedUserKey: this.protectedKey, salt: this.shape.salt ?? this.account.email },
              },
            }
          : {}),
        folders: this.folders,
        ciphers: this.ciphers,
      });
    }
    if (path === "/api/folders" && req.method === "POST") {
      const folder = { id: crypto.randomUUID(), name: (body as unknown as { name: string }).name };
      this.folders.push(folder);
      return json(200, folder);
    }
    if (path === "/api/ciphers" && req.method === "POST") {
      const cipher = { ...this.toCipher(body!), id: crypto.randomUUID(), revisionDate: this.nextRevision() };
      this.ciphers.push(cipher);
      return json(200, cipher);
    }
    const del = path.match(/^\/api\/ciphers\/([^/]+)\/delete$/);
    if (del && req.method === "PUT") {
      const c = this.ciphers.find((x) => x.id === del[1]);
      if (!c) return json(404, { message: "Not found" });
      c.deletedDate = this.nextRevision();
      c.revisionDate = c.deletedDate;
      return { status: 200, text: "" };
    }
    const upd = path.match(/^\/api\/ciphers\/([^/]+)$/);
    if (upd && req.method === "PUT") {
      this.beforeUpdate?.(upd[1]!);
      const idx = this.ciphers.findIndex((x) => x.id === upd[1]);
      if (idx < 0) return json(404, { message: "Not found" });
      const current = this.ciphers[idx]!;
      // Like the real server: an edit cannot move an item between owners, and
      // needs edit rights in its organization.
      if ((body!.organizationId ?? null) !== (current.organizationId ?? null)) {
        return json(400, { message: "The organization of an item cannot be changed this way." });
      }
      if (current.edit === false) return json(400, { message: "You do not have permissions to edit this." });
      if (body!.lastKnownRevisionDate && body!.lastKnownRevisionDate !== current.revisionDate) {
        return json(400, {
          message: "The model state is invalid.",
          validationErrors: {
            "": ["The cipher you are updating is out of date. Please save your work, sync your vault, and try again."],
          },
        });
      }
      const next: CipherDto = {
        ...this.toCipher(body!),
        id: current.id,
        revisionDate: this.nextRevision(),
        // Computed by the server from the user's rights, not sent by clients.
        ...(current.organizationId ? { edit: current.edit, viewPassword: current.viewPassword } : {}),
      };
      this.ciphers[idx] = next;
      return json(200, next);
    }
    return json(404, { message: `No route ${req.method} ${path}` });
  };

  private toCipher(req: CipherRequest): CipherDto {
    const { lastKnownRevisionDate: _ignored, encryptedFor: _owner, ...rest } = req;
    return { ...rest, id: "", revisionDate: "", deletedDate: null, fields: req.fields ?? [] } as CipherDto;
  }
}
