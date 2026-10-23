// In-memory stand-in for the parts of the Bitwarden server the plugin uses.
// Behaves like the real one where it matters: revision checks on update,
// soft delete, server-assigned ids and revision dates.

import type { CipherDto, CipherRequest, FolderDto } from "../../src/bw/api";
import {
  deriveMasterKey,
  encryptBytes,
  encryptString,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  type KdfParams,
} from "../../src/bw/crypto";
import type { HttpClient, HttpRequest } from "../../src/bw/http";

export const SERVER = "https://bw.test";

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
  requests: HttpRequest[] = [];
  private tokens = new Set<string>();
  private clock = Date.parse("2026-01-01T00:00:00Z");
  /** Runs before an update is applied; lets tests simulate a concurrent edit. */
  beforeUpdate: ((id: string) => void) | null = null;

  private constructor(
    readonly account: Account,
    private readonly kdf: KdfParams,
    private readonly protectedKey: string,
    private readonly privateKey: string,
  ) {}

  static async create(kdf: KdfParams = { type: KdfType.PBKDF2, iterations: 5000 }): Promise<FakeBitwardenServer> {
    const email = "user@example.com";
    const password = "master password";
    const userKey = await SymmetricKey.generate();
    const stretched = await stretchMasterKey(await deriveMasterKey(password, email, kdf));
    const protectedKey = await encryptBytes(userKey.exportBytes(), stretched);
    const privateKey = await encryptString("not really a private key", userKey);
    return new FakeBitwardenServer(
      { email, password, clientId: "user.1234", clientSecret: "s3cret", userKey },
      kdf,
      protectedKey,
      privateKey,
    );
  }

  nextRevision(): string {
    this.clock += 1000;
    return new Date(this.clock).toISOString();
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
  }): Promise<CipherDto> {
    const folderId = this.folders.find((f) => f.id === opts.folder)?.id ?? (await this.addFolder(opts.folder)).id;
    const userKey = this.account.userKey;
    let key = userKey;
    let wrappedKey: string | null = null;
    if (opts.itemKey) {
      key = await SymmetricKey.generate();
      wrappedKey = await encryptBytes(key.exportBytes(), userKey);
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
      organizationId: null,
      name: await encryptString(opts.name, key),
      notes: type === 2 ? encValue : await encryptString("login notes", key),
      fields,
      login: type === 1 ? { username: await encryptString("me", key), password: encValue, uris: [] } : null,
      secureNote: type === 2 ? { type: 0 } : null,
      key: wrappedKey,
      revisionDate: this.nextRevision(),
      deletedDate: null,
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
    let key = this.account.userKey;
    if (c.key) {
      const { decryptBytes } = await import("../../src/bw/crypto");
      key = await SymmetricKey.fromBytes(await decryptBytes(c.key, key));
    }
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
        profile: { id: "u1", email: this.account.email, key: this.protectedKey, privateKey: this.privateKey },
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
      if (body!.lastKnownRevisionDate && body!.lastKnownRevisionDate !== current.revisionDate) {
        return json(400, {
          message: "The model state is invalid.",
          validationErrors: {
            "": ["The cipher you are updating is out of date. Please save your work, sync your vault, and try again."],
          },
        });
      }
      const next = { ...this.toCipher(body!), id: current.id, revisionDate: this.nextRevision() };
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
