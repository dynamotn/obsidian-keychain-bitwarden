import type { HttpClient } from "./http";
import { KdfType, type KdfParams } from "./crypto";

export interface ServerUrls {
  api: string;
  identity: string;
}

/** Maps what a user types (vault URL) to the API and identity endpoints. */
export function resolveServerUrls(serverUrl: string): ServerUrls {
  const raw = serverUrl.trim() || "https://vault.bitwarden.com";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid server URL: ${raw}`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("The server URL must use https:// (plain http is only allowed for localhost)");
  }
  if (url.username || url.password) throw new Error("The server URL must not contain credentials");
  const host = url.hostname;
  if (host === "vault.bitwarden.com" || host === "bitwarden.com") {
    return { api: "https://api.bitwarden.com", identity: "https://identity.bitwarden.com" };
  }
  if (host === "vault.bitwarden.eu" || host === "bitwarden.eu") {
    return { api: "https://api.bitwarden.eu", identity: "https://identity.bitwarden.eu" };
  }
  const base = `${url.origin}${url.pathname}`.replace(/\/+$/, "");
  return { api: `${base}/api`, identity: `${base}/identity` };
}

export class BitwardenApiError extends Error {
  override name = "BitwardenApiError";
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }

  /** The server rejected an edit because the item changed on another device. */
  get isOutOfDate(): boolean {
    return this.status === 400 && /out of date/i.test(this.message);
  }
}

// --- Wire types (camelCase after normalisation) -----------------------------

export interface FieldDto {
  type: number;
  name: string | null;
  value: string | null;
  linkedId?: number | null;
}

export interface CipherDto {
  id: string;
  type: number;
  folderId: string | null;
  organizationId: string | null;
  name: string;
  notes: string | null;
  fields: FieldDto[] | null;
  login?: Record<string, unknown> | null;
  secureNote?: { type: number } | null;
  key?: string | null;
  passwordHistory?: PasswordHistoryDto[] | null;
  favorite?: boolean;
  reprompt?: number;
  revisionDate: string;
  deletedDate?: string | null;
  /** Organization items only: false when the user may not change the item. */
  edit?: boolean;
  /** Organization items only: false when the organization hides the password from this user. */
  viewPassword?: boolean;
}

export interface PasswordHistoryDto {
  password: string;
  lastUsedDate: string;
}

export interface FolderDto {
  id: string;
  name: string;
}

export interface OrganizationDto {
  id: string;
  /** The organization key, RSA-encrypted to this account; absent until the membership is confirmed. */
  key?: string | null;
  enabled?: boolean;
}

export interface SyncDto {
  profile: {
    id: string;
    email: string;
    key: string;
    privateKey?: string | null;
    organizations?: OrganizationDto[] | null;
  };
  folders: FolderDto[];
  ciphers: CipherDto[];
}

export interface CipherRequest {
  type: number;
  folderId: string | null;
  /** Kept as is on edits; new items are always personal. */
  organizationId: string | null;
  name: string;
  notes: string | null;
  fields: FieldDto[];
  favorite: boolean;
  reprompt: number;
  key: string | null;
  login?: Record<string, unknown> | null;
  secureNote?: { type: number } | null;
  passwordHistory?: PasswordHistoryDto[] | null;
  lastKnownRevisionDate?: string;
  /** Account the item is encrypted for. Required by Vaultwarden 1.37+, optional on bitwarden.com. */
  encryptedFor?: string;
}

export interface Session {
  accessToken: string;
  expiresAt: number;
}

export interface ApiCredentials {
  clientId: string;
  clientSecret: string;
}

export interface DeviceInfo {
  identifier: string;
  name: string;
}

// DeviceType.SDK in the Bitwarden server enum.
const DEVICE_TYPE = "21";
const CLIENT_NAME = "obsidian-keychain-bitwarden";
const CLIENT_VERSION = "0.1.0";

/** Bitwarden used to answer in PascalCase; newer servers use camelCase. Accept both. */
export function normalizeKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k.charAt(0).toLowerCase() + k.slice(1)] = normalizeKeys(v);
    return out;
  }
  return value;
}

export class BitwardenApi {
  private session: Session | null = null;
  /** Account id, learnt from the last sync. */
  private userId: string | null = null;

  constructor(
    readonly urls: ServerUrls,
    private readonly http: HttpClient,
    private readonly device: DeviceInfo,
    private readonly now: () => number = Date.now,
  ) {}

  private commonHeaders(): Record<string, string> {
    return {
      "Bitwarden-Client-Name": CLIENT_NAME,
      "Bitwarden-Client-Version": CLIENT_VERSION,
      "Device-Type": DEVICE_TYPE,
    };
  }

  private async send(
    url: string,
    method: "GET" | "POST" | "PUT" | "DELETE",
    body: string | undefined,
    headers: Record<string, string>,
  ): Promise<unknown> {
    const res = await this.http({ url, method, body, headers: { ...this.commonHeaders(), ...headers } });
    let parsed: unknown = undefined;
    if (res.text) {
      try {
        parsed = normalizeKeys(JSON.parse(res.text));
      } catch {
        parsed = undefined;
      }
    }
    if (res.status < 200 || res.status >= 300) {
      throw new BitwardenApiError(res.status, describeError(res.status, parsed));
    }
    return parsed;
  }

  async prelogin(email: string): Promise<KdfParams> {
    const res = (await this.send(
      `${this.urls.identity}/accounts/prelogin`,
      "POST",
      JSON.stringify({ email }),
      { "Content-Type": "application/json" },
    )) as { kdf: number; kdfIterations: number; kdfMemory?: number | null; kdfParallelism?: number | null };
    if (res.kdf === KdfType.Argon2id) {
      return {
        type: KdfType.Argon2id,
        iterations: res.kdfIterations,
        memory: res.kdfMemory ?? 0,
        parallelism: res.kdfParallelism ?? 0,
      };
    }
    if (res.kdf === KdfType.PBKDF2) return { type: KdfType.PBKDF2, iterations: res.kdfIterations };
    throw new Error(`Unsupported KDF type from server: ${res.kdf}`);
  }

  /** Logs in with a personal API key. It authenticates only; decrypting still needs the master password. */
  async loginWithApiKey(creds: ApiCredentials): Promise<void> {
    const form = new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api",
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      deviceType: DEVICE_TYPE,
      deviceIdentifier: this.device.identifier,
      deviceName: this.device.name,
    });
    const res = (await this.send(`${this.urls.identity}/connect/token`, "POST", form.toString(), {
      "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    })) as { access_token?: string; expires_in?: number };
    if (!res?.access_token) throw new Error("The server did not return an access token");
    this.session = {
      accessToken: res.access_token,
      expiresAt: this.now() + Math.max(60, (res.expires_in ?? 3600) - 60) * 1000,
    };
  }

  get isLoggedIn(): boolean {
    return this.session !== null && this.session.expiresAt > this.now();
  }

  logout(): void {
    this.session = null;
    this.userId = null;
  }

  private async authed(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<unknown> {
    if (!this.isLoggedIn) throw new BitwardenApiError(401, "Not logged in");
    const headers: Record<string, string> = { Authorization: `Bearer ${this.session!.accessToken}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return this.send(`${this.urls.api}${path}`, method, body === undefined ? undefined : JSON.stringify(body), headers);
  }

  async sync(): Promise<SyncDto> {
    const res = (await this.authed("GET", "/sync?excludeDomains=true")) as SyncDto;
    if (!res?.profile?.key) throw new Error("Sync response has no account key");
    res.folders ??= [];
    res.ciphers ??= [];
    this.userId = res.profile.id;
    return res;
  }

  async createFolder(encryptedName: string): Promise<FolderDto> {
    return (await this.authed("POST", "/folders", { name: encryptedName })) as FolderDto;
  }

  private withOwner(req: CipherRequest): CipherRequest {
    if (!this.userId) throw new Error("internal: sync before writing items");
    return { ...req, encryptedFor: this.userId };
  }

  async createItem(req: CipherRequest): Promise<CipherDto> {
    return (await this.authed("POST", "/ciphers", this.withOwner(req))) as CipherDto;
  }

  async updateItem(id: string, req: CipherRequest): Promise<CipherDto> {
    return (await this.authed("PUT", `/ciphers/${encodeURIComponent(id)}`, this.withOwner(req))) as CipherDto;
  }

  /** Moves the item to the trash, where it can still be restored from any Bitwarden client. */
  async trashItem(id: string): Promise<void> {
    await this.authed("PUT", `/ciphers/${encodeURIComponent(id)}/delete`);
  }
}

/**
 * Server-provided text is untrusted: keep it short and mark it as coming from
 * the server, so a hostile server cannot pass off instructions as the plugin's.
 */
function describeError(status: number, body: unknown): string {
  const b = (body ?? {}) as Record<string, unknown>;
  const model = b.errorModel as Record<string, unknown> | undefined;
  const parts = [
    b.error_description,
    b.message,
    model?.message,
    b.validationErrors ? JSON.stringify(b.validationErrors) : undefined,
  ].filter((p): p is string => typeof p === "string" && p.length > 0);
  const text = parts.join(" ").replace(/\s+/g, " ");
  const clipped = text.length > 200 ? `${text.slice(0, 200)}…` : text;
  return `HTTP ${status}${clipped ? ` (server says: ${clipped})` : ""}`;
}
