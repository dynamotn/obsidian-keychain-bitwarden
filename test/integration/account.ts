// Creates a throwaway account on a test Vaultwarden and fetches its personal
// API key, using the same client-side crypto a real client would.

import {
  decryptString,
  deriveMasterKey,
  encryptBytes,
  encryptString,
  hashMasterPassword,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  unwrapKey,
  wrapKey,
  type KdfParams,
  type KeyAlgorithm,
} from "../../src/bw/crypto";
import { fromBase64, toBase64 } from "../../src/bw/encoding";

export interface TestAccount {
  email: string;
  password: string;
  clientId: string;
  clientSecret: string;
  /** What a web vault session holds; used to set up organizations like a real client would. */
  userId: string;
  accessToken: string;
  userKey: SymmetricKey;
  publicKey: string;
}

async function post(url: string, body: string, headers: Record<string, string>) {
  const res = await fetch(url, { method: "POST", body, headers });
  const text = await res.text();
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

export async function registerAccount(
  serverUrl: string,
  kdf: KdfParams = { type: KdfType.PBKDF2, iterations: 600_000 },
  /** A COSE algorithm makes an account on the newer ("v2") encryption. */
  userKeyAlgorithm: KeyAlgorithm = "aes256-cbc-hmac",
): Promise<TestAccount> {
  const email = `it-${crypto.randomUUID().slice(0, 8)}@example.com`;
  const password = `pw ${crypto.randomUUID()} ✓`;
  const masterKey = await deriveMasterKey(password, email, kdf);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await SymmetricKey.generate(userKeyAlgorithm);
  const hash = await hashMasterPassword(masterKey, password);

  const rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKey = toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey)));
  const privateKey = await encryptBytes(new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey)), userKey, "pkcs8");

  const kdfFields =
    kdf.type === KdfType.Argon2id
      ? { kdf: 1, kdfIterations: kdf.iterations, kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism }
      : { kdf: 0, kdfIterations: kdf.iterations };
  // Vaultwarden 1.34+ uses the two-step registration; without a mail server the
  // first step hands the verification token straight back.
  const verify = await fetch(`${serverUrl}/identity/accounts/register/send-verification-email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, name: "integration test", receiveMarketingEmails: false }),
  });
  const emailVerificationToken = (await verify.text()).replace(/^"|"$/g, "");
  if (!verify.ok) throw new Error(`send-verification-email: HTTP ${verify.status}`);
  await post(
    `${serverUrl}/identity/accounts/register/finish`,
    JSON.stringify({
      email,
      emailVerificationToken,
      masterPasswordHash: hash,
      masterPasswordHint: null,
      userSymmetricKey: await wrapKey(userKey, stretched),
      userAsymmetricKeys: { publicKey, encryptedPrivateKey: privateKey },
      ...kdfFields,
    }),
    { "Content-Type": "application/json" },
  );

  const token = await post(
    `${serverUrl}/identity/connect/token`,
    new URLSearchParams({
      grant_type: "password",
      username: email,
      password: hash,
      scope: "api offline_access",
      client_id: "web",
      deviceType: "9",
      deviceIdentifier: crypto.randomUUID(),
      deviceName: "integration-test",
    }).toString(),
    { "Content-Type": "application/x-www-form-urlencoded" },
  );
  const key = await post(`${serverUrl}/api/accounts/api-key`, JSON.stringify({ masterPasswordHash: hash }), {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token.access_token}`,
  });
  const userId = JSON.parse(atob(token.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub;
  return {
    email,
    password,
    clientId: `user.${userId}`,
    clientSecret: key.apiKey ?? key.ApiKey,
    userId,
    accessToken: token.access_token,
    userKey,
    publicKey,
  };
}

async function api(account: TestAccount, serverUrl: string, method: string, path: string, body?: unknown) {
  const res = await fetch(`${serverUrl}/api${path}`, {
    method,
    headers: { Authorization: `Bearer ${account.accessToken}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

export interface TestOrganization {
  id: string;
  key: SymmetricKey;
  collectionId: string;
}

/** Creates an organization owned by the account, the way the web vault does. */
export async function createOrganization(serverUrl: string, account: TestAccount): Promise<TestOrganization> {
  const key = await SymmetricKey.generate();
  const pub = await crypto.subtle.importKey("spki", fromBase64(account.publicKey), { name: "RSA-OAEP", hash: "SHA-1" }, false, [
    "encrypt",
  ]);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, key.exportBytes()));
  const orgRsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const org = await api(account, serverUrl, "POST", "/organizations", {
    name: "Integration team",
    billingEmail: account.email,
    planType: 0,
    key: `4.${toBase64(wrapped)}`,
    collectionName: await encryptString("Default collection", key),
    keys: {
      publicKey: toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", orgRsa.publicKey))),
      encryptedPrivateKey: await encryptBytes(new Uint8Array(await crypto.subtle.exportKey("pkcs8", orgRsa.privateKey)), key, "pkcs8"),
    },
  });
  const collections = await api(account, serverUrl, "GET", `/organizations/${org.id}/collections`);
  return { id: org.id, key, collectionId: collections.data[0].id };
}

/** Creates a personal folder and returns its id. */
export async function createFolder(serverUrl: string, account: TestAccount, name: string): Promise<string> {
  return (await api(account, serverUrl, "POST", "/folders", { name: await encryptString(name, account.userKey) })).id;
}

/** Creates a secure note owned by the organization, filed in one of the account's folders. */
export async function createOrganizationNote(
  serverUrl: string,
  account: TestAccount,
  org: TestOrganization,
  folderId: string,
  name: string,
  value: string,
): Promise<string> {
  const cipher = await api(account, serverUrl, "POST", "/ciphers/create", {
    cipher: {
      type: 2,
      organizationId: org.id,
      folderId,
      name: await encryptString(name, org.key),
      notes: await encryptString(value, org.key),
      fields: [],
      favorite: false,
      reprompt: 0,
      key: null,
      secureNote: { type: 0 },
      encryptedFor: account.userId,
    },
    collectionIds: [org.collectionId],
  });
  return cipher.id;
}

/** Reads an item's note as another organization member would: straight from the server, with the organization key. */
export async function readOrganizationNote(
  serverUrl: string,
  account: TestAccount,
  org: TestOrganization,
  cipherId: string,
): Promise<{ organizationId: string | null; notes: string }> {
  const c = await api(account, serverUrl, "GET", `/ciphers/${cipherId}`);
  const key = c.key ? await unwrapKey(c.key, org.key) : org.key;
  return { organizationId: c.organizationId, notes: await decryptString(c.notes, key) };
}
