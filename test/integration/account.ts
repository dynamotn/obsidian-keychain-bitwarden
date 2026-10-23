// Creates a throwaway account on a test Vaultwarden and fetches its personal
// API key, using the same client-side crypto a real client would.

import {
  deriveMasterKey,
  encryptBytes,
  hashMasterPassword,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  type KdfParams,
} from "../../src/bw/crypto";
import { toBase64 } from "../../src/bw/encoding";

export interface TestAccount {
  email: string;
  password: string;
  clientId: string;
  clientSecret: string;
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
): Promise<TestAccount> {
  const email = `it-${crypto.randomUUID().slice(0, 8)}@example.com`;
  const password = `pw ${crypto.randomUUID()} ✓`;
  const masterKey = await deriveMasterKey(password, email, kdf);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await SymmetricKey.generate();
  const hash = await hashMasterPassword(masterKey, password);

  const rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKey = toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey)));
  const privateKey = await encryptBytes(new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey)), userKey);

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
      userSymmetricKey: await encryptBytes(userKey.exportBytes(), stretched),
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
  return { email, password, clientId: `user.${userId}`, clientSecret: key.apiKey ?? key.ApiKey };
}
