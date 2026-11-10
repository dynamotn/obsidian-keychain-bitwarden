// The signed security state of a v2 (COSE) account, made the way Bitwarden's SDK makes it, so that the fake server's
// COSE accounts unlock in the core (ADR 0019): an Ed25519 signing key as a COSE_Key, wrapped under the user key
// (EncString type 7, content format cose-key), and a COSE_Sign1 over `{"version": n}` in the SDK's SecurityState
// signing namespace. The core derives the verifying key from the wrapped key, so no `verifyingKey` is served.
import { encodeCbor, type CborMap, type CborValue } from "./cbor";
import { encryptBytes, type SymmetricKey } from "./crypto";
import { toBase64 } from "./encoding";

// COSE labels: key type OKP, key id, algorithm EdDSA, curve Ed25519, private key; header content type, and the SDK's
// signing namespace header with its SecurityState value. The same numbers as the core's crypto/sign.rs.
const [KTY, KID, ALG, CRV, D] = [1, 2, 3, -1, -4];
const [OKP, EDDSA, ED25519] = [1, -8, 6];
const [H_ALG, H_CONTENT_TYPE, H_KID, H_NAMESPACE] = [1, 3, 4, -80000];
const [CBOR_CONTENT, NS_SECURITY_STATE] = [60, 2];

/** `accountKeys`' `signatureKeyPair` and `securityState` for an account with `userKey`. */
export async function signedSecurityState(userKey: SymmetricKey, version = 2) {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  // An Ed25519 PKCS#8 is a fixed 16-byte prefix, then the 32-byte private key.
  const d = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).slice(-32);
  const kid = crypto.getRandomValues(new Uint8Array(16));
  const key: CborMap = new Map<number, CborValue>([[KTY, OKP], [KID, kid], [ALG, EDDSA], [CRV, ED25519], [D, d]]);
  const wrappedSigningKey = await encryptBytes(encodeCbor(key), userKey, "cose-key");
  d.fill(0);

  const header: CborMap = new Map<number, CborValue>([[H_ALG, EDDSA], [H_KID, kid], [H_CONTENT_TYPE, CBOR_CONTENT], [H_NAMESPACE, NS_SECURITY_STATE]]);
  const protectedBytes = encodeCbor(header);
  const payload = encodeCbor(new Map([["version", version]]));
  const toSign = encodeCbor(["Signature1", protectedBytes, new Uint8Array(0), payload]);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, toSign));
  const signed = encodeCbor([protectedBytes, new Map(), payload, signature]);
  return {
    signatureKeyPair: { wrappedSigningKey },
    securityState: { securityState: toBase64(signed), securityVersion: version },
  };
}
