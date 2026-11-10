// The signed security state of a v2 (COSE) account, made the way Bitwarden's SDK makes it, so that the fake server's
// COSE accounts unlock in the core (ADR 0019): an Ed25519 signing key as a COSE_Key, wrapped under the user key
// (EncString type 7, content format cose-key), and a COSE_Sign1 over `{"version": n}` in the SDK's SecurityState
// signing namespace. The core derives the verifying key from the wrapped key, so no `verifyingKey` is served.
import { encodeCbor, type CborMap, type CborValue } from "./cbor";
import { encryptBytes, type SymmetricKey } from "./crypto";
import { fromBase64, toBase64 } from "./encoding";

// COSE labels: key type OKP, key id, algorithm EdDSA, curve Ed25519, private key; header content type, and the SDK's
// signing namespace header with its SecurityState value. The same numbers as the core's crypto/sign.rs.
const [KTY, KID, ALG, CRV, D] = [1, 2, 3, -1, -4];
const [OKP, EDDSA, ED25519] = [1, -8, 6];
const [H_ALG, H_CONTENT_TYPE, H_KID, H_NAMESPACE] = [1, 3, 4, -80000];
const [CBOR_CONTENT, NS_SECURITY_STATE] = [60, 2];

// Linux WebKit's WebCrypto cannot generate Ed25519 keys, so the test account has ONE fixed signing key and the
// signatures for the versions the tests use are precomputed. Ed25519 is deterministic, and the signed bytes are a
// fixed header plus `{"version": n}`, so nothing here needs WebCrypto Ed25519. To add a version, sign
// CBOR ["Signature1", protectedBytes, h'', payload] with SEED in Node 26 (WebCrypto Ed25519 works there) and add it.
const SEED = fromBase64("+tC7oRsqKM7+Amy5bTPStIegtpAAfJ7H+rlLDcbkTBE=");
const KEY_ID = new Uint8Array(16).map((_, i) => 0xa0 + i);
const SIGNATURES: Record<number, string> = {
  1: "40LzpeFTJvz7tXfsvlKBvNuzyk9zN9yvx9uimSCag/xhi86OSkc7/MJkWD1gpk1h0GRYqBAEeljS3I4GUmlmAg==",
  2: "2a5/0+0nflXSkqvEivRayjI17htetL2U0GH8e/xY2oxVduhQZOAWl3L9AGnUEWUILDH+g2tWC7X+QHOhCfmxBQ==",
};

/** `accountKeys`' `signatureKeyPair` and `securityState` for an account with `userKey`. */
export async function signedSecurityState(userKey: SymmetricKey, version = 2) {
  const signature = SIGNATURES[version];
  if (!signature) throw new Error(`test/helpers/bw/sign.ts has no precomputed signature for security version ${version}`);
  const key: CborMap = new Map<number, CborValue>([[KTY, OKP], [KID, KEY_ID], [ALG, EDDSA], [CRV, ED25519], [D, SEED]]);
  const wrappedSigningKey = await encryptBytes(encodeCbor(key), userKey, "cose-key");

  const header: CborMap = new Map<number, CborValue>([[H_ALG, EDDSA], [H_KID, KEY_ID], [H_CONTENT_TYPE, CBOR_CONTENT], [H_NAMESPACE, NS_SECURITY_STATE]]);
  const payload = encodeCbor(new Map([["version", version]]));
  const signed = encodeCbor([encodeCbor(header), new Map(), payload, fromBase64(signature)]);
  return {
    signatureKeyPair: { wrappedSigningKey },
    securityState: { securityState: toBase64(signed), securityVersion: version },
  };
}
