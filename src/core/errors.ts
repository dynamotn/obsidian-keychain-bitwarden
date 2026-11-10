// What a WasmSession call rejects with: the JSON text of `{code, message, …fields}` (dybw-core
// crates/dybw-core-wasm/src/error.rs). `parseCoreError` turns it into one typed error per code, whose message is the
// core's text and whose fields are the error's own; no field carries a value, a key or ciphertext.

/** A KDF as `acceptKdf` takes it and `kdf-weakened` carries it; `memory` in MiB. */
export type Kdf =
  | { type: "pbkdf2"; iterations: number }
  | { type: "argon2id"; iterations: number; memory: number; parallelism: number };

export class CoreError extends Error {
  override name = "CoreError";
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** No keys: locked, or a lock stopped the call (a sync included). */
export class LockedError extends CoreError {}
/** Another call has the keys out. */
export class BusyError extends CoreError {}
export class WrongPasswordError extends CoreError {}
/** ADR 0017: the server offers a weaker KDF than the one pinned on this device; `acceptKdf(offered, origin)`. */
export class KdfWeakenedError extends CoreError {
  declare readonly pinned: Kdf;
  declare readonly offered: Kdf;
  declare readonly source: "sync-unlock-data" | "prelogin";
  declare readonly origin: string;
}
export class KdfPinUnreadableError extends CoreError {}
/** ADR 0019: the account's security version went down; `acceptSecurityVersion(offered)`. */
export class SecurityDowngradeError extends CoreError {
  declare readonly seen: number;
  declare readonly offered: number;
}
export class SecurityStateError extends CoreError {
  declare readonly fault: "missing" | "invalid" | "stored-unreadable";
}
/** ADR 0018: a self-hosted identity origin this device has not acknowledged; `acknowledgeOrigin(origin)`. */
export class OriginNotAcknowledgedError extends CoreError {
  declare readonly origin: string;
}
export class WrongOriginError extends CoreError {}
/** The sync would clear half or more of what was synced: nothing was applied. */
export class MassClearError extends CoreError {
  declare readonly clears: number;
  declare readonly base: number;
}
/** The server or the connection failed; `status` only for an HTTP error. */
export class ApiError extends CoreError {
  declare readonly status?: number;
}
/** A host port failed (device storage, the KDF, …). */
export class PortError extends CoreError {}
/** The core refused an input, or data it cannot read. */
export class InvalidError extends CoreError {}

const TYPES: Record<string, typeof CoreError> = {
  locked: LockedError,
  busy: BusyError,
  "wrong-password": WrongPasswordError,
  "kdf-weakened": KdfWeakenedError,
  "kdf-pin-unreadable": KdfPinUnreadableError,
  "security-downgrade": SecurityDowngradeError,
  "security-state": SecurityStateError,
  "origin-not-acknowledged": OriginNotAcknowledgedError,
  "wrong-origin": WrongOriginError,
  "mass-clear": MassClearError,
  api: ApiError,
  port: PortError,
  invalid: InvalidError,
};

/**
 * The typed error for what a core call rejected with. A code this plugin does not know is a plain `CoreError`; a
 * rejection that is not the core's JSON (an Error thrown on the JS side) is returned as it is.
 */
export function parseCoreError(e: unknown): Error {
  if (typeof e !== "string") return e instanceof Error ? e : new Error(String(e));
  let parsed: unknown;
  try {
    parsed = JSON.parse(e);
  } catch {
    return new InvalidError("invalid", e);
  }
  const { code, message, ...fields } = (parsed ?? {}) as { code?: unknown; message?: unknown };
  if (typeof code !== "string" || typeof message !== "string") return new InvalidError("invalid", e);
  const Type = Object.hasOwn(TYPES, code) ? TYPES[code]! : CoreError;
  return Object.assign(new Type(code, message), fields);
}
