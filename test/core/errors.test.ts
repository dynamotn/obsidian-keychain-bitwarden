import { describe, expect, it } from "vitest";
import {
  ApiError,
  BusyError,
  CoreError,
  InvalidError,
  KdfPinUnreadableError,
  KdfWeakenedError,
  LockedError,
  MassClearError,
  OriginNotAcknowledgedError,
  parseCoreError,
  PortError,
  SecurityDowngradeError,
  SecurityStateError,
  WrongOriginError,
  WrongPasswordError,
} from "../../src/core/errors";

const reject = (fields: Record<string, unknown>) => JSON.stringify({ message: "the core's text", ...fields });

describe("parseCoreError", () => {
  it.each([
    ["locked", LockedError],
    ["busy", BusyError],
    ["wrong-password", WrongPasswordError],
    ["kdf-pin-unreadable", KdfPinUnreadableError],
    ["wrong-origin", WrongOriginError],
    ["port", PortError],
    ["invalid", InvalidError],
  ])("types %s", (code, Type) => {
    const e = parseCoreError(reject({ code }));
    expect(e).toBeInstanceOf(Type);
    expect(e).toBeInstanceOf(CoreError);
    expect(e).toMatchObject({ code, message: "the core's text" });
  });

  it("keeps each code's fields", () => {
    const pinned = { type: "pbkdf2", iterations: 600_000 };
    const offered = { type: "pbkdf2", iterations: 5_000 };
    const origin = "https://bw.test";
    expect(parseCoreError(reject({ code: "kdf-weakened", pinned, offered, source: "prelogin", origin }))).toEqual(
      expect.objectContaining({ pinned, offered, source: "prelogin", origin }),
    );
    expect(parseCoreError(reject({ code: "kdf-weakened", pinned, offered, source: "prelogin", origin }))).toBeInstanceOf(KdfWeakenedError);
    expect(parseCoreError(reject({ code: "security-downgrade", seen: 2, offered: 1 }))).toMatchObject({ seen: 2, offered: 1 });
    expect(parseCoreError(reject({ code: "security-downgrade", seen: 2, offered: 1 }))).toBeInstanceOf(SecurityDowngradeError);
    expect(parseCoreError(reject({ code: "security-state", fault: "missing" }))).toBeInstanceOf(SecurityStateError);
    expect(parseCoreError(reject({ code: "origin-not-acknowledged", origin }))).toBeInstanceOf(OriginNotAcknowledgedError);
    expect(parseCoreError(reject({ code: "mass-clear", clears: 3, base: 4 }))).toBeInstanceOf(MassClearError);
    expect(parseCoreError(reject({ code: "api", status: 500 }))).toMatchObject({ status: 500 });
    expect(parseCoreError(reject({ code: "api" }))).toBeInstanceOf(ApiError);
  });

  it("answers a plain CoreError for a code it does not know", () => {
    const e = parseCoreError(reject({ code: "newer-code" }));
    expect(e.constructor).toBe(CoreError);
    expect(e).toMatchObject({ code: "newer-code", name: "CoreError" });
  });

  it("never lets a field replace the code, the message or a method", () => {
    const e = parseCoreError(JSON.stringify({ code: "locked", message: "m", hasOwnProperty: 1 })) as LockedError;
    expect(e.code).toBe("locked");
    expect(e.message).toBe("m");
    expect(parseCoreError(reject({ code: "__proto__" })).constructor).toBe(CoreError);
    expect(parseCoreError(reject({ code: "toString" })).constructor).toBe(CoreError);
  });

  it.each([
    ["text that is not JSON", "boom"],
    ["JSON null", "null"],
    ["an object without a code", JSON.stringify({ message: "m" })],
    ["an object without a message", JSON.stringify({ code: "locked" })],
  ])("reads %s as invalid, keeping the text", (_kind, text) => {
    expect(parseCoreError(text)).toBeInstanceOf(InvalidError);
    expect(parseCoreError(text)).toMatchObject({ code: "invalid", message: text });
  });

  it("returns an Error thrown on the JS side as it is, and wraps anything else", () => {
    const error = new TypeError("x");
    expect(parseCoreError(error)).toBe(error);
    expect(parseCoreError(42)).toEqual(new Error("42"));
  });
});
