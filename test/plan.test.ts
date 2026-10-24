import { describe, expect, it } from "vitest";
import { planSync, type BaseEntry, type ConflictPolicy, type RemoteEntry } from "../src/sync/plan";

const R = (id: string, rev: string, fp: string, cipherId = `c-${id}`, organization = false): RemoteEntry => ({
  id,
  cipherId,
  revisionDate: rev,
  fingerprint: fp,
  organization,
});
const B = (id: string, rev: string, fp: string, cipherId = `c-${id}`): BaseEntry => ({
  cipherId,
  revisionDate: rev,
  fingerprint: fp,
});

function plan(opts: {
  remote?: RemoteEntry[];
  base?: [string, BaseEntry][];
  local?: Record<string, string>;
  pending?: string[];
  policy?: ConflictPolicy;
}) {
  return planSync({
    remote: new Map((opts.remote ?? []).map((r) => [r.id, r])),
    base: new Map(opts.base ?? []),
    local: (id) => ({ fingerprint: opts.local?.[id] ?? null }),
    pendingCreates: new Set(opts.pending ?? []),
    policy: opts.policy ?? "ask",
  });
}

describe("planSync", () => {
  it("pulls a new remote secret onto a fresh device", () => {
    expect(plan({ remote: [R("a", "1", "x")] })).toEqual([{ kind: "pull", id: "a" }]);
  });

  it("adopts a remote secret whose value already matches locally", () => {
    expect(plan({ remote: [R("a", "1", "x")], local: { a: "x" } })).toEqual([{ kind: "adopt", id: "a" }]);
  });

  it("does nothing when neither side changed", () => {
    expect(plan({ remote: [R("a", "1", "x")], base: [["a", B("a", "1", "x")]], local: { a: "x" } })).toEqual([]);
  });

  it("pulls remote edits and pushes local edits", () => {
    expect(plan({ remote: [R("a", "2", "y")], base: [["a", B("a", "1", "x")]], local: { a: "x" } })).toEqual([
      { kind: "pull", id: "a" },
    ]);
    expect(plan({ remote: [R("a", "1", "x")], base: [["a", B("a", "1", "x")]], local: { a: "z" } })).toEqual([
      { kind: "push", id: "a" },
    ]);
  });

  it("only refreshes the base when the item changed but the value did not", () => {
    expect(plan({ remote: [R("a", "2", "x")], base: [["a", B("a", "1", "x")]], local: { a: "x" } })).toEqual([
      { kind: "adopt", id: "a" },
    ]);
    expect(plan({ remote: [R("a", "2", "x")], base: [["a", B("a", "1", "x")]], local: { a: "z" } })).toEqual([
      { kind: "push", id: "a" },
    ]);
  });

  it("treats a replaced Bitwarden item as a remote change", () => {
    expect(plan({ remote: [R("a", "1", "x", "new")], base: [["a", B("a", "1", "x", "old")]], local: { a: "x" } })).toEqual(
      [{ kind: "pull", id: "a" }],
    );
  });

  it("restores a secret missing on this device instead of deleting it remotely", () => {
    expect(plan({ remote: [R("a", "1", "x")], base: [["a", B("a", "1", "x")]] })).toEqual([{ kind: "pull", id: "a" }]);
  });

  it("detects both-changed conflicts, and converges when both made the same edit", () => {
    const base: [string, BaseEntry][] = [["a", B("a", "1", "x")]];
    expect(plan({ remote: [R("a", "2", "y")], base, local: { a: "z" } })).toEqual([
      { kind: "conflict", id: "a", conflict: "both-changed" },
    ]);
    expect(plan({ remote: [R("a", "2", "y")], base, local: { a: "y" } })).toEqual([{ kind: "adopt", id: "a" }]);
  });

  it("applies the conflict policy", () => {
    const input = { remote: [R("a", "2", "y")], base: [["a", B("a", "1", "x")]] as [string, BaseEntry][], local: { a: "z" } };
    expect(plan({ ...input, policy: "prefer-remote" })).toEqual([{ kind: "pull", id: "a" }]);
    expect(plan({ ...input, policy: "prefer-local" })).toEqual([{ kind: "push", id: "a" }]);
  });

  it("flags an unsynced local value that differs from a new remote one", () => {
    expect(plan({ remote: [R("a", "1", "x")], local: { a: "local" } })).toEqual([
      { kind: "conflict", id: "a", conflict: "local-unsynced" },
    ]);
  });

  it("clears locally when deleted remotely, unless edited here", () => {
    expect(plan({ base: [["a", B("a", "1", "x")]], local: { a: "x" } })).toEqual([{ kind: "clear-local", id: "a" }]);
    expect(plan({ base: [["a", B("a", "1", "x")]], local: { a: "edited" } })).toEqual([
      { kind: "conflict", id: "a", conflict: "deleted-remotely" },
    ]);
    expect(plan({ base: [["a", B("a", "1", "x")]], local: { a: "edited" }, policy: "prefer-local" })).toEqual([
      { kind: "create", id: "a" },
    ]);
    expect(plan({ base: [["a", B("a", "1", "x")]] })).toEqual([{ kind: "forget", id: "a" }]);
  });

  it("creates only what the user queued", () => {
    expect(plan({ local: { a: "v", b: "w" }, pending: ["a"] })).toEqual([{ kind: "create", id: "a" }]);
    expect(plan({ pending: ["gone"] })).toEqual([{ kind: "forget", id: "gone" }]);
  });

  it("is deterministic (sorted by id)", () => {
    const ids = plan({ remote: ["c", "a", "b"].map((id) => R(id, "1", "x")) }).map((a) => a.id);
    expect(ids).toEqual(["a", "b", "c"]);
  });

  it("honours per-secret overrides", () => {
    const actions = planSync({
      remote: new Map([["a", R("a", "2", "y")], ["b", R("b", "2", "y")]]),
      base: new Map([["a", B("a", "1", "x")], ["b", B("b", "1", "x")]]),
      local: () => ({ fingerprint: "z" }),
      pendingCreates: new Set(),
      policy: "ask",
      overrides: new Map([["b", { policy: "prefer-local", kind: "both-changed" }]]),
    });
    expect(actions).toEqual([
      { kind: "conflict", id: "a", conflict: "both-changed" },
      { kind: "push", id: "b" },
    ]);
  });

  describe("organization items claiming an id", () => {
    const policies: ConflictPolicy[] = ["ask", "prefer-local", "prefer-remote"];

    it("always asks before a pending or unsynced local value meets a new organization item", () => {
      for (const policy of policies) {
        for (const pending of [[], ["a"]]) {
          expect(plan({ remote: [R("a", "1", "theirs", "org-1", true)], local: { a: "mine" }, pending, policy })).toEqual([
            { kind: "conflict", id: "a", conflict: "organization-claim" },
          ]);
        }
      }
    });

    it("always asks when an organization item replaces the item a secret was synced with", () => {
      for (const policy of policies) {
        for (const local of ["base", "edited"]) {
          const remote = [R("a", "2", "theirs", "org-1", true)];
          expect(plan({ remote, base: [["a", B("a", "1", "base", "mine-1")]], local: { a: local }, policy })).toEqual([
            { kind: "conflict", id: "a", conflict: "organization-claim" },
          ]);
        }
      }
    });

    it("keeps a local value as a new personal item, never pushing it to the organization", () => {
      const actions = planSync({
        remote: new Map([["a", R("a", "1", "theirs", "org-1", true)]]),
        base: new Map(),
        local: () => ({ fingerprint: "mine" }),
        pendingCreates: new Set(["a"]),
        policy: "prefer-local",
        overrides: new Map([["a", { policy: "prefer-local", kind: "organization-claim" }]]),
      });
      expect(actions).toEqual([{ kind: "create", id: "a" }]);
    });

    it("still pulls onto an empty device and pushes to the organization item it synced with", () => {
      expect(plan({ remote: [R("a", "1", "theirs", "org-1", true)] })).toEqual([{ kind: "pull", id: "a" }]);
      const base: [string, BaseEntry][] = [["a", B("a", "1", "x", "org-1")]];
      expect(plan({ remote: [R("a", "1", "x", "org-1", true)], base, local: { a: "y" } })).toEqual([{ kind: "push", id: "a" }]);
    });
  });
});
