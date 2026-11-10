import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { STORAGE_PREFIX } from "../src/core/ports";
import { KdfWeakenedError, OriginNotAcknowledgedError, SecurityDowngradeError, WrongPasswordError } from "../src/core/errors";
import { isSelfHosted, summarize, type SyncReport } from "../src/controller";
import { KdfAbortedError } from "../src/bw/argon2";
import { acknowledgeToggle, historyAnswers, rollbackQuestion, syncQuestion, unlockAsking, unlockQuestion, type UnlockQuestion } from "../src/questions";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";

// The core's questions (ADRs 0016-0019): which one an unlock error or a sync report asks, what the answers send back,
// and the flows end to end over the fake server, whose host follows redirects (refusesRedirects false) as requestUrl.

const ACKNOWLEDGED = `${STORAGE_PREFIX}acknowledged-origins`;
const PIN = `${STORAGE_PREFIX}kdf-pin`;

const emptyReport: SyncReport = {
  pulled: [],
  pushed: [],
  created: [],
  cleared: [],
  conflicts: [],
  errors: [],
  passes: 1,
  keptChanging: false,
  questions: [],
  rollbacks: [],
  held: [],
  readOnly: [],
  unknownFeatures: [],
  unreadable: [],
  duplicates: [],
  skipped: [],
  warnings: [],
};

describe("the core's questions", () => {
  let server: FakeBitwardenServer;
  let a: TestDevice;

  beforeEach(async () => {
    server = await FakeBitwardenServer.create();
    a = makeDevice(server.http, server.account);
  });

  afterEach(() => vi.restoreAllMocks());

  /** Unlocks `d`, answering every question with `answer`; the questions asked are pushed to `asked`. */
  const unlockAnswering = (d: TestDevice, answer: boolean, asked: UnlockQuestion[] = []) =>
    unlockAsking(
      () => d.controller.unlock(server.account.password),
      d.controller,
      async (q) => {
        asked.push(q);
        return answer;
      },
    );

  describe("self-hosted origin (ADR 0018)", () => {
    it.each([
      ["https://vault.bitwarden.com", false],
      ["https://bitwarden.eu", false],
      ["", false],
      ["https://bw.example:8443/vault", true],
      ["not a url", false],
    ])("%j is self-hosted: %s", (url, expected) => {
      expect(isSelfHosted(url)).toBe(expected);
    });

    it("asks to acknowledge it, then unlocks", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      expect(await a.controller.originAcknowledged()).toBe(false);
      const asked: UnlockQuestion[] = [];
      await unlockAnswering(a, true, asked);
      expect(asked.map((q) => q.kind)).toEqual(["origin"]);
      expect(asked[0]!.text).toMatch(/https:\/\/bw\.test[\s\S]*proxy in front of it/);
      expect(asked[0]!.accept).toBe("Acknowledge and retry");
      expect(a.controller.isUnlocked).toBe(true);
      expect(await a.controller.originAcknowledged()).toBe(true);
      expect(JSON.parse(a.localStorage.get(ACKNOWLEDGED) as string)).toEqual(["https://bw.test"]);
    });

    it("sends nothing when the question is cancelled", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      server.requests = [];
      await expect(unlockAnswering(a, false)).rejects.toBeInstanceOf(OriginNotAcknowledgedError);
      expect(server.requests.filter((r) => r.url.endsWith("/connect/token"))).toHaveLength(0);
      expect(a.controller.isUnlocked).toBe(false);
    });

    it("acknowledged from the settings, unlocks without asking", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      await a.controller.acknowledgeOrigin();
      const asked: UnlockQuestion[] = [];
      await unlockAnswering(a, false, asked);
      expect(asked).toEqual([]);
    });

    it("turned off in the settings, locks, and the next unlock asks again", async () => {
      await a.controller.unlock(server.account.password);
      await a.controller.forgetOrigin();
      expect(a.controller.isUnlocked).toBe(false);
      expect(a.controller.status).toBe("locked");
      expect(await a.controller.originAcknowledged()).toBe(false);
      await expect(a.controller.unlock(server.account.password)).rejects.toBeInstanceOf(OriginNotAcknowledgedError);
    });
  });

  describe("the settings toggle (ADR 0018)", () => {
    /** A ToggleComponent whose setValue fires onChange, as Obsidian's may. */
    const toggleOf = () => {
      const view = {
        value: false,
        disabled: false,
        onChange: (_: boolean): unknown => undefined,
        setValue(on: boolean) {
          view.value = on;
          view.onChange(on);
        },
        setDisabled(off: boolean) {
          view.disabled = off;
        },
      };
      const toggle = acknowledgeToggle(a.controller, view);
      view.onChange = (on) => toggle.change(on);
      return { view, toggle };
    };

    it("shows the server in the URL field, and setting the value acts on nothing", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      await a.controller.acknowledgeOrigin("https://other.test");
      const forget = vi.spyOn(a.controller, "forgetOrigin");
      const acknowledge = vi.spyOn(a.controller, "acknowledgeOrigin");
      const { view, toggle } = toggleOf();
      a.settings.serverUrl = "https://other.test";
      await toggle.refresh();
      expect(view.value).toBe(true);
      a.settings.serverUrl = "https://bw.test";
      await toggle.refresh();
      expect(view.value).toBe(false);
      expect(forget).not.toHaveBeenCalled();
      expect(acknowledge).not.toHaveBeenCalled();
    });

    it("drops a late answer for an older URL", async () => {
      const { view, toggle } = toggleOf();
      let answer!: (on: boolean) => void;
      vi.spyOn(a.controller, "originAcknowledged")
        .mockReturnValueOnce(new Promise((resolve) => (answer = resolve)))
        .mockResolvedValueOnce(false);
      const old = toggle.refresh();
      await toggle.refresh();
      answer(true);
      await old;
      expect(view.value).toBe(false);
    });

    it("lets the user's choice win over a refresh still waiting", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      const { view, toggle } = toggleOf();
      let answer!: (on: boolean) => void;
      vi.spyOn(a.controller, "originAcknowledged").mockReturnValueOnce(new Promise((resolve) => (answer = resolve)));
      const pending = toggle.refresh();
      await toggle.change(true);
      answer(false);
      await pending;
      expect(view.value).toBe(false); // untouched by the stale refresh: the view keeps what the user clicked
      expect(await a.controller.originAcknowledged()).toBe(true);
    });

    it("drops a late failure for an older URL", async () => {
      const { view, toggle } = toggleOf();
      let fail!: (e: Error) => void;
      vi.spyOn(a.controller, "originAcknowledged")
        .mockReturnValueOnce(new Promise((_, reject) => (fail = reject)))
        .mockResolvedValueOnce(true);
      const old = toggle.refresh();
      await toggle.refresh();
      fail(new Error("Invalid server URL"));
      await old;
      expect(view.disabled).toBe(false);
      expect(view.value).toBe(true);
    });

    it("is disabled when the core cannot answer", async () => {
      const { view, toggle } = toggleOf();
      vi.spyOn(a.controller, "originAcknowledged").mockRejectedValueOnce(new Error("no core"));
      await toggle.refresh();
      expect(view.disabled).toBe(true);
      await toggle.refresh();
      expect(view.disabled).toBe(false);
      expect(view.value).toBe(true);
    });

    it("puts the toggle back to what the core holds when the change failed", async () => {
      const { view, toggle } = toggleOf();
      await toggle.refresh();
      vi.spyOn(a.controller, "forgetOrigin").mockRejectedValueOnce(new Error("storage failed"));
      view.value = false;
      await expect(toggle.change(false)).rejects.toThrow("storage failed");
      expect(view.value).toBe(true);
    });
  });

  describe("weakened KDF (ADR 0017)", () => {
    it("shows the pinned and the offered settings, and accepting them retries the unlock", async () => {
      await a.controller.unlock(server.account.password);
      a.controller.lock();
      const pin = JSON.parse(a.localStorage.get(PIN) as string) as object;
      a.localStorage.set(PIN, JSON.stringify({ ...pin, iterations: 600_000 }));
      const unlock = vi.spyOn(a.controller, "unlock");
      const asked: UnlockQuestion[] = [];
      await unlockAnswering(a, true, asked);
      expect(asked.map((q) => q.kind)).toEqual(["kdf"]);
      expect(asked[0]!.text).toContain("pinned on this device: PBKDF2, 600000 iterations");
      expect(asked[0]!.text).toContain("offered: PBKDF2, 5000 iterations");
      expect(unlock).toHaveBeenCalledTimes(2);
      expect(a.controller.isUnlocked).toBe(true);
    });

    it("keeps the pin when the question is cancelled", async () => {
      await a.controller.unlock(server.account.password);
      a.controller.lock();
      const pinned = JSON.stringify({ ...(JSON.parse(a.localStorage.get(PIN) as string) as object), iterations: 600_000 });
      a.localStorage.set(PIN, pinned);
      await expect(unlockAnswering(a, false)).rejects.toBeInstanceOf(KdfWeakenedError);
      expect(a.localStorage.get(PIN)).toBe(pinned);
    });

    it("describes Argon2id with its memory and lanes", () => {
      const e = Object.assign(new KdfWeakenedError("kdf-weakened", "weaker"), {
        pinned: { type: "argon2id", iterations: 3, memory: 64, parallelism: 4 },
        offered: { type: "argon2id", iterations: 2, memory: 16, parallelism: 1 },
        source: "prelogin",
        origin: "https://bw.test",
      });
      expect(unlockQuestion(e, a.controller)!.text).toContain(
        "pinned on this device: Argon2id, 64 MiB, 3 iterations, 4 lanes\noffered: Argon2id, 16 MiB, 2 iterations, 1 lanes",
      );
    });
  });

  describe("security downgrade (ADR 0019)", () => {
    it("shows the versions, and accepting the offered one retries the unlock", async () => {
      a.localStorage.set(`${STORAGE_PREFIX}security-version`, "5");
      const asked: UnlockQuestion[] = [];
      await unlockAnswering(a, true, asked);
      expect(asked.map((q) => q.kind)).toEqual(["security"]);
      expect(asked[0]!.text).toContain("version 5 on this device, the server now offers version 0");
      expect(a.localStorage.get(`${STORAGE_PREFIX}security-version`)).toBe("0");
      expect(a.controller.isUnlocked).toBe(true);
    });
  });

  describe("unlockAsking", () => {
    it("asks each kind of question once: the same error again is the answer", async () => {
      const e = Object.assign(new SecurityDowngradeError("security-downgrade", "down"), { seen: 2, offered: 1 });
      vi.spyOn(a.controller, "acceptSecurityVersion").mockResolvedValue();
      const asked: UnlockQuestion[] = [];
      const unlock = vi.fn().mockRejectedValue(e);
      await expect(unlockAsking(unlock, a.controller, async (q) => asked.push(q) > 0)).rejects.toBe(e);
      expect(unlock).toHaveBeenCalledTimes(2);
      expect(asked).toHaveLength(1);
    });

    it("drops the question when a lock came while it was open: nothing recorded, nothing retried", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      const unlock = vi.spyOn(a.controller, "unlock");
      const run = unlockAsking(
        () => a.controller.unlock(server.account.password),
        a.controller,
        async () => {
          a.controller.lock();
          return true;
        },
      );
      await expect(run).rejects.toBeInstanceOf(KdfAbortedError);
      expect(unlock).toHaveBeenCalledTimes(1);
      expect(a.localStorage.has(ACKNOWLEDGED)).toBe(false);
    });

    it("does not retry when a lock came while the answer was recorded", async () => {
      a.localStorage.delete(ACKNOWLEDGED);
      const acknowledge = a.controller.acknowledgeOrigin.bind(a.controller);
      vi.spyOn(a.controller, "acknowledgeOrigin").mockImplementation(async (origin) => {
        a.controller.lock();
        await acknowledge(origin);
      });
      const unlock = vi.spyOn(a.controller, "unlock");
      await expect(unlockAnswering(a, true)).rejects.toBeInstanceOf(KdfAbortedError);
      expect(unlock).toHaveBeenCalledTimes(1);
      expect(a.controller.isUnlocked).toBe(false);
    });

    it("asks nothing for an error that is not a question", async () => {
      const e = new WrongPasswordError("wrong-password", "wrong");
      const ask = vi.fn();
      await expect(unlockAsking(() => Promise.reject(e), a.controller, ask)).rejects.toBe(e);
      expect(ask).not.toHaveBeenCalled();
      expect(unlockQuestion(new Error("x"), a.controller)).toBeNull();
    });
  });

  describe("history (ADR 0016)", () => {
    it("builds the answers keyed by id and the question they were given for; no answer is a cancel", () => {
      const questions: SyncReport["questions"] = [
        { id: "a", label: "A", question: "first-write-back" },
        { id: "b", label: "B", question: "evicts-foreign-history" },
        { id: "c", label: "C", question: "first-write-back" },
      ];
      const answers = historyAnswers(questions, new Map([["a", "write-to-login"], ["b", "keep-separate"]] as const));
      expect([...answers]).toEqual([
        ["a", { question: "first-write-back", answer: "write-to-login" }],
        ["b", { question: "evicts-foreign-history", answer: "keep-separate" }],
      ]);
    });

    it("asks again when the question changed since the answer", async () => {
      await a.controller.unlock(server.account.password);
      await server.addItem({ name: "site", type: 1, value: "pw" });
      await a.controller.sync();
      a.store.set("site", "rotated");
      const asked = (await a.controller.sync()).questions;
      expect(asked).toEqual([{ id: "site", label: "site", question: "first-write-back" }]);
      const stale = new Map([["site", { question: "evicts-foreign-history", answer: "write-to-login" }]] as const);
      const r = await a.controller.sync(undefined, stale);
      expect(r.questions).toEqual(asked);
      expect(r.pushed).toEqual([]);
      const r2 = await a.controller.sync(undefined, historyAnswers(asked, new Map([["site", "keep-separate"]])));
      expect(r2.questions).toEqual([]);
      expect(r2.pushed).toEqual(["site"]);
    });
  });

  describe("rollback (ADR 0019)", () => {
    it("keeps the local value until the user accepts the server's versions", async () => {
      await a.controller.unlock(server.account.password);
      const c = await server.addItem({ name: "k", value: "old" });
      const old = c.revisionDate;
      await a.controller.sync();
      await server.editValue(c.id, "new");
      await a.controller.sync();
      // The server serves the older version again, as after a restore from a backup.
      await server.editValue(c.id, "old");
      c.revisionDate = old;
      const r = await a.controller.sync();
      expect(r.rollbacks).toEqual([{ id: "k", cipherId: c.id }]);
      expect(a.store.get("k")).toBe("new");
      expect(syncQuestion(r, "prefer-remote")).toBe("rollbacks");
      expect(rollbackQuestion(r)).toMatchObject({ accept: "Accept the server's versions", text: expect.stringContaining("1 synced") });
      const accepted = await a.controller.sync(undefined, undefined, true);
      expect(accepted.rollbacks).toEqual([]);
      expect(a.store.get("k")).toBe("old");
    });
  });

  describe("syncQuestion", () => {
    it.each([
      [{}, "ask", null],
      [{ conflicts: [{ id: "k" }] }, "ask", "conflicts"],
      [{ conflicts: [{ id: "k" }] }, "prefer-local", null],
      [{ questions: [{ id: "k" }], conflicts: [{ id: "j" }] }, "ask", "history"],
      [{ rollbacks: [{ id: "k" }], questions: [{ id: "j" }] }, "ask", "rollbacks"],
    ] as const)("%j with policy %s opens %s", (part, policy, expected) => {
      expect(syncQuestion({ ...emptyReport, ...part } as unknown as SyncReport, policy)).toBe(expected);
    });

    it("goes on to the next question in line once the rollback was declined", () => {
      const report = { ...emptyReport, rollbacks: [{ id: "k" }], questions: [{ id: "j" }] } as unknown as SyncReport;
      expect(syncQuestion(report, "ask", true)).toBe("history");
      expect(syncQuestion({ ...report, questions: [] }, "ask", true)).toBeNull();
    });
  });

  describe("summarize", () => {
    it("counts the held and unknown-feature items with the core's sentences", async () => {
      expect(summarize(emptyReport)).toBe("everything is up to date");
      const report = {
        ...emptyReport,
        pulled: ["a"],
        pushed: ["b"],
        created: ["c"],
        cleared: ["d"],
        conflicts: [{ id: "e" }],
        skipped: [{ cipherId: "f" }],
        errors: [{ id: "g" }],
        warnings: ["1 items need a newer version of this tool: left alone", "2 synced secrets can no longer be used here: kept as they are"],
      } as unknown as SyncReport;
      expect(summarize(report)).toBe(
        "1 updated, 1 uploaded, 1 added to Bitwarden, 1 cleared, 1 conflict(s), 1 item(s) skipped, 1 error(s), " +
          "1 items need a newer version of this tool: left alone, 2 synced secrets can no longer be used here: kept as they are",
      );
    });
  });
});
