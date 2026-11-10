// The core's questions to the user (ADRs 0016-0019): which one an unlock error or a sync report asks, in what words,
// and what the answer sends back. ui.ts only renders them.

import { KdfAbortedError } from "./bw/argon2";
import type { ConflictPolicy, HistoryAnswer, HistoryQuestion, SecretsController, SyncReport } from "./controller";
import { KdfWeakenedError, OriginNotAcknowledgedError, SecurityDowngradeError, type Kdf } from "./core/errors";

/** A yes/no question: `text` holds one paragraph per line. */
export interface Question {
  title: string;
  text: string;
  accept: string;
}

export interface UnlockQuestion extends Question {
  kind: "origin" | "kdf" | "security";
  /** Records the user's acceptance on this device. */
  apply: () => Promise<void>;
}

/** ADR 0018, for the settings toggle and the unlock question alike. */
export const ORIGIN_NAME = "I accept that this server, or a proxy in front of it, could redirect my API key";
export const ORIGIN_TEXT =
  "Obsidian follows redirects and cannot refuse them, nor tell where a request ended up. A compromised or " +
  "misconfigured server, or a proxy in front of it, could redirect the request that carries your API key and collect " +
  "the key. Bitwarden cloud is not affected. Accept this only for a server you trust; it applies to this device only.";

const kdfText = (k: Kdf) =>
  k.type === "pbkdf2"
    ? `PBKDF2, ${k.iterations} iterations`
    : `Argon2id, ${k.memory} MiB, ${k.iterations} iterations, ${k.parallelism} lanes`;

/** The question an unlock error asks before the unlock is tried again; null for any other error. */
export function unlockQuestion(e: unknown, controller: SecretsController): UnlockQuestion | null {
  if (e instanceof OriginNotAcknowledgedError) {
    return {
      kind: "origin",
      title: "Self-hosted server",
      text: `${e.origin}\n${ORIGIN_NAME}?\n${ORIGIN_TEXT}`,
      accept: "Acknowledge and retry",
      apply: () => controller.acknowledgeOrigin(e.origin),
    };
  }
  if (e instanceof KdfWeakenedError) {
    return {
      kind: "kdf",
      title: "Weaker key derivation",
      text:
        `${e.origin} now asks for weaker key derivation settings than the ones pinned on this device.\n` +
        `pinned on this device: ${kdfText(e.pinned)}\noffered: ${kdfText(e.offered)}\n` +
        "Accept them only if you changed them yourself: check in the Bitwarden web vault first.",
      accept: "Accept the weaker settings and retry",
      apply: () => controller.acceptKdf(e.offered, e.origin),
    };
  }
  if (e instanceof SecurityDowngradeError) {
    return {
      kind: "security",
      title: "Older account security state",
      text:
        `The account's security state went back: version ${e.seen} on this device, the server now offers version ` +
        `${e.offered}.\nA server can do this to serve a key from before a rotation. Accept it only if you moved the ` +
        "account to another server or restored it from a backup.",
      accept: "Accept the server's version and retry",
      apply: () => controller.acceptSecurityVersion(e.offered),
    };
  }
  return null;
}

/**
 * Runs `unlock`, and when it fails with a question the user accepts, records the answer and runs it again. Each kind of
 * question is asked once: the same error after the answer is the unlock's. A cancelled question rejects with its error.
 */
export async function unlockAsking<T>(
  unlock: () => Promise<T>,
  controller: SecretsController,
  ask: (q: UnlockQuestion) => Promise<boolean>,
): Promise<T> {
  const asked = new Set<UnlockQuestion["kind"]>();
  const generation = controller.lockGeneration;
  // A lock or an unload while the question was open cancels the unlock: nothing is recorded, nothing retried.
  const stillWanted = () => {
    if (controller.lockGeneration !== generation) throw new KdfAbortedError();
  };
  for (;;) {
    try {
      return await unlock();
    } catch (e) {
      const q = unlockQuestion(e, controller);
      if (!q || asked.has(q.kind)) throw e;
      const accepted = await ask(q);
      stillWanted();
      if (!accepted) throw e;
      asked.add(q.kind);
      await q.apply();
      stillWanted();
    }
  }
}

/** `fn`, dropped once Bitwarden locked since: an answer to a question asked before a lock is no longer wanted. */
export function unlessLocked<A extends unknown[]>(controller: SecretsController, fn: (...args: A) => unknown) {
  const generation = controller.lockGeneration;
  return async (...args: A): Promise<void> => {
    if (controller.lockGeneration === generation) await fn(...args);
  };
}

/** The settings toggle as `acknowledgeToggle` drives it. */
export interface ToggleView {
  setValue(on: boolean): unknown;
  setDisabled(disabled: boolean): unknown;
}

/**
 * ADR 0018's settings toggle, kept on the server in the URL field: `refresh` after the URL changed (a late answer for
 * an older URL is dropped), `change` from the toggle's onChange (ignored while `refresh` sets the value).
 */
export function acknowledgeToggle(controller: SecretsController, view: ToggleView) {
  let seq = 0;
  let refreshing = false;
  const refresh = async () => {
    const mine = ++seq;
    let on: boolean;
    try {
      on = await controller.originAcknowledged();
    } catch {
      if (mine === seq) view.setDisabled(true);
      return;
    }
    if (mine !== seq) return;
    view.setDisabled(false);
    refreshing = true;
    try {
      view.setValue(on);
    } finally {
      refreshing = false;
    }
  };
  /** Rejects with the core's error after putting the toggle back to what the core holds. */
  const change = async (on: boolean) => {
    if (refreshing) return;
    seq++; // The user's choice wins over a refresh still waiting.
    try {
      await (on ? controller.acknowledgeOrigin() : controller.forgetOrigin());
    } catch (e) {
      await refresh();
      throw e;
    }
  };
  return { refresh, change };
}

/** The modal a sync the user asked for opens: rollbacks first (accepting them changes the rest), then history, then conflicts. */
export function syncQuestion(
  report: SyncReport,
  policy: ConflictPolicy,
  rollbackDeclined = false,
): "rollbacks" | "history" | "conflicts" | null {
  if (report.rollbacks.length && !rollbackDeclined) return "rollbacks";
  if (report.questions.length) return "history";
  if (report.conflicts.length && policy === "ask") return "conflicts";
  return null;
}

/** ADR 0019: one button accepts every rollback of the sync. */
export function rollbackQuestion(report: SyncReport): Question {
  return {
    title: "Older versions from Bitwarden",
    text:
      `${report.rollbacks.length} synced secret(s) came back older from Bitwarden: ${report.rollbacks.map((r) => r.id).join(", ")}.\n` +
      "This device keeps its values until you accept. A restore from a backup, or a version restored in the web vault, " +
      "shows this way; so would a server serving old data. Accepting takes the server's versions; it never uploads " +
      "this device's values over them.",
    accept: "Accept the server's versions",
  };
}

/** ADR 0016: what each question warns about, and its answers. */
export const HISTORY_TEXT: Record<HistoryQuestion, string> = {
  "first-write-back":
    "is a login you marked by hand: this is the first time this device writes its password. The current password " +
    "moves into the item's password history",
  "evicts-foreign-history":
    "has a full password history: writing to it loses the oldest password in it, which this device did not write",
};
export const HISTORY_CHOICES: Record<HistoryAnswer["answer"], string> = {
  "write-to-login": "Write to the login",
  "keep-separate": "Keep the app's value separate",
};

/** The answers to send: each tied to the question it was given for, so another question asks again. No pick is a cancel. */
export function historyAnswers(
  questions: SyncReport["questions"],
  picks: ReadonlyMap<string, HistoryAnswer["answer"]>,
): Map<string, HistoryAnswer> {
  const answers = new Map<string, HistoryAnswer>();
  for (const q of questions) {
    const answer = picks.get(q.id);
    if (answer) answers.set(q.id, { question: q.question, answer });
  }
  return answers;
}
