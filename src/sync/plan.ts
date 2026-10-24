// Pure three-way reconciliation between Bitwarden (remote), Obsidian's
// SecretStorage (local) and what both looked like after the last sync (base).
// No I/O here, so the rules can be tested exhaustively and benchmarked.

export interface BaseEntry {
  cipherId: string;
  revisionDate: string;
  /** Keyed fingerprint of the value at the last sync, never the value itself. */
  fingerprint: string;
  /** Scope of the Bitwarden item, so a re-upload keeps it ("global" when absent). */
  scope?: string;
}

export interface RemoteEntry {
  id: string;
  cipherId: string;
  revisionDate: string;
  fingerprint: string;
  /** The item belongs to an organization, whose members (and a hostile server) can create items. */
  organization?: boolean;
}

export interface LocalEntry {
  /** null when the secret does not exist on this device. */
  fingerprint: string | null;
}

export type ConflictKind = "both-changed" | "local-unsynced" | "deleted-remotely" | "organization-claim";

export type Action =
  | { kind: "pull"; id: string }
  | { kind: "push"; id: string }
  | { kind: "create"; id: string }
  | { kind: "adopt"; id: string }
  | { kind: "clear-local"; id: string }
  | { kind: "forget"; id: string }
  | { kind: "conflict"; id: string; conflict: ConflictKind };

export type ConflictPolicy = "ask" | "prefer-remote" | "prefer-local";

/** A decision about one specific conflict; ignored if the conflict has since changed kind. */
export interface ConflictOverride {
  policy: Exclude<ConflictPolicy, "ask">;
  kind: ConflictKind;
}

export interface PlanInput {
  remote: ReadonlyMap<string, RemoteEntry>;
  base: ReadonlyMap<string, BaseEntry>;
  local: (id: string) => LocalEntry;
  /** Secrets the user asked to upload that have no Bitwarden item yet. */
  pendingCreates: ReadonlySet<string>;
  policy: ConflictPolicy;
  /** Per-secret decisions, e.g. from the conflict dialog. */
  overrides?: ReadonlyMap<string, ConflictOverride>;
}

export function planSync(input: PlanInput): Action[] {
  const { remote, base, local, pendingCreates } = input;
  const actions: Action[] = [];
  const ids = new Set<string>([...remote.keys(), ...base.keys(), ...pendingCreates]);

  const resolve = (id: string, conflict: ConflictKind): Action => {
    const override = input.overrides?.get(id);
    // A local value that was never synced may belong to someone else (another
    // plugin, a stale device), and an organization item new to this id may
    // have been planted by anyone in it: only an explicit decision may
    // overwrite either side.
    const fallback = conflict === "local-unsynced" || conflict === "organization-claim" ? "ask" : input.policy;
    const policy = override && override.kind === conflict ? override.policy : fallback;
    if (policy === "prefer-remote") {
      return conflict === "deleted-remotely" ? { kind: "clear-local", id } : { kind: "pull", id };
    }
    if (policy === "prefer-local") {
      // Keeping the local value next to a claiming organization item uploads
      // it as a new personal item, which then wins; it is never sent to the organization.
      return conflict === "deleted-remotely" || conflict === "organization-claim"
        ? { kind: "create", id }
        : { kind: "push", id };
    }
    return { kind: "conflict", id, conflict };
  };

  for (const id of [...ids].sort()) {
    const r = remote.get(id);
    const b = base.get(id);
    const l = local(id);
    // An organization item other than the one this id was synced with.
    const claimed = r?.organization === true && r.cipherId !== b?.cipherId;

    if (r && claimed && l.fingerprint !== null && l.fingerprint !== r.fingerprint) {
      actions.push(resolve(id, "organization-claim"));
      continue;
    }

    if (r && !b) {
      if (l.fingerprint === null || l.fingerprint === r.fingerprint) actions.push({ kind: l.fingerprint ? "adopt" : "pull", id });
      else if (pendingCreates.has(id)) actions.push(resolve(id, "both-changed"));
      else actions.push(resolve(id, "local-unsynced"));
      continue;
    }

    if (r && b) {
      // Compare values, not just revisions: edits to other parts of the item
      // (name, favourite, folder) bump the revision without touching the secret.
      const remoteChanged = r.cipherId !== b.cipherId || r.fingerprint !== b.fingerprint;
      const remoteTouched = remoteChanged || r.revisionDate !== b.revisionDate;
      // A secret missing on this device is restored, never treated as a deletion:
      // SecretStorage has no delete API, so absence usually means "new device".
      if (l.fingerprint === null) {
        actions.push({ kind: "pull", id });
        continue;
      }
      const localChanged = l.fingerprint !== b.fingerprint;
      if (!remoteChanged && !localChanged) {
        if (remoteTouched) actions.push({ kind: "adopt", id });
        continue;
      }
      if (remoteChanged && !localChanged) actions.push({ kind: "pull", id });
      else if (!remoteChanged && localChanged) actions.push({ kind: "push", id });
      else if (l.fingerprint === r.fingerprint) actions.push({ kind: "adopt", id });
      else actions.push(resolve(id, "both-changed"));
      continue;
    }

    if (!r && b) {
      if (l.fingerprint === null) actions.push({ kind: "forget", id });
      else if (l.fingerprint === b.fingerprint) actions.push({ kind: "clear-local", id });
      else actions.push(resolve(id, "deleted-remotely"));
      continue;
    }

    // Neither remote nor base: only an explicit upload request creates an item.
    if (pendingCreates.has(id)) {
      actions.push(l.fingerprint === null ? { kind: "forget", id } : { kind: "create", id });
    }
  }
  return actions;
}
