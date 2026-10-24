import { App, FuzzySuggestModal, Modal, Notice, Setting } from "obsidian";
import type { ConflictInfo, SyncReport } from "./sync/engine";
import type { ConflictOverride } from "./sync/plan";
import { KdfAbortedError } from "./bw/argon2";
import type { Scope } from "./bw/vault";

export class UnlockModal extends Modal {
  private busy = false;

  constructor(
    app: App,
    private readonly onSubmit: (password: string) => Promise<void>,
    /** Called when the dialog is closed while unlocking is still in progress. */
    private readonly onCancel: () => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    this.setTitle("Unlock Bitwarden");
    const { contentEl } = this;
    const input = contentEl.createEl("input", {
      type: "password",
      attr: { autocomplete: "current-password", placeholder: "Master password", "aria-label": "Master password" },
    });
    input.setCssProps({ width: "100%" });
    const error = contentEl.createDiv({ cls: "mod-warning" });
    const submit = async () => {
      if (this.busy || !input.value) return;
      this.busy = true;
      button.setDisabled(true).setButtonText("Unlocking…");
      error.setText("");
      const password = input.value;
      input.value = "";
      try {
        await this.onSubmit(password);
        this.close();
      } catch (e) {
        // Cancelled by closing the dialog: there is nothing left to show.
        if (e instanceof KdfAbortedError) return;
        error.setText((e as Error).message);
        input.focus();
      } finally {
        this.busy = false;
        button.setDisabled(false).setButtonText("Unlock");
      }
    };
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") void submit();
    });
    let button!: import("obsidian").ButtonComponent;
    new Setting(contentEl).addButton((b) => {
      button = b.setButtonText("Unlock").setCta().onClick(() => void submit());
    });
    window.setTimeout(() => input.focus(), 0);
  }

  override onClose(): void {
    if (this.busy) this.onCancel();
    this.contentEl.empty();
  }
}

const CONFLICT_TEXT: Record<ConflictInfo["kind"], string> = {
  "both-changed": "changed both here and in Bitwarden",
  "local-unsynced": "exists here with a different value than in Bitwarden",
  "deleted-remotely": "was deleted in Bitwarden but edited here",
};

export class ConflictModal extends Modal {
  private readonly choices = new Map<string, ConflictOverride>();

  constructor(
    app: App,
    private readonly conflicts: ConflictInfo[],
    private readonly onResolve: (choices: Map<string, ConflictOverride>) => Promise<void>,
  ) {
    super(app);
  }

  override onOpen(): void {
    this.setTitle("Resolve secret conflicts");
    const { contentEl } = this;
    contentEl.createEl("p", { text: "Values are not shown here. Pick which side wins for each secret." });
    for (const c of this.conflicts) {
      new Setting(contentEl)
        .setName(c.label === c.id ? c.id : `${c.label} (${c.id})`)
        .setDesc(CONFLICT_TEXT[c.kind])
        .addDropdown((d) =>
          d
            .addOption("", "Decide later")
            .addOption("prefer-remote", c.kind === "deleted-remotely" ? "Clear on this device" : "Use Bitwarden")
            .addOption("prefer-local", c.kind === "deleted-remotely" ? "Upload again" : "Use this device")
            .onChange((v) => {
              // Tied to the kind shown here: if the conflict changes before the
              // sync runs, the choice no longer applies and the user is asked again.
              if (v) this.choices.set(c.id, { policy: v as ConflictOverride["policy"], kind: c.kind });
              else this.choices.delete(c.id);
            }),
        );
    }
    new Setting(contentEl).addButton((b) =>
      b
        .setButtonText("Apply")
        .setCta()
        .onClick(async () => {
          b.setDisabled(true);
          try {
            if (this.choices.size) await this.onResolve(this.choices);
            this.close();
          } catch (e) {
            new Notice(`Bitwarden: ${(e as Error).message}`);
            b.setDisabled(false);
          }
        }),
    );
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

export class PickSecretModal extends FuzzySuggestModal<string> {
  constructor(
    app: App,
    private readonly ids: string[],
    private readonly onPick: (id: string) => void,
  ) {
    super(app);
    this.setPlaceholder("Secret to upload to Bitwarden");
  }
  getItems(): string[] {
    return this.ids;
  }
  getItemText(id: string): string {
    return id;
  }
  onChooseItem(id: string): void {
    this.onPick(id);
  }
}

interface ScopeChoice {
  label: string;
  scope: Scope;
}

export class PickScopeModal extends FuzzySuggestModal<ScopeChoice> {
  constructor(
    app: App,
    private readonly vaultName: string,
    private readonly onPick: (scope: Scope) => void,
  ) {
    super(app);
    this.setPlaceholder("Where should this secret be available?");
  }
  getItems(): ScopeChoice[] {
    return [
      { label: "Every vault on every device", scope: { kind: "global" } },
      { label: `Only vault "${this.vaultName}"`, scope: { kind: "vault", name: this.vaultName } },
      { label: "Only this device", scope: { kind: "device", id: "" } },
    ];
  }
  getItemText(c: ScopeChoice): string {
    return c.label;
  }
  onChooseItem(c: ScopeChoice): void {
    this.onPick(c.scope);
  }
}

export function summarize(report: SyncReport): string {
  const parts: string[] = [];
  if (report.pulled.length) parts.push(`${report.pulled.length} updated`);
  if (report.pushed.length) parts.push(`${report.pushed.length} uploaded`);
  if (report.created.length) parts.push(`${report.created.length} added to Bitwarden`);
  if (report.cleared.length) parts.push(`${report.cleared.length} cleared`);
  if (report.conflicts.length) parts.push(`${report.conflicts.length} conflict(s)`);
  if (report.skipped.length) parts.push(`${report.skipped.length} item(s) skipped`);
  if (report.errors.length) parts.push(`${report.errors.length} error(s)`);
  return parts.length ? parts.join(", ") : "everything is up to date";
}
