import { App, Notice, Platform, Plugin, PluginSettingTab, requestUrl, Setting } from "obsidian";
import type { HttpClient } from "./bw/http";
import { SECRET_CLIENT_ID, SECRET_CLIENT_SECRET, SecretsController, type Status } from "./controller";
import type { SecretStore, SyncReport } from "./sync/engine";
import type { ConflictOverride, ConflictPolicy } from "./sync/plan";
import { parseDeviceState, type DeviceState } from "./sync/state";
import { ConflictModal, PickScopeModal, PickSecretModal, summarize, UnlockModal } from "./ui";
import { DEFAULT_SETTINGS, parseSettings, type PluginSettings } from "./settings";

const STATE_KEY = "keychain-bitwarden:state";
const SETTINGS_KEY = "keychain-bitwarden:settings";

const STATUS_TEXT: Record<Status, string> = {
  locked: "🔒 Bitwarden",
  idle: "✓ Bitwarden",
  syncing: "⟳ Bitwarden",
  error: "⚠ Bitwarden",
  conflict: "⚠ Bitwarden conflicts",
};

const obsidianHttp: HttpClient = async (req) => {
  const res = await requestUrl({
    url: req.url,
    method: req.method,
    headers: req.headers,
    body: req.body,
    throw: false,
  });
  return { status: res.status, text: res.text };
};

export default class KeychainBitwardenPlugin extends Plugin {
  override settings: PluginSettings = { ...DEFAULT_SETTINGS };

  controller!: SecretsController;
  /** Last explicit user action (unlock, manual sync); drives auto-lock. */
  private lastActivity = Date.now();
  private lastSync = 0;
  private lastReport: SyncReport | null = null;

  override async onload(): Promise<void> {
    this.settings = parseSettings(this.app.loadLocalStorage(SETTINGS_KEY));
    const storage = this.app.secretStorage;
    const store: SecretStore = {
      get: (id) => storage.getSecret(id),
      set: (id, value) => storage.setSecret(id, value),
      list: () => storage.listSecrets(),
    };
    this.controller = new SecretsController({
      http: obsidianHttp,
      store,
      settings: () => this.settings,
      loadState: () => this.loadDeviceState(),
      saveState: (s) => this.app.saveLocalStorage(STATE_KEY, s),
      vaultName: this.app.vault.getName(),
      deviceName: `Obsidian (${Platform.isMobile ? (Platform.isIosApp ? "iOS" : "Android") : "desktop"})`,
    });

    if (!Platform.isMobile) {
      const bar = this.addStatusBarItem();
      bar.addClass("mod-clickable");
      bar.setText(STATUS_TEXT.locked);
      this.register(
        this.controller.onStatus((s, detail) => {
          bar.setText(STATUS_TEXT[s]);
          bar.setAttr("aria-label", detail ?? STATUS_TEXT[s]);
        }),
      );
      this.registerDomEvent(bar, "click", () => this.primaryAction());
    }

    this.addCommand({ id: "unlock", name: "Unlock", callback: () => this.openUnlock() });
    this.addCommand({
      id: "lock",
      name: "Lock",
      callback: () => {
        this.controller.lock();
        new Notice("Bitwarden locked");
      },
    });
    this.addCommand({ id: "sync", name: "Sync now", callback: () => void this.syncNow(true) });
    this.addCommand({ id: "upload", name: "Upload a secret to Bitwarden…", callback: () => this.openUpload() });
    this.addCommand({ id: "resolve-conflicts", name: "Resolve conflicts…", callback: () => this.openConflicts() });

    this.addSettingTab(new SettingsTab(this.app, this));

    this.app.workspace.onLayoutReady(() => void this.startup());

    this.registerInterval(
      window.setInterval(() => {
        const s = this.settings;
        const now = Date.now();
        if (s.autoLockMinutes > 0 && this.controller.isUnlocked && now - this.lastActivity > s.autoLockMinutes * 60_000) {
          this.controller.lock();
          return;
        }
        if (s.syncIntervalMinutes > 0 && this.controller.isUnlocked && now - this.lastSync > s.syncIntervalMinutes * 60_000) {
          void this.syncNow(false);
        }
      }, 30_000),
    );
    // Coming back to the app (desktop focus, mobile resume) is a good moment to pull changes.
    this.registerDomEvent(document, "visibilitychange", () => {
      if (document.visibilityState === "visible" && this.controller.isUnlocked) void this.syncNow(false);
    });
  }

  override onunload(): void {
    this.controller?.lock();
  }

  private loadDeviceState(): DeviceState {
    const raw: unknown = this.app.loadLocalStorage(STATE_KEY);
    const state = parseDeviceState(raw);
    // Persist a fresh state immediately so the device id stays stable.
    if (!raw) this.app.saveLocalStorage(STATE_KEY, state);
    return state;
  }

  async saveSettings(): Promise<void> {
    this.app.saveLocalStorage(SETTINGS_KEY, this.settings);
  }

  private async startup(): Promise<void> {
    if (!this.settings.email || !this.settings.rememberKey) return;
    try {
      if (await this.controller.unlockFromRememberedKey()) await this.syncNow(false);
    } catch (e) {
      new Notice(`Bitwarden: ${(e as Error).message}`);
    }
  }

  primaryAction(): void {
    if (!this.controller.isUnlocked) this.openUnlock();
    else if (this.controller.status === "conflict") this.openConflicts();
    else void this.syncNow(true);
  }

  openUnlock(): void {
    new UnlockModal(this.app, async (password) => {
      await this.controller.unlock(password);
      this.lastActivity = Date.now();
      await this.syncNow(true);
    }).open();
  }

  async syncNow(verbose: boolean, overrides?: Map<string, ConflictOverride>): Promise<void> {
    if (!this.controller.isUnlocked) {
      if (verbose) this.openUnlock();
      return;
    }
    if (verbose) this.lastActivity = Date.now();
    this.lastSync = Date.now();
    try {
      const report = await this.controller.sync(overrides);
      this.lastReport = report;
      const changed = report.pulled.length + report.pushed.length + report.created.length + report.cleared.length;
      if (verbose || changed || report.conflicts.length || report.errors.length) {
        new Notice(`Bitwarden: ${summarize(report)}`);
      }
      for (const err of report.errors) console.warn("[keychain-bitwarden]", err);
      for (const s of report.skipped) console.debug("[keychain-bitwarden] skipped", s.cipherId, s.reason);
      if (report.conflicts.length && this.settings.conflictPolicy === "ask" && verbose) this.openConflicts();
    } catch (e) {
      new Notice(`Bitwarden: ${(e as Error).message}`, 10_000);
    }
  }

  openConflicts(): void {
    const conflicts = this.lastReport?.conflicts ?? [];
    if (!conflicts.length) {
      new Notice("Bitwarden: no conflicts");
      return;
    }
    new ConflictModal(this.app, conflicts, (choices) => this.syncNow(true, choices)).open();
  }

  openUpload(): void {
    if (!this.controller.isUnlocked) {
      this.openUnlock();
      return;
    }
    const ids = this.controller.uploadCandidates();
    if (!ids.length) {
      new Notice("Bitwarden: every local secret is already synced");
      return;
    }
    new PickSecretModal(this.app, ids, (id) => {
      new PickScopeModal(this.app, this.app.vault.getName(), (scope) => {
        try {
          this.controller.queueUpload(id, scope);
          void this.syncNow(true);
        } catch (e) {
          new Notice(`Bitwarden: ${(e as Error).message}`);
        }
      }).open();
    }).open();
  }
}

class SettingsTab extends PluginSettingTab {
  constructor(
    app: App,
    private readonly plugin: KeychainBitwardenPlugin,
  ) {
    super(app, plugin);
  }

  override display(): void {
    const { containerEl } = this;
    const p = this.plugin;
    const storage = this.app.secretStorage;
    containerEl.empty();

    new Setting(containerEl).setName("Account").setHeading();
    new Setting(containerEl)
      .setName("Server URL")
      .setDesc("Your Bitwarden server: the US or EU cloud, or a self-hosted one.")
      .addText((t) =>
        t
          .setPlaceholder("https://vault.bitwarden.com")
          .setValue(p.settings.serverUrl)
          .onChange(async (v) => {
            p.settings.serverUrl = v.trim();
            await p.saveSettings();
          }),
      );
    new Setting(containerEl).setName("Email").addText((t) =>
      t.setValue(p.settings.email).onChange(async (v) => {
        p.settings.email = v.trim();
        await p.saveSettings();
      }),
    );
    const secretInput = (name: string, desc: string, id: string, part: "clientId" | "clientSecret") =>
      new Setting(containerEl)
        .setName(name)
        .setDesc(desc)
        .addText((t) => {
          t.inputEl.type = "password";
          t.inputEl.autocomplete = "off";
          t.setPlaceholder(storage.getSecret(id) ? "•••••• (saved)" : "").onChange((v) => {
            try {
              p.controller.setApiKey(part, v);
            } catch (e) {
              new Notice(`Bitwarden: ${(e as Error).message}`);
            }
          });
        });
    secretInput(
      "API key client_id",
      "From the Bitwarden web vault → Settings → Security → Keys → API key. It is only ever sent to the server above; " +
        "change the server and you will have to enter it again.",
      SECRET_CLIENT_ID,
      "clientId",
    );
    secretInput(
      "API key client_secret",
      "Kept in Obsidian's secret storage, which every installed plugin can read. With it, a plugin can download " +
        "your encrypted vault (not decrypt it).",
      SECRET_CLIENT_SECRET,
      "clientSecret",
    );

    new Setting(containerEl).setName("Sync").setHeading();
    new Setting(containerEl)
      .setName("Bitwarden folder")
      .setDesc("Login and secure note items in this folder become Obsidian secrets.")
      .addText((t) =>
        t.setValue(p.settings.folderName).onChange(async (v) => {
          p.settings.folderName = v.trim() || "obsidian";
          await p.saveSettings();
        }),
      );
    new Setting(containerEl)
      .setName("Sync interval (minutes)")
      .setDesc("Set to 0 to turn periodic sync off. Sync also runs when Obsidian comes back to the foreground.")
      .addText((t) =>
        t.setValue(String(p.settings.syncIntervalMinutes)).onChange(async (v) => {
          const n = Number.parseInt(v, 10);
          p.settings.syncIntervalMinutes = Number.isFinite(n) && n >= 0 ? n : 10;
          await p.saveSettings();
        }),
      );
    new Setting(containerEl).setName("When both sides changed").addDropdown((d) =>
      d
        .addOption("ask", "Ask me")
        .addOption("prefer-remote", "Bitwarden wins")
        .addOption("prefer-local", "This device wins")
        .setValue(p.settings.conflictPolicy)
        .onChange(async (v) => {
          p.settings.conflictPolicy = v as ConflictPolicy;
          await p.saveSettings();
        }),
    );

    new Setting(containerEl).setName("Security").setHeading();
    new Setting(containerEl)
      .setName("Remember unlock on this device")
      .setDesc(
        "Keeps your Bitwarden account key in Obsidian's secret storage so you are not asked for the master password " +
          "at every start. Every installed plugin can read that storage, and together with the API key the account key " +
          "decrypts your WHOLE Bitwarden vault, not just this folder. Only enable it on a device you trust, with plugins you trust.",
      )
      .addToggle((t) =>
        t.setValue(p.settings.rememberKey).onChange(async (v) => {
          p.settings.rememberKey = v;
          if (!v) p.controller.forgetRememberedKey();
          await p.saveSettings();
        }),
      );
    new Setting(containerEl)
      .setName("Auto-lock after (minutes)")
      .setDesc("Set to 0 to stay unlocked until Obsidian closes.")
      .addText((t) =>
        t.setValue(String(p.settings.autoLockMinutes)).onChange(async (v) => {
          const n = Number.parseInt(v, 10);
          p.settings.autoLockMinutes = Number.isFinite(n) && n >= 0 ? n : 0;
          await p.saveSettings();
        }),
      );

    new Setting(containerEl).setName("Actions").setHeading();
    new Setting(containerEl)
      .setName(p.controller.isUnlocked ? "Unlocked" : "Locked")
      .setDesc(`Device id: ${p.controller.deviceId()}`)
      .addButton((b) =>
        b.setButtonText(p.controller.isUnlocked ? "Lock" : "Unlock").onClick(() => {
          if (p.controller.isUnlocked) p.controller.lock();
          else p.openUnlock();
          this.display();
        }),
      )
      .addButton((b) => b.setButtonText("Sync now").setCta().onClick(() => void p.syncNow(true)));
    new Setting(containerEl)
      .setName("Reset sync state")
      .setDesc("Forget what was synced on this device. Secrets themselves are kept; the next sync re-matches them.")
      .addButton((b) =>
        b
          .setButtonText("Reset")
          .setWarning()
          .onClick(() => {
            try {
              p.controller.resetState();
              new Notice("Bitwarden: sync state reset");
            } catch (e) {
              new Notice(`Bitwarden: ${(e as Error).message}`);
            }
          }),
      );
  }
}
