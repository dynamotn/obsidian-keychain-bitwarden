import {
  SECRET_API_ORIGIN,
  SECRET_CLIENT_ID,
  SECRET_CLIENT_SECRET,
  SecretsController,
  type ControllerSettings,
} from "../../src/controller";
import { resolveServerUrls } from "../../src/bw/api";
import type { Argon2Runner } from "../../src/bw/argon2";
import type { HttpClient } from "../../src/bw/http";
import type { SecretStore } from "../../src/sync/engine";
import { parseDeviceState, type DeviceState } from "../../src/sync/state";

const ID_RULE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Mimics Obsidian's SecretStorage, including its id validation. */
export class MemorySecretStore implements SecretStore {
  readonly values = new Map<string, string>();
  get(id: string): string | null {
    return this.values.get(id) ?? null;
  }
  set(id: string, value: string): void {
    if (!ID_RULE.test(id)) throw new Error(`Invalid secret id: ${id}`);
    this.values.set(id, value);
  }
  list(): string[] {
    return [...this.values.keys()];
  }
}

export interface TestDevice {
  controller: SecretsController;
  store: MemorySecretStore;
  settings: ControllerSettings;
  localStorage: Map<string, unknown>;
  state(): DeviceState;
}

export function makeDevice(
  http: HttpClient,
  account: { email: string; clientId: string; clientSecret: string },
  opts: {
    vaultName?: string;
    serverUrl?: string;
    settings?: Partial<ControllerSettings>;
    argon2?: Argon2Runner;
  } = {},
): TestDevice {
  const store = new MemorySecretStore();
  store.set(SECRET_CLIENT_ID, account.clientId);
  store.set(SECRET_CLIENT_SECRET, account.clientSecret);
  store.set(SECRET_API_ORIGIN, new URL(resolveServerUrls(opts.serverUrl ?? "https://bw.test").identity).origin);
  const settings: ControllerSettings = {
    serverUrl: opts.serverUrl ?? "https://bw.test",
    email: account.email,
    folderName: "obsidian",
    conflictPolicy: "ask",
    rememberKey: false,
    ...opts.settings,
  };
  const localStorage = new Map<string, unknown>();
  const loadState = () => {
    const raw = localStorage.get("state");
    const s = parseDeviceState(raw === undefined ? undefined : structuredClone(raw));
    if (raw === undefined) localStorage.set("state", structuredClone(s));
    return s;
  };
  const controller = new SecretsController({
    http,
    store,
    settings: () => settings,
    loadState,
    saveState: (s) => localStorage.set("state", structuredClone(s)),
    vaultName: opts.vaultName ?? "notes",
    deviceName: "test",
    argon2: opts.argon2,
  });
  return { controller, store, settings, localStorage, state: loadState };
}
