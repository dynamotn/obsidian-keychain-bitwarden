# Bitwarden Secrets for Obsidian

Keeps Obsidian's secret storage (the keychain plugins use for API keys and
tokens, Obsidian 1.11.4+) in sync with one folder of your Bitwarden vault, on
desktop, iOS and Android.

Obsidian deliberately does not sync secret storage between devices. This
plugin makes Bitwarden the place where those secrets live: add a secret once,
and it appears on every device where the plugin is unlocked. Other plugins
keep reading `app.secretStorage` as usual and need no changes.

Design, security review, test results and performance figures are in
[`docs/obsidian-plugin.md`](../docs/obsidian-plugin.md).

## How it maps

- Every **login** or **secure note** item in the Bitwarden folder (default
  `obsidian`) becomes a secret.
- **Secret id**: the item's `obsidian-id` custom field, or else the item name.
  Either way it must be lowercase letters, digits and dashes, like
  `openai-api-key`.
- **Value**: the login password, or the secure note's notes.
- **Scope**: an optional `obsidian-scope` field limits where the secret
  appears:
  - `global` (default): every vault on every device;
  - `vault:<name>`: only the vault with that name;
  - `device:<id>`: only one device. The device id is shown in the settings.
- Secrets that exist only on this device are never uploaded on their own.
  Use **Upload a secret to Bitwarden…** to choose which ones go up.

## Setup

1. In the Bitwarden web vault, go to *Settings → Security → Keys → View API
   key*.
2. In the plugin settings, enter:
   - the server URL (`https://vault.bitwarden.com`, `https://vault.bitwarden.eu`
     or a self-hosted server);
   - your email;
   - the API key's `client_id` and `client_secret`.
3. Run **Bitwarden Secrets: Unlock** and enter your master password. The
   password never leaves the device. It derives the key that decrypts the
   folder, and the API key only authenticates.

## Sync rules

The plugin does a three-way comparison of Bitwarden, this device, and what
both looked like at the last sync:

| Bitwarden | This device | Result |
|---|---|---|
| changed | unchanged | updated here |
| unchanged | changed | uploaded |
| changed | changed (differently) | conflict: you choose, or the configured policy decides |
| item trashed | unchanged | cleared here (set to empty: secret storage cannot delete) |
| item unreadable (newer format, moved to an org, renamed) | any | left alone, reported as skipped |
| new | a different value exists that was never synced | conflict, regardless of the policy |

Safety rails:

- Sync stops instead of acting when:
  - the folder disappears;
  - it is replaced by a different folder;
  - more than half of the synced secrets would be cleared at once.
- A secret you edit while a sync runs is not overwritten.
- Editing a value keeps the rest of the Bitwarden item intact: username,
  URIs, notes, custom fields, attachments and properties this plugin does
  not know about. For logins, the old password goes to the password history.

## Security notes

- Settings and sync state live in this device's vault `localStorage`, not
  in `data.json`. `data.json` is often synced or committed, and whoever can
  edit it must not be able to redirect your API key.
- The API key is bound to the server it was entered for. Changing the
  server URL requires entering the key again.
- Every installed plugin can read Obsidian's secret storage. That includes
  the API key and, if you enable **Remember unlock on this device**, your
  account key. Together they decrypt your **whole** vault, not just this
  folder. Keep that option off unless you trust the device and every plugin
  on it.
- Only Bitwarden's authenticated encryption (type 2, AES-CBC + HMAC) is
  accepted. KDF parameters from the server are range-checked, so a server
  cannot downgrade the KDF or set it to an absurd cost.

## Limitations

- Organization items and the newer COSE item encryption (type 7) are not
  supported; such items are skipped and kept as they are.
- Obsidian on mobile has been reported to share secret storage across vaults
  ([forum](https://forum.obsidian.md/t/secretstorage-appears-to-be-shared-across-vaults-on-mobile-but-vault-scoped-on-desktop/117793)),
  so a `vault:` scope cannot isolate secrets between vaults there.
- A very expensive Argon2 setting (close to the 1 GiB maximum Bitwarden
  allows) runs on the main thread and can freeze a phone for a while during
  unlock.

## Development

```sh
npm install
npm run build              # typecheck + production bundle (main.js)
npm run check:bundle       # bundle may only require "obsidian", no Node globals
npm test                   # unit + multi-device sync tests (in-memory Bitwarden)
npm run test:browser       # the same suites in WebKit (≈ iOS) and Chromium (≈ Android)
npm run perf               # performance budgets (add :browser for WebKit/Chromium)

# Against a real server, cross-checked with rbw and the official Bitwarden CLI:
docker run -d --rm --name bw-secrets-it -p 127.0.0.1:18080:80 \
  -e SIGNUPS_ALLOWED=true -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest
BW_IT_URL=http://127.0.0.1:18080 npm run test:integration
```

The crypto known-answer vectors in `test/fixtures/vectors.json` come from an
independent Python implementation, `test/fixtures/gen_vectors.py`. To
regenerate them:

```sh
uv run --no-project --with cryptography --with argon2-cffi python test/fixtures/gen_vectors.py
```
