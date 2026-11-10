# M6 test map (draft)

Every test that M6 replaces or removes, with the test that now covers it. No row without a covering test.
Draft: Task 9 (the controller on dybw-core) fills the controller, sync, organizations and sync-shape rows; Task 11
adds the hub rows, Task 12 the `src/bw`/`src/sync` unit suites it deletes.

Until Task 12 deletes `src/bw` and `src/sync`, the suites written for them keep running unchanged in
`test/legacy/`, on a copy of the old controller (`test/legacy/controller.ts`), so that code stays covered at 100%.
`test/engine.test.ts` and `test/integration/vaultwarden.test.ts` still use that copy (`test/legacy/device.ts`):
the engine suite goes with `src/sync` (Task 12), the Vaultwarden suite is ported in Task 13.

The four "unlocking with a cancellable derivation" tests of `test/argon2.test.ts` run on the new controller, same
file and names: the Argon2 port's abort signal is the unlock's.

## What changed in the ported assertions

The scenarios are the same; what they assert follows the core where it reports differently:

- Errors are typed by code (`src/core/errors.ts`): a wrong password is `WrongPasswordError`, a mass clear
  `MassClearError` with `clears` and `base`, a lock during a sync `LockedError`, an HTTP failure `ApiError` with
  `status`. The report's `errors` are `{id, error}`.
- Skipped items carry the core's reason codes (`wrong-type`, `reserved-id`, `unknown-encoding`,
  `unknown-location`, `invalid-id`, `view-password-hidden`). Duplicates are in `duplicates`, held items (blob,
  item key or value no longer usable) in `held`, items an organization does not let the user edit in `readOnly`,
  undecryptable items in `unreadable`; a sync that kept seeing changes sets `keptChanging` and a warning instead of
  an error. An `obsidian:scope` the plugin cannot read applies nowhere, without a report.
- Organization keys are read at unlock: an unreadable organization key or a missing private key is in the unlock
  summary's `orgProblems`, once, not in every sync's errors; tests that change organizations unlock a device after.
- ADR 0016: the first write-back into a login's own password asks (`questions`); the ported tests answer
  `write-to-login` on the next sync.
- A COSE ("v2") account's new item is encrypted as a whole (a blob) that the test crypto cannot read: those
  assertions read the item back through another device instead, and such an upload has no field or notes limit.
- An item without a name is labelled with its id; a pushed item keeps a missing `secureNote` part missing; when a
  value moves into the notes, the first `obsidian:location` becomes `notes` and the others stay.

## Per test

### `test/controller.test.ts` (before M6; kept as `test/legacy/controller.test.ts` until Task 12)

| Test | Covered by |
|---|---|
| SecretsController > status > reports every change to listeners until they unsubscribe | `test/controller.test.ts`, same name, on the core |
| SecretsController > unlock > needs the account email before contacting the server | `test/controller.test.ts`, same name, on the core |
| SecretsController > unlock > stops before deriving the key when cancelled | `test/controller.test.ts`, same name, on the core |
| SecretsController > unlock > lets a lock that arrives while the key is derived win | `test/controller.test.ts`, same name, on the core |
| SecretsController > API key > refuses a key that was never bound to a server, without sending it | `test/controller.test.ts`, same name, on the core |
| SecretsController > remembered key > is not used when there is none | `test/controller.test.ts`, same name, on the core |
| SecretsController > remembered key > is not used once remembering is turned off | `test/controller.test.ts`, same name, on the core |
| SecretsController > remembered key > is dropped when it is not base64 | `test/controller.test.ts`, same name, on the core |
| SecretsController > remembered key > is dropped when it is a key of the wrong size | `test/controller.test.ts`, same name, on the core |
| SecretsController > sync > refuses to run while locked | `test/controller.test.ts`, same name, on the core |
| SecretsController > sync > merges the conflict choices of every call queued behind a running sync | `test/controller.test.ts`, same name, on the core |
| SecretsController > sync > still runs a queued sync when the running one fails | `test/controller.test.ts`, same name, on the core |
| SecretsController > sync > reports a lock during the last write as a cancellation, not as a result | `test/controller.test.ts`, same name, on the core |
| SecretsController > uploads > refuses a secret that does not exist on this device | `test/controller.test.ts`, same name, on the core |
| SecretsController > uploads > queues a secret once, keeping the latest scope | `test/controller.test.ts`, same name, on the core |
| SecretsController > resetState > forgets the sync state but keeps the device id | `test/controller.test.ts`, same name, on the core |
| SecretsController > resetState > refuses while a sync is running | `test/controller.test.ts` › SecretsController > resetState > waits for a running sync, then resets (ruling: `resetState` queues behind a running sync instead of refusing) |
| SecretsController > notificationsHubUrl > authenticates the hub with the current session | `test/controller.test.ts` › SecretsController > notifications hub > authenticates the hub with the current session (the core's `runHub` opens the socket with the sync's token) |
| SecretsController > notificationsHubUrl > fails while locked, without contacting the server | `test/controller.test.ts` › SecretsController > notifications hub > fails while locked, without contacting the server |

### `test/sync.test.ts` (before M6; kept as `test/legacy/sync.test.ts` until Task 12)

| Test | Covered by |
|---|---|
| with a %s account key > unlock > rejects a wrong master password | `test/sync.test.ts`, same name, on the core |
| with a %s account key > unlock > rejects a wrong API key | `test/sync.test.ts`, same name, on the core |
| with a %s account key > unlock > works with Argon2id accounts | `test/sync.test.ts`, same name, on the core |
| with a %s account key > unlock > never sends the master password or anything derived from it | `test/sync.test.ts`, same name, on the core |
| with a %s account key > unlock > remembers the key only when asked, and drops a stale one | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > pulls items created by other Bitwarden clients, including per-item keys and logins | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > uploads on one device and delivers to another | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > is idempotent | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > only uploads what was explicitly queued | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > keeps the rest of an item intact when pushing a new value | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > pushes through per-item keys | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > reports conflicts and resolves them per secret | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > retries when another device edits during the push | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > clears a secret deleted in Bitwarden | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > refuses to wipe the device when every item disappears | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > syncs marked items in any folder, or none, and ignores folders entirely | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > blob-encrypted items > holds an item that was synced and then rewritten as a blob, instead of clearing it | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > blob-encrypted items > is not fooled by an Object.prototype.format_version set by another plugin | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > blob-encrypted items > neither adopts nor reports a new blob item | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > blob-encrypted items > still reads a legacy item whose data is not a blob | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > stops syncing an item once its obsidian:id field is removed | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > reads and writes the value in an obsidian:password field when there is one | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > skips items storing base64, which secret storage cannot hold | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > reads a blank or valueless obsidian:encoding as no encoding | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > upload into the notes of the new item, marked obsidian:location=notes, and sync back | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > move out of an obsidian:password field into empty notes, dropping every copy of the field | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > fail without touching anything when the notes hold the user's text, or nothing fits | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > never overwrite the user's notes when obsidian:location is empty | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > never overwrite the user's notes when obsidian:location is whitespace | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > never overwrite the user's notes when obsidian:location is without a value | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > keep a login's value in its own password when obsidian:location is empty | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > keep a login's value in its own password when obsidian:location is whitespace | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > move into empty notes over an empty obsidian:location, setting it to notes | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > clear a stale copy in the notes when a value from obsidian:password fits again | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > drop every obsidian:location with the stale notes, so a duplicate never takes over | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > leave exactly one obsidian:location=notes when a value moves into the notes | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > values too long for a field > refuse an upload too long even for the notes, and keep it queued | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > files uploads in the configured folder, or in none | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > respects vault and device scopes | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > stores device-scoped uploads under this device's id | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > never lets Bitwarden overwrite the plugin's own credentials | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > keeps credentials left under the pre-rename prefix out of sync and uploads | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > skips undecryptable or invalid items without failing the sync | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > uses the oldest of duplicate ids on every device, however they are edited | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > stores a new upload in an obsidian:password field, leaving the notes free | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > queues a call made during a running sync instead of dropping it | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > keeps state per device, outside anything that gets synced | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > prefers a duplicate with a creation date, then the lowest item id | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > skips marked items other than logins and secure notes | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > reads a field or item part the server sends without a value as empty | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > pushes to items missing their login or secure note part | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > uploads and pushes an empty secret as no value | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > gives up after three passes when an item keeps changing under the push | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > forgets a secret gone from both Bitwarden and this device, and a queued upload whose value is gone | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > uploads with the global scope when the queued scope is not one it knows | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > keeps a secret whose item key can no longer be unwrapped instead of clearing it | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > does not clear a secret edited while the sync is running | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > keeps a secret whose item became unreadable instead of clearing it | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > never overwrites either side for a never-synced local value, whatever the policy | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > ignores a conflict choice once the conflict changed kind | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > keeps the scope when a deleted secret is uploaded again | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > does not overwrite a local edit made while the sync is running | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > refuses to clear most secrets at once | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > refuses to clear exactly half of the secrets at once | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > still clears one secret deleted on its own | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > only sends the API key to the server it was entered for | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > keeps the API key through a passing change of server, sending it only to its own | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > does not carry one part of the API key over to another server | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > files uploads in the same folder on every device when several share the name | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > stops a running sync when locked | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > refuses a remembered key it cannot verify | `test/sync.test.ts`, same name, on the core |
| with a %s account key > sync between devices > audit regressions > keeps unknown item properties when pushing | `test/sync.test.ts`, same name, on the core |

### `test/organizations.test.ts` (before M6; kept as `test/legacy/organizations.test.ts` until Task 12)

| Test | Covered by |
|---|---|
| with a %s account key > organization items > are left alone unless enabled | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are pulled with the organization's key | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > accept organization keys wrapped with RSA-OAEP SHA-256 too | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are pushed back encrypted for the organization, which keeps the item | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are only pulled when the organization does not allow editing | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are skipped when the organization hides the password | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > never take over a personal secret with the same id, even when newer | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are skipped while the membership is not confirmed | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > never upload a pending secret into an organization item claiming its id | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > never let an organization item silently take over a secret whose personal item was deleted | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > never send a later local value to an organization item that was pulled without asking | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > push to an organization item once confirmed, and then without asking again | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > take the organization's value when the first push is declined | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > ask before the first push even when a confirmed claim bound the id | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > report an organization key that cannot be read, and personal items still sync | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > report an unreadable organization key once, even when the sync takes another pass | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > report an account without a private key, and personal items still sync | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are left alone when their organization is disabled | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are not needed for personal items to sync when the server lists no organizations | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named by the organization's id when it has no name | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named without control characters and line breaks, as their owners chose the name | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named without characters that reorder text, as their owners chose the name | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named without runs of spaces, as their owners chose the name | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named without more than 64 characters, as their owners chose the name | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named by the organization's id when its name is nothing but control characters | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are named by the organization's id when its name is missing | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > stop taking pushes once the organization takes the right to edit away, even after a confirmation | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > upload nothing when a claim is declined for a secret this device no longer holds | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > organization items > are never where new uploads go | `test/organizations.test.ts`, same name, on the core |
| with a %s account key > account private key > refuses anything but RSA-OAEP organization keys | dybw-core `crates/dybw-core/src/crypto/rsa_mark_tests.rs::org_keys_unwrap` (types 2, 5, 6, no type, bad base64 refused) and `org_key_type_picks_the_hash` |

### `test/sync-shape.test.ts` (before M6; kept as `test/legacy/sync-shape.test.ts` until Task 12)

| Test | Covered by |
|---|---|
| the newer sync response, %s account key > unlocks and syncs with the keys where newer servers put them | `test/sync-shape.test.ts`, same name, on the core |
| the newer sync response, %s account key > uses the master key salt the server gives, not the email | `test/sync-shape.test.ts`, same name, on the core |
| the newer sync response, %s account key > reads the private key from accountKeys, for organizations and the remembered key | `test/sync-shape.test.ts`, same name, on the core |
