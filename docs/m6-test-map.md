# M6 test map

Every test that M6 replaced or removed, with the test that now covers it. No row without a covering test.
Core tests are named at dybw-core `cd962fa` (the rev in `core.rev`), paths under `crates/`; plugin tests by file
and full name.

M6 removed the plugin's own Bitwarden code (`src/bw/` but the Argon2 runner and its worker, and `src/sync/`) and the
suites written for it, with the fixtures only they read; the controller runs on the core. The core runs its
conformance vectors and crypto known answers in WASM, in Node, Chromium and WebKit, on every CI run
(`dybw-core-wasm/js/test/vectors.test.ts` over `runVectors`/`runKnownAnswers`), from `vectors/crypto/`, where the
fixtures the plugin dropped live byte-identical. `test/fixtures/vectors.json` stays for the Argon2 known answer of
`test/argon2.test.ts`; the frozen test crypto under `test/helpers/bw/` stays as the fake server's and the
Vaultwarden account's oracle.

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

### `test/controller.test.ts` (before M6)

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

### `test/sync.test.ts` (before M6)

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

### `test/organizations.test.ts` (before M6)

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

### `test/sync-shape.test.ts` (before M6)

| Test | Covered by |
|---|---|
| the newer sync response, %s account key > unlocks and syncs with the keys where newer servers put them | `test/sync-shape.test.ts`, same name, on the core |
| the newer sync response, %s account key > uses the master key salt the server gives, not the email | `test/sync-shape.test.ts`, same name, on the core |
| the newer sync response, %s account key > reads the private key from accountKeys, for organizations and the remembered key | `test/sync-shape.test.ts`, same name, on the core |

### `test/notifications.test.ts` (before M6)

The hub is the core's (`runHub`, `crates/dybw-core/src/api/hub.rs`): the protocol rows are core tests in
`crates/dybw-core/src/api/msgpack_tests.rs` and `hub_tests.rs` (dybw-core `cd962fa`); the plugin's own rows, through
the controller, its socket port and the real core, are in `test/hub.test.ts`. Ruling: `wake()` starts a running hub
over (stop + restart) instead of only waking one that is down, so a socket a suspend killed silently is replaced too.

| Test | Covered by |
|---|---|
| MessagePack decoder (vectors from the Python msgpack library) > (each of the 46 vectors) | dybw-core `msgpack_tests.rs::msgpack_kat`, over the same `vectors/crypto/msgpack.json` (byte-identical) |
| MessagePack decoder > decodes a real Vaultwarden notification | dybw-core `hub_tests.rs::understands_the_frame_vaultwarden_actually_sends`; `test/hub.test.ts` › notifications hub client > understands the frame Vaultwarden actually sends |
| MessagePack decoder > decodes %s (bin 32, map 32, int 64 within and beyond the safe range) | dybw-core `msgpack_tests.rs::msgpack_wide_headers` and `msgpack_kat` (int 64 vectors) |
| MessagePack decoder > keeps the type and bytes of an application %s | dybw-core `msgpack_tests.rs::msgpack_ext_and_int_keys` and `msgpack_wide_headers` |
| MessagePack decoder > rejects %s | dybw-core `msgpack_tests.rs::msgpack_rejects` and `msgpack_huge_array_header_fails_without_allocating` |
| MessagePack decoder > rejects deep nesting instead of overflowing the stack | dybw-core `msgpack_tests.rs::msgpack_rejects` ("depth 33") |
| MessagePack decoder > does not let map keys reach the object prototype | dybw-core `msgpack_tests.rs::msgpack_ext_and_int_keys` (a map is a list of pairs in Rust: no prototype; no JS object is built from a notification any more) |
| SignalR framing > splits several length-prefixed messages | dybw-core `msgpack_tests.rs::signalr_frames` |
| SignalR framing > reads multi-byte lengths | dybw-core `msgpack_tests.rs::signalr_frames` |
| SignalR framing > rejects %s | dybw-core `msgpack_tests.rs::signalr_frames` |
| SignalR framing > rejects oversized messages | dybw-core `msgpack_tests.rs::signalr_frames` |
| hub URLs > %s | dybw-core `hub_tests.rs::hub_urls`; `test/controller.test.ts` › SecretsController > notifications hub > authenticates the hub with the current session |
| notifications hub client > negotiates MessagePack, then reports a change made elsewhere | `test/hub.test.ts`, same name, on the core; dybw-core `hub_tests.rs::negotiates_messagepack_then_reports_a_change_made_elsewhere` |
| notifications hub client > understands the frame Vaultwarden actually sends | `test/hub.test.ts`, same name, on the core; dybw-core `hub_tests.rs::understands_the_frame_vaultwarden_actually_sends` |
| notifications hub client > accepts the handshake and a first message in one frame | dybw-core `hub_tests.rs::accepts_the_handshake_and_a_first_message_in_one_frame` |
| notifications hub client > ignores changes this device made itself, and non-vault notifications | `test/hub.test.ts`, same name, on the core, with the device's own id; and › ignores changes an upgraded device made itself, under the id it had before the core; dybw-core `hub_tests.rs::ignores_changes_this_device_made_itself_and_other_push_types` |
| notifications hub client > coalesces a burst and spaces reports out | `test/hub.test.ts`, same name, on the core, and › syncs once for a change pushed by another device; dybw-core `hub_tests.rs::coalesces_a_burst_and_spaces_reports_out` |
| notifications hub client > sends pings while connected | `test/hub.test.ts`, same name, on the core; dybw-core `hub_tests.rs::sends_pings_while_connected` |
| notifications hub client > reconnects with growing delays after the connection drops | `test/hub.test.ts`, same name, on the core (first two delays); dybw-core `hub_tests.rs::reconnects_with_growing_delays_after_the_connection_drops` |
| notifications hub client > keeps backing off from a server that accepts the handshake, then closes at once | dybw-core `hub_tests.rs::keeps_backing_off_from_a_server_that_accepts_the_handshake_then_closes_at_once` |
| notifications hub client > reconnects when the server goes silent | dybw-core `hub_tests.rs::reconnects_when_the_server_goes_silent` |
| notifications hub client > starts over after %s (a refused handshake, a malformed handshake) | dybw-core `hub_tests.rs::starts_over_after_a_refused_or_malformed_handshake` |
| notifications hub client > starts over after malformed MessagePack | dybw-core `hub_tests.rs::starts_over_after_malformed_messagepack_and_reports_nothing` |
| notifications hub client > starts over when the server sends Close | dybw-core `hub_tests.rs::starts_over_when_the_server_sends_close_and_reconnects_once_for_two`, `run_hub_follows_a_close_from_the_server` |
| notifications hub client > retries later when no URL can be had (for example while logging in fails) | dybw-core `hub_tests.rs::run_hub_backs_off_when_no_url_can_be_had_or_the_connect_fails` |
| notifications hub client > stops for good: no reconnect and no late reports | `test/hub.test.ts`, same name, on the core, and › stops when locked, and never reconnects with the old token; dybw-core `hub_tests.rs::run_hub_stops_during_the_wait_for_a_reconnect` |
| notifications hub client > with timers that may still fire after being cleared > reports no change once stopped | `test/hub.test.ts` › stops for good: no reconnect and no late reports (the core checks `stop` before reporting; the plugin's `sleepMs` ends on the hub's signal) |
| notifications hub client > with timers that may still fire after being cleared > does not reconnect once stopped | `test/hub.test.ts` › stops for good: no reconnect and no late reports; dybw-core `hub_tests.rs::run_hub_stops_during_the_wait_for_a_reconnect` |
| notifications hub client > with timers that may still fire after being cleared > never pings a new socket before its handshake | dybw-core `dybw-core/src/api/hub_tests.rs:92` (`negotiates_messagepack_then_reports_a_change_made_elsewhere`: `on_open` sends only the handshake and pings start once it is answered) and `:501` (`run_hub_follows_a_close_from_the_server`: a socket that never finished its handshake was sent "only the handshake") |
| notifications hub client > wakes up at once instead of waiting for the next attempt | `test/hub.test.ts`, same name, on the core (`SecretsController.wake`) |
| notifications hub client > ignores a stale socket's events after reconnecting | `test/core/ports.test.ts` › socket ports > close closes the socket, ends a waiting recv with null and forgets the id (a closed socket's id is forgotten: its late frames reach no `recv`) |
| notifications hub client > ignores a stale socket's open, error and close events after reconnecting | `test/core/ports.test.ts` › socket ports > close closes the socket, ends a waiting recv with null and forgets the id |
| notifications hub client > keeps its connection when started again | `test/hub.test.ts`, same name, on the core |
| notifications hub client > does not wake a connection that is up, or a hub that was stopped | `test/hub.test.ts` › does not wake a hub that was stopped; the first half is changed by the ruling above: › starts a connection that looks up over when woken, › keeps one connection when woken twice in a row, › stays stopped when locked right after a wake |
| notifications hub client > opens one socket when woken while the first URL is still on its way | `test/hub.test.ts` › starts a connection that looks up over when woken (the stopped run closes its socket at its next stop check; one socket stays open) |
| notifications hub client > does not retry for a URL request that an earlier wake superseded | `test/hub.test.ts` › starts a connection that looks up over when woken (the core reads the URL from its own keys, without a request: nothing to supersede) |
| notifications hub client > opens no socket when stopped while the URL is on its way | `test/controller.test.ts` › SecretsController > notifications hub > fails while locked, without contacting the server; dybw-core `hub_tests.rs::run_hub_stops_during_the_wait_for_a_reconnect` |
| notifications hub client > retries later when the socket cannot be created | `test/hub.test.ts`, same name, on the core; dybw-core `hub_tests.rs::run_hub_backs_off_when_no_url_can_be_had_or_the_connect_fails` |
| notifications hub client > starts over after a socket error | `test/hub.test.ts`, same name, on the core; dybw-core `hub_tests.rs::run_hub_reconnects_after_the_socket_ends_or_fails` |
| notifications hub client > starts over when a ping cannot be sent | dybw-core `hub_tests.rs::run_hub_starts_over_after_a_send_fails` |
| notifications hub client > accepts the handshake as a text frame, and ignores text after it | dybw-core `hub_tests.rs::accepts_the_handshake_as_a_text_frame_and_ignores_text_after_it` |
| notifications hub client > starts over after a message of a type the socket should never deliver | `test/core/ports.test.ts` › socket ports > queues frames in order, text and binary, until recv takes them (the port hands only text or bytes to the core) |
| notifications hub client > stays connected and reports nothing for %s | dybw-core `hub_tests.rs::stays_connected_and_reports_nothing_for_messages_it_does_not_act_on` |
| notifications hub client > reconnects once when one message closes the connection twice | dybw-core `hub_tests.rs::starts_over_when_the_server_sends_close_and_reconnects_once_for_two` |
| notifications hub client with the default timers > schedules retries on window timers and clears them on stop | `test/core/ports.test.ts` › sleepMs resolves after its time, › sleepMs ends at once on the hub's stop signal, also one aborted before, and never rejects |

### `test/api.test.ts` (before M6; `src/bw/api.ts`, `src/bw/vault.ts`, `src/sync/state.ts`)

| Test | Covered by |
|---|---|
| resolveServerUrls > maps the Bitwarden clouds and self-hosted servers | dybw-core `dybw-core/src/api/client_tests.rs::resolve_urls`, `::the_cloud_identity_origins_are_what_resolve_server_urls_maps` |
| resolveServerUrls > refuses plain http to remote hosts and embedded credentials | dybw-core `client_tests.rs::resolve_urls`, `::origins_are_scheme_host_and_port` |
| normalizeKeys > lower-cases the first letter of every key, recursively | dybw-core `client_tests.rs::normalize_keys_lowercases_first_letter_recursively`, `::put_reply_is_normalized` |
| normalizeKeys from an untrusted server > never lets a __proto__ key replace an object's prototype | dybw-core `client_tests.rs::normalize_keys_lowercases_first_letter_recursively` (serde_json maps: a `__proto__` key is a key like any other; no JS object is built from a server answer any more) |
| BitwardenApiError > recognises out-of-date edits | dybw-core `client_tests.rs::errors_shaped` (`is_out_of_date`); `test/sync.test.ts` › … retries when another device edits during the push |
| parseScope > parses known scopes and rejects others | dybw-core `dybw-core/src/sync/engine_tests.rs::scopes_are_read_as_the_plugin_parses_them`; `test/sync.test.ts` › … respects vault and device scopes |
| parseDeviceState > keeps the device id but drops malformed content | dybw-core `dybw-core/src/sync/state_tests.rs::drops_parts_that_are_not_of_the_right_kind`, `::a_stored_device_id_never_asks_for_a_fresh_one` |
| parseDeviceState > drops ids that break the id rule or are reserved for the plugin | dybw-core `state_tests.rs::drops_entries_the_plugin_drops`, `::the_namespace_decides_which_ids_are_synced` |
| parseDeviceState > keeps a confirmation to push to an organization item, and only a true one | dybw-core `state_tests.rs::drops_entries_the_plugin_drops` (a non-true `pushConfirmed` is dropped), `::plugin_state_round_trips` |

### `test/api-client.test.ts` (before M6; `src/bw/api.ts`)

| Test | Covered by |
|---|---|
| BitwardenApi > prelogin > reads PBKDF2 and Argon2id parameters | dybw-core `client_tests.rs::prelogin_parses_both_kdfs` |
| BitwardenApi > prelogin > leaves missing Argon2id parameters at zero, for key derivation to reject | dybw-core `client_tests.rs::prelogin_parses_both_kdfs`; `dybw-core/src/crypto/tests.rs::kdf_bounds` |
| BitwardenApi > prelogin > refuses a KDF it does not know | dybw-core `client_tests.rs::prelogin_parses_both_kdfs` |
| BitwardenApi > loginWithApiKey > sends the client credentials and this device, then keeps the token | dybw-core `client_tests.rs::login_sends_client_credentials`, `::api_key_bound_to_origin` |
| BitwardenApi > loginWithApiKey > assumes an hour when the server does not say how long the token lasts | dybw-core `client_tests.rs::the_token_is_renewed_a_minute_before_it_expires`, `::a_short_lived_token_lasts_a_minute` |
| BitwardenApi > loginWithApiKey > refuses an answer without an access token | dybw-core `client_tests.rs::login_refuses_answers_without_a_token` |
| BitwardenApi > authenticated calls > are refused before logging in, without reaching the server | dybw-core `client_tests.rs::calls_need_a_login_and_send_nothing_without` |
| BitwardenApi > authenticated calls > are refused again once the token expired or after logging out | dybw-core `client_tests.rs::the_token_is_renewed_a_minute_before_it_expires`, `::a_failed_renewal_surfaces_and_sends_nothing_else`; `test/hub.test.ts` › stops when locked, and never reconnects with the old token |
| BitwardenApi > authenticated calls > send the bearer token, and a JSON body only when there is one | dybw-core `client_tests.rs::calls_need_a_login_and_send_nothing_without`, `::writes_name_their_owner_and_encode_ids` |
| BitwardenApi > sync > fills in missing lists and learns the account id for later writes | dybw-core `client_tests.rs::sync_needs_a_profile_id`, `::writes_name_their_owner_and_encode_ids` |
| BitwardenApi > sync > refuses a response with %s (no profile, no account key, an empty body) | dybw-core `client_tests.rs::sync_needs_a_profile_id`; `dybw-vectors/tests/accounts.rs::partial_unlock_data_without_profile_key_is_incomplete` |
| BitwardenApi > sync > finds the account key where newer servers put it | dybw-core `accounts.rs::unlock_from_user_decryption_only`; `test/sync-shape.test.ts` › … unlocks and syncs with the keys where newer servers put them |
| BitwardenApi > refuses to write an item before a sync told it whose vault this is | dybw-core `client_tests.rs::writes_name_their_owner_and_encode_ids` |
| BitwardenApi > errors from the server > quotes what the server says, marked as coming from it | dybw-core `client_tests.rs::errors_shaped`, `::server_text_is_joined_cleaned_and_clipped`; `test/integration/vaultwarden.test.ts` › … pushes to an item the server sends without its secure note part (a real server's text in the report) |
| BitwardenApi > errors from the server > joins several messages and collapses whitespace | dybw-core `client_tests.rs::server_text_is_joined_cleaned_and_clipped` |
| BitwardenApi > errors from the server > clips long server text | dybw-core `client_tests.rs::errors_shaped`, `::server_text_is_joined_cleaned_and_clipped` |
| BitwardenApi > errors from the server > gives only the status for %s | dybw-core `client_tests.rs::bodies_that_are_not_json_give_only_the_status` |

### `test/crypto.test.ts` (before M6; `src/bw/crypto.ts`)

| Test | Covered by |
|---|---|
| key derivation (known answers) > PBKDF2 master key, stretched key and password hash | dybw-core `dybw-core/src/crypto/tests.rs::master_keys_match_kat` (same `vectors/crypto/vectors.json`), and in WASM `dybw-core-wasm/js/test/vectors.test.ts` (`runKnownAnswers`) |
| key derivation (known answers) > Argon2id master key and stretched key | dybw-core `tests.rs::master_keys_match_kat`; `test/argon2.test.ts` › Argon2 in a worker > derives the known-answer key in a real worker / in the embedded worker, as shipped |
| EncString > decrypts the protected user key with the stretched key | dybw-core `tests.rs::master_keys_match_kat`, `dybw-vectors/tests/accounts.rs::unlock_pbkdf2` |
| EncString > decrypts reference ciphertexts and round-trips its own | dybw-core `tests.rs::enc_strings_match_kat`, `::round_trip` |
| EncString > uses a fresh IV for every encryption | dybw-core `tests.rs::rng_and_key_ref` (every IV comes from the host's `random`); `dybw-core-wasm/src/tests.rs::random_fills_large_buffers_in_chunks` |
| EncString > rejects tampered data, wrong keys and unauthenticated types | dybw-core `tests.rs::malformed_and_unsupported_inputs`, `::round_trip` (wrong key: `BadMac`) |
| EncString > names no type when the string has none | dybw-core `tests.rs::malformed_and_unsupported_inputs` |
| EncString > rejects type 2 parts of the wrong size before checking the MAC | dybw-core `tests.rs::malformed_and_unsupported_inputs` (IV, MAC and part counts) |
| EncString > reports data that passes the MAC but does not decrypt | dybw-core `tests.rs::bad_padding_is_decrypt_error`, `::round_trip` (non-UTF-8 text) |
| EncString > refuses legacy data under a COSE key | dybw-core `dybw-core/src/crypto/cose_tests.rs::key_types_cross_decrypt` |
| key wrapping > wraps a COSE key under a COSE key as a COSE key | dybw-core `cose_tests.rs::key_types_cross_decrypt` |
| key wrapping > wraps a key under a legacy key in its byte format | dybw-core `tests.rs::round_trip` (`decrypt_key` of a wrapped key) |
| key wrapping > has no COSE form for a legacy key | dybw-core `cose_tests.rs::key_types_cross_decrypt` (content kinds are not interchangeable) |
| AccountPrivateKey > reports a private key that is not PKCS#8 | dybw-core `dybw-core/src/crypto/rsa_mark_tests.rs::pkcs8_has_its_own_decrypt`; `dybw-core/src/vault/orgs_tests.rs::a_missing_or_unreadable_private_key_is_a_problem_per_organization`; `test/core/ports.test.ts` (rsaOaepDecrypt rejects an unimportable key with `key`) |
| cancelling the key derivation > does not start when already cancelled | `test/controller.test.ts` › SecretsController > unlock > stops before deriving the key when cancelled; `test/argon2.test.ts` › Argon2 on the calling thread > refuses to start when already aborted |
| cancelling the key derivation > discards a PBKDF2 key cancelled while it was derived | `test/controller.test.ts` › SecretsController > unlock > lets a lock that arrives while the key is derived win; dybw-core `dybw-core-wasm/src/tests.rs::lock_wins_over_a_running_unlock` |
| KDF bounds > refuses downgraded or abusive parameters | dybw-core `tests.rs::kdf_bounds`; `accounts.rs::accept_kdf_refuses_out_of_bounds_params`, `::out_of_range_kdf_names_its_source` |
| SymmetricKey > wipes its raw material | dybw-core `tests.rs::debug_and_errors_are_redacted` (keys are `Zeroizing`, never printed); the WASM instance wipes on `lock` (`dybw-core-wasm/src/tests.rs::a_session_unlocks_and_locks`) |
| SymmetricKey > rejects keys of the wrong size | dybw-core `tests.rs::malformed_and_unsupported_inputs` (`from_bytes(&[0; 63])`), `cose_tests.rs::aead_inputs` |
| ValueFingerprinter > is deterministic per key and binds the id | dybw-core `rsa_mark_tests.rs::marks_match_kat`, `::marks_on_cose_keys_and_subkeys` |

### `test/cose.test.ts` (before M6; `src/bw/cose.ts`, `cbor.ts`, `aead.ts`)

The two `EncString type 7` groups ran once per account of `cose-vectors.json` (XAES-256-GCM, XChaCha20-Poly1305);
the core reads the same file (`vectors/crypto/cose-vectors.json`, byte-identical).

| Test | Covered by |
|---|---|
| XAES-256-GCM (C2SP test vectors) > key 0x%i… | dybw-core `cose_tests.rs::xaes_c2sp` (the same two vectors) |
| AEAD inputs > refuse keys that are not 32 bytes | dybw-core `cose_tests.rs::aead_inputs` |
| AEAD inputs > refuse nonces that are not 24 bytes | dybw-core `cose_tests.rs::aead_inputs` |
| AEAD inputs > refuse a tampered XChaCha20-Poly1305 ciphertext | dybw-core `cose_tests.rs::xchacha_round_trip_and_tamper` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > unlocks the account key with the master password | dybw-core `dybw-vectors/tests/accounts.rs::unlock_v2`, `::cose_v2_unlocks_with_version_2`; `test/sync.test.ts` (COSE accounts) › … unlock |
| EncString type 7, %s (vectors from Bitwarden's SDK) > encodes COSE keys byte for byte like the SDK | dybw-core `cose_tests.rs::cose_vectors_decrypt` (`to_bytes` equals the SDK's key), `::cose_pad_and_key_errors` (`encode_cose_key`) |
| EncString type 7, %s (vectors from Bitwarden's SDK) > decrypts strings, padded or not | dybw-core `cose_tests.rs::cose_vectors_decrypt` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > unwraps legacy and COSE item keys, and decrypts with them | dybw-core `cose_tests.rs::cose_vectors_decrypt` (`itemKeys`, both kinds) |
| EncString type 7, %s (vectors from Bitwarden's SDK) > unwraps the private key, which then reads organization keys | dybw-core `cose_tests.rs::cose_vectors_decrypt` (`privateKey`); `orgs_tests.rs::real_rsa_on_the_vectors_account` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > round-trips what the plugin encrypts | dybw-core `cose_tests.rs::cose_round_trip`; the SDK reads it back: `dybw-vectors/tests/sdk.rs::bitwarden_sdk_decrypts_strings_and_wrapped_keys_the_core_produced` (CI `sdk` job) |
| EncString type 7, %s (vectors from Bitwarden's SDK) > refuses a message for another key or of another kind | dybw-core `cose_tests.rs::cose_decrypt_refuses_wrong_key_and_shape`, `::key_types_cross_decrypt` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > refuses tampered messages | dybw-core `cose_tests.rs::cose_decrypt_refuses_wrong_key_and_shape`, `::xchacha_round_trip_and_tamper`, `::xaes_c2sp` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > refuses messages of the wrong shape | dybw-core `cose_tests.rs::cose_decrypt_refuses_wrong_key_and_shape` |
| EncString type 7, %s (vectors from Bitwarden's SDK) > refuses a message with a missing or unknown content type | dybw-core `cose_tests.rs::cose_decrypt_refuses_wrong_key_and_shape` (missing or unknown content type) |
| COSE keys > only allow the operations they list | dybw-core `cose_tests.rs::cose_pad_and_key_errors` |
| COSE keys > reject malformed keys | dybw-core `cose_tests.rs::cose_pad_and_key_errors`, `::aead_inputs` |
| COSE keys > allow no operation when they list none | dybw-core `cose_tests.rs::cose_pad_and_key_errors` (no `key_ops` allows nothing) |
| COSE keys > use the SDK's padding | dybw-core `cose_tests.rs::cose_pad_and_key_errors` (`pad`/`unpad`) |
| COSE keys > keep their kind when remembered | dybw-core `accounts.rs::a_remembered_cose_key_unlocks_with_its_security_state`; `test/sync.test.ts` (COSE accounts) › … remembers the key only when asked, and drops a stale one |
| CBOR decoder > rejects %s | dybw-core `cose_tests.rs::cbor_rejects` |
| CBOR decoder > keeps a truncated text string a truncation, not a UTF-8 error | dybw-core `cose_tests.rs::cbor_rejects` |
| CBOR decoder > reads integers beyond 2^53 as bigints | dybw-core `cose_tests.rs::cbor_round_trip_shortest` (`u64::MAX`, the full 64-bit range) |
| CBOR decoder > rejects a %s longer than 2^53 bytes | dybw-core `cose_tests.rs::cbor_huge_array_header_fails_without_allocating`, `::cbor_rejects` |
| CBOR decoder > reads the simple values false, true and null | dybw-core `cose_tests.rs::cbor_round_trip_shortest` |
| CBOR decoder > rejects deep nesting | dybw-core `cose_tests.rs::cbor_rejects` |
| CBOR decoder > round-trips the values COSE uses | dybw-core `cose_tests.rs::cbor_round_trip_shortest`; `dybw-core/src/crypto/cbor.rs` tests `encoded_len_matches_encode` |
| CBOR decoder > refuses to encode what it cannot represent | dybw-core `cose_tests.rs::cbor_round_trip_shortest` (the Rust `Cbor` type holds only integers COSE uses; no float or wider value can be built) |

### `test/plan.test.ts` (before M6; `src/sync/plan.ts`)

One to one with dybw-core `dybw-core/src/sync/plan_tests.rs` (the planner was ported from this suite).

| Test | Covered by |
|---|---|
| planSync > pulls a new remote secret onto a fresh device | `plan_tests.rs::pulls_a_new_remote_secret_onto_a_fresh_device` |
| planSync > adopts a remote secret whose value already matches locally | `plan_tests.rs::adopts_a_remote_secret_whose_value_already_matches_locally` |
| planSync > does nothing when neither side changed | `plan_tests.rs::does_nothing_when_neither_side_changed` |
| planSync > pulls remote edits and pushes local edits | `plan_tests.rs::pulls_remote_edits_and_pushes_local_edits` |
| planSync > only refreshes the base when the item changed but the value did not | `plan_tests.rs::only_refreshes_the_base_when_the_item_changed_but_the_value_did_not` |
| planSync > treats a replaced Bitwarden item as a remote change | `plan_tests.rs::treats_a_replaced_item_as_a_remote_change` |
| planSync > restores a secret missing on this device instead of deleting it remotely | `plan_tests.rs::restores_a_secret_missing_on_this_device_instead_of_deleting_it_remotely` |
| planSync > detects both-changed conflicts, and converges when both made the same edit | `plan_tests.rs::detects_both_changed_and_converges_when_both_made_the_same_edit` |
| planSync > applies the conflict policy | `plan_tests.rs::applies_the_conflict_policy` |
| planSync > flags an unsynced local value that differs from a new remote one | `plan_tests.rs::flags_an_unsynced_local_value_that_differs_from_a_new_remote_one` |
| planSync > clears locally when deleted remotely, unless edited here | `plan_tests.rs::clears_locally_when_deleted_remotely_unless_edited_here` |
| planSync > clears an edited secret deleted remotely only when the policy prefers Bitwarden | `plan_tests.rs::clears_an_edited_secret_deleted_remotely_only_when_the_policy_prefers_bitwarden` |
| planSync > treats a queued upload meeting a new remote item of the same id as a both-changed conflict | `plan_tests.rs::a_queued_upload_meeting_a_new_remote_item_of_the_same_id_is_both_changed` |
| planSync > creates only what the user queued | `plan_tests.rs::creates_only_what_the_user_queued` |
| planSync > is deterministic (sorted by id) | `plan_tests.rs::is_deterministic_sorted_by_id` |
| planSync > honours per-secret overrides | `plan_tests.rs::honours_per_secret_overrides`, `::an_override_for_another_kind_is_ignored` |
| planSync > organization items claiming an id > always asks before a pending or unsynced local value meets a new organization item | `plan_tests.rs::always_asks_before_a_pending_or_unsynced_local_value_meets_a_new_organization_item` |
| planSync > organization items claiming an id > always asks when an organization item replaces the item a secret was synced with | `plan_tests.rs::always_asks_when_an_organization_item_replaces_the_item_a_secret_was_synced_with` |
| planSync > organization items claiming an id > asks even when the values match or the local value is gone, so the id is never bound without consent | `plan_tests.rs::asks_even_when_the_values_match_or_the_local_value_is_gone` |
| planSync > organization items claiming an id > keeps a local value as a new personal item, never pushing it to the organization | `plan_tests.rs::keeps_a_local_value_as_a_new_personal_item_never_pushing_it_to_the_organization` |
| planSync > organization items claiming an id > still pulls onto an empty device and pushes to the organization item it synced with | `plan_tests.rs::still_pulls_onto_an_empty_device_and_pushes_to_the_organization_item_it_synced_with` |
| planSync > the first push to an organization item > is always asked, whatever the policy | `plan_tests.rs::the_first_push_to_an_organization_item_is_always_asked_whatever_the_policy` |
| planSync > the first push to an organization item > is asked when prefer-local settles a both-changed conflict | `plan_tests.rs::the_first_push_is_asked_when_prefer_local_settles_a_both_changed_conflict` |
| planSync > the first push to an organization item > pushes, marked as confirmed, only once the user agreed to it | `plan_tests.rs::pushes_marked_confirmed_only_once_the_user_agreed` |
| planSync > the first push to an organization item > never asks for personal items | `plan_tests.rs::never_asks_for_personal_items` |

### `test/engine.test.ts` (before M6; `src/sync/engine.ts`)

| Test | Covered by |
|---|---|
| runSync > stops before the next item once cancelled, leaving it untouched | dybw-core `dybw-core/src/sync/engine_tests.rs::stops_before_the_next_action_once_cancelled`, `::a_sync_cancelled_while_reading_writes_nothing`; `test/sync.test.ts` › … audit regressions > stops a running sync when locked |
| the engine, given actions the planner should never return > ignores a pull or push for an id it read no item for | dybw-core `engine_tests.rs::ignores_a_pull_push_or_adopt_for_an_id_it_read_no_item_for` |
| the engine, given actions the planner should never return > never pushes for a secret this device does not hold | dybw-core `engine_tests.rs::never_pushes_or_creates_for_a_secret_this_device_does_not_hold` |
| the engine, given actions the planner should never return > refuses to push to an organization item the secret was not synced with, even confirmed | dybw-core `engine_tests.rs::refuses_to_push_to_an_organization_item_the_secret_was_not_synced_with_even_confirmed` |
| the engine, given actions the planner should never return > refuses a confirmed push when the organization's key is not at hand | dybw-core `engine_tests.rs::keeps_a_secret_whose_item_key_or_value_can_no_longer_be_read` (an item of an organization this device has no key for is kept, never written), `orgs_tests.rs::organizations_not_allowed_are_never_unwrapped`, `write_tests.rs::organization_items_use_the_organization_key` |
| the engine, given actions the planner should never return > refuses the first push to an organization item without the user's confirmation | dybw-core `engine_tests.rs::refuses_the_first_push_to_an_organization_item_without_confirmation` |

### `test/state.test.ts` (before M6; `src/sync/state.ts`)

| Test | Covered by |
|---|---|
| parseDeviceState > makes up a device id when the stored one is missing or empty | dybw-core `state_tests.rs::makes_up_a_device_id_when_the_stored_one_is_missing_or_empty`; `test/core/ports.test.ts` (the `device` key falls back to the state's `deviceId`) |
| parseDeviceState > starts fresh from a state of another version, keeping only the device id | dybw-core `state_tests.rs::starts_fresh_from_a_state_of_another_version_keeping_only_the_device_id` |
| parseDeviceState > drops parts that are not of the right kind | dybw-core `state_tests.rs::drops_parts_that_are_not_of_the_right_kind` |
| resetDeviceState > forgets what was synced and queued, but keeps the device id | dybw-core `state_tests.rs::reset_forgets_what_was_synced_and_queued_but_keeps_the_device_id`; `test/controller.test.ts` › SecretsController > resetState > forgets the sync state but keeps the device id |

### `test/vault.test.ts` (before M6; `src/bw/vault.ts`)

| Test | Covered by |
|---|---|
| unlockUserKey > salts the master key with the email unless given another salt | dybw-core `dybw-vectors/tests/accounts.rs::unlock_uses_the_server_salt`, `::source_two_uses_prelogin_and_email`; `test/sync-shape.test.ts` › … uses the master key salt the server gives, not the email |

### `test/vectors/vectors.test.ts` (before M6; opt-in `npm run test:vectors`)

| Test | Covered by |
|---|---|
| dybw conformance vectors (obsidian) > (each vector) | dybw-core `dybw-vectors/tests/vectors.rs::every_vector_runs` (native) and `dybw-core-wasm/src/tests.rs::every_vector_runs_over_the_host` with `dybw-core-wasm/js/test/vectors.test.ts` (the shipped module in Node, Chromium and WebKit); the plugin's 25 expected failures are 0 in the core |
| dybw conformance vectors (obsidian) > expected-failures.txt lists only existing vectors | dybw-core `vectors.rs::expected_failures_list_existing_vectors` |
| conformance vectors (fails when no vectors directory is given) | dybw-core `vectors.rs::vectors_found` |

### `test/sdk/verify.test.ts` (before M6; opt-in `npm run test:sdk`)

| Test | Covered by |
|---|---|
| accepted by Bitwarden's SDK > decrypts strings and wrapped keys the plugin produced | dybw-core `dybw-vectors/tests/sdk.rs::bitwarden_sdk_decrypts_strings_and_wrapped_keys_the_core_produced` (the core encrypts what the plugin uploads; CI `sdk` job, locally `cargo test -p dybw-vectors --test sdk --locked -- --ignored`) |

### `test/perf/perf.test.ts`

| Test | Covered by |
|---|---|
| performance > PBKDF2-SHA256, 600,000 iterations (Bitwarden default) | `test/perf/perf.test.ts` › performance > PBKDF2-SHA256, 600,000 iterations (Bitwarden default), as an unlock in the core (row `pbkdf2-600k`, same budget); dybw-core `runPerf` row `pbkdf2-600k` |
| performance > Argon2id, 64 MiB / 3 iterations / 4 lanes (Bitwarden default) | `test/perf/perf.test.ts`, same name, on the Argon2 runner the core's `argon2id` port calls |
| performance > decrypts 1,000 marked secrets inside a 5,000-item vault | `test/perf/perf.test.ts` › performance > decrypts 1,000 marked secrets inside a 5,000-item vault, as a first sync (row `decrypt-1000-of-5000`, same budget, end to end); dybw-core `runPerf` row `decrypt-1000-of-5000` |
| performance > plans a 10,000-secret sync | dybw-core `runPerf` row `plan-10000` (`dybw-core-wasm/js/test/perf.test.ts`, same 500 ms budget in Node, Chromium and WebKit; ruling D11: the shipped module has no planner-only export) |

### `test/integration/vaultwarden.test.ts`

Every test kept under its name, on the core's controller (`test/helpers/device.ts`), the hub through `startHub`.
Added: › follows redirects only for a server acknowledged on the device (ADR 0018), › pushes to an item the server
sends without its secure note part: Vaultwarden refuses the push, › writes a new item of a COSE account at security
version 2 as a blob: Vaultwarden refuses it at any size. The two COSE runs use security state version 1: Vaultwarden
1.37.5 refuses blob items (the last test).
