# Personal vault edge adapters

This candidate adds a Chromium Manifest V3 preview and a bounded opaque
ciphertext store to the separate Rust personal vault. It is not approved for
real credentials or a replacement for an audited password manager.

## Chromium preview

The sensitive implementation is `heptabao-browser` in Rust. The extension in
`clients/chromium` is the platform transport and form UI. It has `activeTab`,
`scripting`, and `nativeMessaging` permissions; no persistent website host
permission, content script, external message listener or remote script.

Load the unpacked extension into a dedicated test profile and record its exact
extension ID. Then run the create-only installer with a built native binary,
existing encrypted vault and **new** private installation directory:

```sh
python3 tools/install_personal_browser.py \
  --binary /absolute/bin/heptabao-browser \
  --vault /absolute/private-vault \
  --install-root /absolute/new-private-install \
  --native-manifest-dir /absolute/browser/NativeMessagingHosts \
  --extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The example ID must be replaced by the actual browser ID. The manifest routes
one exact ID to the native process; it is not secure attestation against a
malicious process with the same OS account. The personal OS account, installed
extension and native host are trusted. An untrusted AI process must use a
different principal before any same-account file isolation can be claimed.

Open the extension action (or Ctrl+Shift+Y), unlock locally, select a login and
explicitly fill. Only the exact canonical HTTPS origin is eligible. This first
scope rejects IP literals, Unicode display names, uncanonical ports, suffix
matching, cross-frame forms, hidden or ambiguous fields, GET forms, other
submission targets and cross-origin submit overrides. Unsupported sites require
an explicit new implementation and its own qualification.

Browser-supplied tab/document identity is rechecked before final fill. A lock or
popup close cancels a fill that has not yet been dispatched. A dispatch already
accepted by the browser cannot be recalled; the explicit lock acknowledgement
waits for its outcome. The extension never automatically submits the form.
The authorized page can read credentials after fill, including in its event
handlers; credential custody does not restrict that page's later behavior.

The runtime must identify the caller document as a real action `POPUP`. The
worker binds each exact extension-page port once to the browser's unique popup
context and document; later operations must match that same registered identity.
This also covers Chrome action-popup ports that omit `MessageSender.documentId`.
It never accepts a document identity supplied in a popup message or rebinds an
old port to a newly opened popup. Chrome
can report the parent window unfocused while that popup owns focus; in this
case the worker requires a fresh, challenge-bound reply from the same popup,
matching the browser-supplied parent window and a 500 ms monotonic deadline.
The renderer independently checks its own current focus before assigning
fields. Native fill responses have at most a two-second remaining authorization
lease; late asynchronous stages and late renderer execution refuse the fill.
Expiry clears retained credential fields without acknowledging an unresolved
browser dispatch as complete. Failed fill attempts also request native lock.

The native host clears its expired session on a 100 ms timer, supports explicit
lock, and exits when the browser pipe closes. The default lifetime is 60 seconds,
bounded to 1–300 seconds. JavaScript strings are not guaranteed to be immediately
erased by their garbage collector; the UI does not persist them or log them.
Native output is nonblocking and has a 30 ms frame deadline, so an unread browser
pipe cannot keep the unlocked process alive indefinitely. Output failure exits
the host and releases the vault session.

## Firefox native-host candidate

The native executable also accepts Firefox's actual manifest-path and add-on-ID
launch arguments. This is a private staging and CLI-tested candidate; a Firefox
browser login has not been qualified. It uses a separate host name and fixed
candidate add-on ID. It does not manufacture a Chromium extension origin.

Prepare a new installation under an existing owner-only directory:

```sh
python3 tools/install_personal_firefox.py \
  --binary /absolute/bin/heptabao-browser \
  --vault /absolute/private-vault \
  --install-root /absolute/private-parent/new-firefox-install
```

The installer creates private configuration, launcher and native-host manifest
files, then verifies their bytes and the executable identity. It refuses an
existing installation. It does not register the manifest with Firefox, install
an extension, change a browser profile or modify Snap/portal permissions.
The native process requires the exact configured manifest path, manifest digest,
add-on ID, standard-I/O transport and private launcher. A different caller,
modified manifest or unknown configuration field is refused. These checks are
local routing and installation checks under the trusted OS owner, not process
attestation or isolation from another process with the same UID.

The shared framing, origin checks, bounded unlock lease, explicit lock and
output deadline are unchanged. The separate thirteen-case real-process profile
exercises that launch contract, encrypted-vault use, wrong-origin and cross-frame
refusal, actual expiry, lock, malformed callers and installation preservation.
It starts no browser and cannot establish Firefox UI or native-host discovery
compatibility. The original eight-case Chromium pipe profile is also executed
against the new executable; browser regression observations are recorded
separately in the support matrix.

## Opaque snapshot store

`heptabao-sync ABSOLUTE_PRIVATE_STORE VAULT_ID` is a single-owner CLI/SDK adapter,
not an unauthenticated network service or automatic sync daemon. The transport
must authenticate the owner and authorize the destination vault. The store has
no master password, recovery secret or data key. Clients authenticate/decrypt
downloaded envelopes before using any entries.

Commands arrive as bounded JSON on stdin:

```json
{"op":"head"}
```

```json
{"op":"publish","operation_id":"device-a-operation-0001","expected_head":null,"ciphertext":"BASE64_ENCRYPTED_ENVELOPE"}
```

For subsequent publications, `expected_head` is the returned receipt's
`head_id`, **not** its ciphertext digest. The head identity includes the
publication generation and request identity, so A → B → A cannot bypass the
comparison. A stale head or reused operation ID with different input fails
without overwriting the current head. The whole encrypted snapshot is the unit
of conflict; there is no automatic field merge or last-writer-wins rule.

Exact retries reconcile the immutable receipt. `receipt` reads by operation ID;
`fetch` reads a committed `ciphertext_sha256`, including historical versions.
Private fsync/rename publication writes state and receipt together. An uncertain
storage error fences the in-process owner; reopening verifies bytes and renews
the durability barriers before acknowledging recovery. Partial unreferenced
objects can be repaired only with the exact digest-bound caller bytes.

Limits: one store/vault, 4 MiB per encrypted snapshot, 64 MiB total retained
ciphertext (including uncommitted orphans), 4096 publications and 4096 objects.
State and pending metadata are individually bounded to 2 MiB. Capacity refuses
new publication and retains evidence. No automatic history deletion is exposed.
The untrusted server's complete old-state replay is not detectable without a
separate trusted client frontier. This implementation does not claim otherwise.

## Qualification boundaries

- `personal_edge_live.py`: actual CLI/native-pipe processes, wrong origin, expiry,
  explicit lock, replay/reopen, offline conflict, A/B/A and historical recovery.
- `firefox_native_cli.py`: thirteen real-process Firefox launch and shared IPC
  cases in a new private root; no Firefox browser or native-host registration.
- `browser_worker_test.mjs`: deterministic tests of the **actual worker module**
  with mocked Chrome scheduling; this is not browser execution evidence.
- `browser_live.py`: actual unchanged extension, Chromium native messaging,
  HTTPS login fixture and real renderer rejection cases. The test certificate
  exception is fixture-only and does not qualify TLS certificate validation.
- Physical two-device execution is recorded separately; two local directories
  alone do not establish physical device synchronization.

Android AutofillService/CredentialProviderService, native Passkey providers,
credential exchange, shared-vault key distribution, device revocation, stronger
rollback detection, release signing, external security review and long-term
support remain separate acceptance work. They are not inferred from these tests.
