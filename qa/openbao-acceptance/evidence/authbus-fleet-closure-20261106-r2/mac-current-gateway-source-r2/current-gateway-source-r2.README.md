# Current gateway source review and same-parent observer preparation

This checkpoint contains public installed SDK source and a new read-only
observer. It contains no current credential bytes, profile identifiers,
configuration contents or configuration/credential digests. No provider call,
gateway RPC, production credential write or service change was performed.

## Completed source observations

Nine exact installed files were read through three complete native file-read
responses. Each local file's whole byte count and SHA256 match its original
response. These are current installed source observations, not proof that the
running gateway has loaded a particular plugin configuration.

- `config.get` in `config-DQFoEP4y.js` calls `readConfigFileSnapshot()`. It is a
  disk configuration read, not a runtime plugin-memory observation.
- `plugins.uiDescriptors` in `plugin-host-hooks-BhKC1rhk.js` reads the active
  plugin registry's UI descriptors. The already-bound AuthBus plugin has no UI
  descriptor registration, so its absence there cannot prove it is disabled.
- `plugins.sessionAction` combines the loaded-plugin and registered-action
  checks and can execute an action. It was not called as a probe.
- The health path can refresh its cache and schedule further health work. It
  was not called under a claim of zero side effects.
- `getStatusSummary` in `status.summary-fItK9afs.js` calls task maintenance
  configuration and `reconcileInspectableTasks()`. Its session model details
  cover at most the ten recent sessions per agent and ten combined recent
  sessions. It is not a complete or side-effect-free consumer inventory.
- `health-state-Bj_QhGa5.js` builds part of its gateway snapshot from
  `getRuntimeConfig()`, but it does not expose AuthBus's current writer flags.
  No handshake or authenticated gateway request was sent.

## Observer prepared for the same original parent operation

`mac_current_gateway_observation_r2.py` is an executable `begin` / `bind` /
`finish` observer. It accepts the already-qualified original Commands,
ProcessReader and launchctl parser as pinned dependencies. Its original
absolute deadline is at most 45 seconds; each of the two exact `launchctl
print gui/501/ai.openclaw.gateway` commands has an eight-second cap clamped to
that deadline. The original helper's retained-child cleanup contract is kept.
An unknown or failed query blocks either ordinal from further dispatch.

The intended parent order is:

1. Complete create-only staging before opening the observer's held ancestor
   descriptors; then call `begin()`.
2. Execute the one read-only inventory child. Require the original child to
   finish with known success and all of its resources closed.
3. Read that child's private configuration copy and its original full9. Call
   `bind_configuration(bytes, full9, source_verify)`, where the pinned verifier
   rechecks the original inventory's named identities and absences.
4. Call `finish()` to compare the second registration, same process births and
   descendant sets, whole held plist bytes/full9 and current source fence.
5. Call `close()` exactly once in the parent's `finally` path and require its
   descriptor receipt and the original command custody receipts to close.

This does not reopen a credential database or the configuration source. It
uses one fixed plist descriptor chain and follows only the registered root's
actual process family, bounded to 128 processes and eight descendant levels.
It records discrete observations, not a continuous lock. The parent must not
publish the unsanitized Commands.public() rows for the two launchctl prints:
their original output hashes describe private argv/environment and are
retained only in private evidence. The module supplies sanitized rows.

The observer preserves all original plist environment and argv privately and
projects only selected key counts, conflicts and fixed-scope booleans. It may
prepare the already-reviewed pure fallback transform as private review files
under the new output directory. It never writes the live configuration,
original plist or designated production fallback path.

## Validation and remaining boundaries

Twelve local boundary cases passed, covering duplicate or malformed selected
environment data, conflicts without value export, typed full9 admission,
private output digests, no replay after an unknown query, PID birth and family
drift, and attempting every returned FD's close once even if one close fails.
The original local execution receipt and stdout are included. This observer
has not yet executed on the Mac; no current gateway observation is claimed.

The four launchctl parser definitions come from the exact 58,613-byte manager
embedded in the successful primitive r4 original launcher (SHA256 19c131fa...).
The SDK r4 scoped manager has a different whole-file SHA256 (2cad3413...). The
four extracted definitions are identical at the AST level; the files are not
treated as having the same whole-file identity. The dependency manifest gives
both the actual source locator and the exact excerpt AST digest.

Production fallback selector qualification, current JavaScript memory flags,
external consumers, full-state rollback, quiescence and provider liveness are
still separate gates. Previous selector/registration r3 synthetic qualification
and sleep-service primitive r4 qualification do not satisfy those gates by
themselves. Existing failed and unknown attempts remain unchanged.
