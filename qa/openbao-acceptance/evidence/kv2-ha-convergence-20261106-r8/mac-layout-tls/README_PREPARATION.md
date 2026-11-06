# Create-only Mac layout and TLS preparation

This package prepares one ordinary `native_v6_file` instance. It contains code,
fixed public inputs, local boundary tests and two separately retained input-stage
generations. It does not grant service startup, initialization, traffic cutover,
HA, AuthBus, old-service cleanup or full OpenBao replacement qualification.

## Frozen preparation and actual Mac result

- Producer: `layout_tls_prepare.py`, 37,376 bytes,
  SHA-256 `c9fb2cb6f960e85ec2eb1f8f35ee30e2446703bcd53cfe416c72c06617f65fba`.
- Inputs: `fixed-inputs.public.json`, 2,130 bytes,
  SHA-256 `a7114185996a845bb9e5bbfe64c76a8d025d38fb35d07bd5a3ec1c4ac64cf494`.
- Fresh stage: `control/formal-kv2-layout-tls-inputs-r2` beneath the known T5
  continuation root. The fixed request is in `stage-r2/`; its filled transport
  body is retained privately and is excluded from the public proof package.
- Preparation uses the previously qualified Python 3.14.3 environment with
  cryptography 50.0.2. Its original clock is 110 seconds of work and a 120-second
  Runtime cap. Input staging has its own separate 52/60-second clock.

The stage is only eleven exact public files. The preparation consumes those
files only after separate admission. Its eight immutable public gate originals
bind the normal 107-case build and terminal, qualified Python environment and
terminal, successful whole-data readback and terminal, and exact launchd
preflight and terminal. These original bytes do not become new observations of
the machine's service/port state.

Root dispatched the successor input stage once as
`1a1b2632788-fc05-7dd8`, then the first preparation once as
`1a1b2643b65-fc05-7dde`. Both obtained original successful, durable terminals.
The actual preparation's result is 4,086 bytes / SHA-256
`6d803e1e5a684dc20abbc3c51fac9632aa497a133455ab0a4798fc79a251a638`.
It created 19 directories, retired all 23 owned directory handles and all 35
owned file handles, and created no child process or service. Its status is
`prepared_not_started`.

The independent actual review rehashed both public certificates, verified the
actual CA/leaf signatures and exact certificate policy, matched both copied
normal binaries to their independent native file information, and compared the
private closure/key metadata against the producer's private pins. Private key
bytes were not read by that review. The actual public originals and both root
and independent review records are under `actual-preparation/`. Source comments
describing the implementation as an unexecuted proposal are preserved as the
original pre-dispatch code; these subsequent receipts are the execution record.

## Filesystem and TLS boundary

The service child is under the existing T5 production root. Its normal server
and seed copies, configuration, uninstalled plist, data, audit, logs and public
certificates are separated. Private keys are created beneath the new internal
`service-authority-current-20261106-r1` child. This step creates 19 directories
with mode 0700, including the separate control output directory, and uses
create-only mode 0600 for ordinary files and mode 0700 for the two binary copies.
Existing objects are never replaced. Failed new objects remain available for
inspection; this module never deletes them.

Every new file is fsynced and read back. Original FDs are registered before any
first `fstat`; even that observation's failure retains one explicit close of the
original FD. Parent directory paths and held FDs retain their stable
device/inode/owner/mode binding. Expected child-count and directory-time changes
are not mistaken for root substitution. Existing artifact contents are pinned,
stream copied, fully hashed and independently read back without executing them.

The TLS issuer and server use separate P-256 private keys and SHA-256 signatures.
The CA expires 3,650 days after generation; the leaf expires 365 days after
generation, with a five-minute not-before clock margin. The leaf has serverAuth
EKU and exactly IP SAN `127.0.0.1` plus DNS SAN `localhost`. No old key is read.
Public certificate pins may leave the host. The original producer keeps
private-key and configuration pins in the private preparation record. This
evidence package additionally includes the exact rendered configuration and
uninstalled plist after root reviewed their fixed locators and confirmed that
they contain no credentials; their package hashes are therefore public.
Private-key and private-closure fingerprints remain withheld. The two keys have separate
directories on the same internal device. This is not a claim of separate device
custody, automatic rotation, private-key encryption, or internal-device-loss
recovery. No endpoint has been verified by preparation alone.

Root token, recovery nonce and all three unseal-share directories remain empty.
The new data directory is only an initial empty directory. Product initialization
can atomically replace that directory; a subsequent actual initialized identity
must have a new explicit binding. The preparation record cannot authorize that
replacement in advance.

## Retained correction history

The 37,005-byte producer `266760…` and input stage request `56f7ef…` are retained.
Root actually dispatched that public-input stage as job
`1a1b25e0cd2-fc05-7db8`; the preparation itself was not dispatched by that stage.
The explicit dispatch correction file supersedes an earlier local observation
that preceded receipt of root's dispatch notice. Neither the original request
nor its staged payload is rewritten.

The successor fixes a first-`fstat` FD registration gap and selects a new stage
directory and idempotency key. The original prepared producer remains unexecuted.
The new producer and stage are separate immutable inputs, not a rewrite of that
original stage or a retry of a business operation.

## Local validation and actual qualification

`final-r3-guards/` preserves the exact eight-test run: eight passed, no failures,
errors or skips, in 0.044 seconds. The FD-birth case includes four actual
first-`fstat` failure branches: read-open, new write, new copy and new directory.
Other cases exercise no-clobber, symlink/hardlink rejection, path substitution,
partial-write preservation, streaming copy and cryptographic certificate
verification, including rejection by the wrong signing key.

This run used Linux, Python 3.12.14 and cryptography 50.0.0. It does not substitute
for Mac execution or the separate actual cryptography 50.0.2 environment receipt.
The public result must be combined with the original Runtime terminal and final
stdout's complete FD retirement before actual preparation can be accepted.

No HTTP operation, product invocation, child process, real LaunchAgents plist
write, bootstrap/bootout, provider or J3160 call exists in this preparation step.
Manager, init, cross-host 2-of-3 custody, seed export, recovery and all client
boundaries require their own later evidence.
