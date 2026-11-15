# Repository layout and language boundaries

HeptaBao has a Rust server and a 53-package first-party Rust workspace. The
repository also contains clients, protocol bridges, database bootstrap scripts,
test drivers and qualification records. Those components have different runtime
and build requirements; their language alone does not establish redundancy.

The [workspace manifest](../Cargo.toml) selects `crates/*`. The
[current runtime map](modules/CURRENT_RUNTIME_MAP.md) identifies which packages
are dependencies of `heptabao-server`, which are separate executables, and which
are standalone contract models or development prototypes. All remain declared
workspace members with their own tests and module guides.

## Where maintained code belongs

| Directory | Role | Languages and retained dependencies |
| --- | --- | --- |
| [`crates/`](../crates/) | Server, persistence, HA, cryptographic custody, personal vault, native browser host, agent renderer and contract models | Rust; the plugin-host subtree also contains Go protocol bridges and genuine SDK test fixtures. |
| [`clients/python/`](../clients/python/README.md) | Installable HTTPS client, CLI, managed-secret agent, proxy, SSH helper and OIDC callback client | Python; console entry points are declared in [`pyproject.toml`](../clients/python/pyproject.toml). These are user-facing programs, not copied server code. |
| [`clients/chromium/`](../clients/chromium/) | Chromium extension UI, service worker and page-filling integration with the Rust native host | JavaScript, HTML and CSS, selected by the extension's [`manifest.json`](../clients/chromium/manifest.json). |
| [`clients/android/`](../clients/android/README.md) | Native Android Autofill provider and synthetic application used to qualify it | Java and Android XML; platform callbacks and Rust vault-format interoperability are implemented here. |
| [`clients/android-passkey/`](../clients/android-passkey/README.md) | Native Android Credential Manager provider, passkey codec and synthetic relying-party fixture | Java and Android XML, with separate host and device qualification. |
| [`tools/authbus/`](../tools/authbus/README.md) | AuthBus coordination and transport | Python coordination plus the maintained JavaScript/Node transport in [`production-transport/`](../tools/authbus/production-transport/README.md). Its SQLite transaction, restart and deadline tests remain beside the implementation. |
| [`tools/openbao-sdk-bridge/`](../tools/openbao-sdk-bridge/README.md) | Companion process for the official OpenBao Go SDK and plugin protocol | Go with pinned modules; the Rust plugin host owns the private IPC boundary. |
| [`bootstrap/`](../bootstrap/) | Explicit provider provisioning and database schema upgrades | SQL. The PostgreSQL upgrade files are migrations, not interchangeable copies of the initial schema. The unused encoded V1.1 repository generator has been retired. See the [provider guide](engines/HEPTABAO_POSTGRESQL_PROVIDER.md). |
| [`qa/`](../qa/) and [`tests/`](../tests/) | Acceptance runners, regression tests, synthetic services, device drivers and fixed comparison inputs | Primarily Python, with JavaScript and other protocol-specific fixtures. These execute the Rust programs and their consumers or validate repository contracts. |
| [`scripts/`](../scripts/) | Repository, documentation, workflow and evidence validation | Python tooling invoked by CI and local validation; [`requirements-plan.txt`](../requirements-plan.txt) records its Python dependencies. |
| [`probes/`](../probes/) | Isolated dependency and platform experiments | Rust probes with separate manifests and lockfiles, consumed by their named qualification workflows. |
| [`vendor/`](../vendor/) and [`third_party/`](../third_party/) | Reviewed third-party source dependencies | The server directly uses vendored bcrypt and QR code code; the server and agent renderer use the vendored template engine. Preserve upstream source provenance, licenses and local patch notices. |
| [`oracle/`](../oracle/README.md), [`schemas/`](../schemas/), [`specs/`](../specs/) and [`qualifications/`](../qualifications/) | Compatibility inputs, data contracts and qualification requirements | Structured data and documentation consumed by the validators and acceptance drivers. |
| [`planning/`](../planning/) and [`docs/`](./) | Design records, current module and operations guides, historical reports and audits | Source-linked documentation and retained evidence. A historical report describes its recorded candidate, not the current checkout. |
| [`.github/workflows/`](../.github/workflows/) | Current validation and explicit historical or platform-specific qualification entry points | GitHub Actions YAML with shell and Python orchestration. A version or date in a workflow name does not make its tested contract redundant. |

The direct Cargo dependencies are visible in the
[server manifest](../crates/heptabao-server/Cargo.toml) and
[agent renderer manifest](../crates/heptabao-agent-renderer/Cargo.toml). In
particular, removing `vendor/` or `third_party/` would remove build inputs.
The distinction between a server dependency and a standalone workspace crate is
recorded in the runtime map; the latter can still be a supported executable,
test target or contract model.

## Current code and historical source copies

Past qualification campaigns committed copies of controllers, SDK files and
reference source under `qa/*/evidence/`. These copies record what ran during a
particular campaign. The maintained implementation remains in the directories
listed above.

The repository cleanup removes the reviewed, inactive source copies from the
current tree and records each original path, mode, Git blob, byte count and
SHA-256 in the
[retired-source manifest](audits/2026-11-15-repository-cleanup/retired-sources.json).
The source commit is
`6faf7957bb0b9390141a9f3680567ef96295eba6`. Its objects remain in Git history.
Original receipts, results, logs, source-binding metadata, archive containers and
Git bundles are retained unchanged. This keeps the observed failures and passes
attached to their original inputs.

To verify the archived source objects without executing them, run from the
repository root:

```sh
python3 scripts/archived_qa_sources.py --verify
```

To recover the reviewed source files into a new directory outside the working
tree:

```sh
python3 scripts/archived_qa_sources.py --restore-to /tmp/heptabao-archived-sources
```

The [restoration tool](../scripts/archived_qa_sources.py) validates the recorded
objects and hashes. Restoring files does not execute a campaign. For historical
replay with its original documentation, receipts, dependencies and scripts, use
the complete original tree instead:

```sh
git worktree add --detach /tmp/heptabao-historical 6faf7957bb0b9390141a9f3680567ef96295eba6
```

Historical paths inside retained receipts still name the historical checkout.
Use that checkout or the manifest to inspect the exact bytes; do not substitute
the latest maintained source for an older recorded hash.

The [second cleanup audit](audits/2026-11-15-repository-cleanup-round2/README.md)
records additional retired generators, historical patches and superseded
workflows, plus shared implementations for the strict YAML loader and native HA
test fixture. Its separate manifest uses commit
`dd38ea55476813fb4b5d6d9a9e73211249536a73`:

```sh
python3 scripts/archived_qa_sources.py --manifest docs/audits/2026-11-15-repository-cleanup-round2/retired-sources.json --verify
```

The same `--manifest` option works with `--restore-to` and `--prefix`.

## Adding future work

Keep reusable source in its maintained directory, with tests next to the relevant
component or under `qa/` and `tests/`. Record a campaign's source commit and hashes
in its evidence instead of committing additional executable source copies. Keep
local build outputs, caches and temporary runs outside the tracked tree.

Retain data fixtures and archives that are required for compatibility,
calibration, upgrade or evidence-integrity checks. If such an input is retired,
update its consumers and provenance together. Current runtime code, tests and
client code stay visible in language statistics; historical evidence and
vendored dependencies are classified separately in [`.gitattributes`](../.gitattributes).
