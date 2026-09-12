# heptabao-cli-contracts

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns a bounded command-line invocation grammar that rejects secret material in process arguments and makes indirect secret input explicit. It does not implement network transport, interactive prompting, shell completion, configuration-file loading or command execution.

## Public API and ownership

### Current API contract and integration boundary

`CliInvocation::parse(&[String])` borrows the argument vector and returns owned command, optional canonical target, optional `SecretInput` and `OutputMode`. It expects arguments without the executable name. There must be one positional command; syntax validation uses `Id`, not an executable command catalog. Limits are 128 arguments and 4096 bytes per argument. Empty/control-containing arguments, unknown options and extra positionals return classified `CliError` values without echoing input.

Supported options are `--target=...`, `--output=human|json` and exactly one of `--secret-stdin`, `--secret-fd=3..1024`, or `--secret-env=NAME`. `EnvironmentName::parse` accepts 1–128 bytes beginning with uppercase ASCII or `_`, followed by uppercase letters, digits or `_`; it stores only the name. Duplicate target and multiple secret sources fail; repeated output options currently select the last value. Known sensitive flags and secret assignments are rejected, but this is a finite grammar/denylist, not a scanner capable of recognizing secret bytes placed in arbitrary identifiers.

Parsing does not read the environment, consume descriptors, authenticate, dispatch commands or render responses. The adapter must validate supported commands, acquire secrets after parsing, avoid logging the borrowed raw arguments and implement remote outcome handling. This crate is outside the current server dependency closure; it is not the parser for the server binary's implemented CLI. Integrating it requires explicit command and option mapping, not assuming matching command names.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-cli-contracts`; Cargo SHA-256 `1e80ab6f04bb99c06a383bcc5ddb35e2389f0809f5e9732512f65cade046ef8b`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_ARGUMENTS` | `crates/heptabao-cli-contracts/src/lib.rs:11` | `pub const MAX_ARGUMENTS: usize = 128;` |
| `const` | `MAX_ARGUMENT_BYTES` | `crates/heptabao-cli-contracts/src/lib.rs:12` | `pub const MAX_ARGUMENT_BYTES: usize = 4096;` |
| `struct` | `EnvironmentName` | `crates/heptabao-cli-contracts/src/lib.rs:31` | `pub struct EnvironmentName(String);` |
| `fn` | `parse` | `crates/heptabao-cli-contracts/src/lib.rs:34` | `pub fn parse(value: impl Into<String>) -> Result<Self, CliError> {` |
| `fn` | `as_str` | `crates/heptabao-cli-contracts/src/lib.rs:49` | `pub fn as_str(&self) -> &str {` |
| `enum` | `SecretInput` | `crates/heptabao-cli-contracts/src/lib.rs:61` | `pub enum SecretInput {` |
| `enum` | `OutputMode` | `crates/heptabao-cli-contracts/src/lib.rs:81` | `pub enum OutputMode {` |
| `struct` | `CliInvocation` | `crates/heptabao-cli-contracts/src/lib.rs:87` | `pub struct CliInvocation {` |
| `fn` | `parse` | `crates/heptabao-cli-contracts/src/lib.rs:95` | `pub fn parse(arguments: &[String]) -> Result<Self, CliError> {` |
| `enum` | `CliError` | `crates/heptabao-cli-contracts/src/lib.rs:204` | `pub enum CliError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The parser accepts at most one positional command and recognized options for target, output and one indirect secret source. Secret sources are standard input, a bounded inherited file descriptor or a syntactically valid environment-variable name; multiple sources are rejected rather than assigned precedence.

## Invariants and authorization

Argument count, byte length and control characters are bounded. Known token, password, unseal, recovery and client-key flags or assignments fail closed, including `--flag=value` forms. A valid invocation is only syntactic input and conveys no authentication, policy or administrative authority.

## Failure, retry and reconciliation

Parsing failures occur before any remote effect and are safe to correct locally. Once a command is dispatched, its retry classification must come from the client and operator outcome contracts; this parser must never turn an ambiguous remote result into an automatic replay.

## Concurrency and ordering

Parsing is pure and contains no shared mutable state. The caller must acquire secret bytes only after parsing succeeds, must avoid copying them into a reconstructed argument vector, and must dispose of the secret input before formatting any diagnostic or retry command.

## Security and privacy

`Debug` redacts target paths and environment names, while secret values are absent from the data model. Supported secret options carry source references rather than values. The adapter must still prevent secrets in arbitrary command/target identifiers, raw-argument logging, shell history and crash reports, disable accidental echo and constrain inherited descriptors.

## Persistence and compatibility

The crate owns no configuration or history format. Command identifiers and option names are currently repository-local contracts; compatibility with another CLI requires a versioned command matrix and differential tests rather than an assumed name match.

## Observability

Recommended events report only command class, parse outcome and output mode. Target paths, environment names, descriptor numbers associated with sensitive flows, raw arguments and secret-bearing rejected input must not be logged or attached to metrics.

## Operations

Operator guidance should prefer standard input or an owner-controlled inherited descriptor, document environment-variable leakage risks and ensure JSON output never includes debug representations of invocation internals. Unsupported options fail rather than being forwarded to another parser.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::secret_bearing_arguments_fail_closed`](../../crates/heptabao-cli-contracts/src/lib.rs) rejects the covered token/password flag and VAULT_TOKEN assignment spellings.
- [`tests::indirect_secret_sources_are_explicit_and_exclusive`](../../crates/heptabao-cli-contracts/src/lib.rs) checks stdin/descriptor selection and rejects mixed secret sources.
- [`tests::debug_output_redacts_target_and_environment_name`](../../crates/heptabao-cli-contracts/src/lib.rs) checks redaction of invocation diagnostics.

`cargo test -p heptabao-cli-contracts` proves rejection of secret-bearing flags and assignments, exclusivity of indirect sources, validation of environment identifiers and diagnostic redaction. Repository validation requires this V3 guide and at least one Rust test before the package can leave the planned set.

## Evolution and open boundaries

Interactive terminal handling, config layering, plugin commands, secure input readers, response rendering and a compatibility command catalog remain open. Future additions must keep supported secret inputs indirect and require the command adapter to prevent live secret material from entering `argv`.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-cli-contracts`
- Crate path: `crates/heptabao-cli-contracts`
- Cargo manifest SHA-256: `1e80ab6f04bb99c06a383bcc5ddb35e2389f0809f5e9732512f65cade046ef8b`
- Rust source files: `1`
- Public lexical declarations: `10`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
