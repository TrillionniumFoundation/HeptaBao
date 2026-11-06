# Actual Mac gateway selector and registration qualification

This archive records the installed OpenClaw gateway's original pre-bootstrap,
configuration validation, and plugin registration functions in an isolated,
credential-free HOME and state directory. It does not start the production
gateway, contact a provider, read production credential rows, or qualify a
production fallback configuration.

## Original r1 outcome

The unique original job `1a1b2f52c86-fc05-8043` completed with exit 1, complete
durable output, and no timeout, cancellation, or retry. Its 17,188-byte stdout
has SHA-256 `a1d455a2fccbf68e778985f30d3eb3acc0da28a742d57806e6c8a1187bb294fe`.
The two original process-read pages reproduce those bytes exactly, including
hex, offsets, and final EOF.

Three of the fifteen declared cases passed. The fourth, S03, was refused by
the original `selectGatewayRunEnvironment` path. The remaining eleven cases
were not executed. No AuthBus or positive-control module was imported and no
plugin registration was reached. The unit opened zero SQLite connections and
made zero mount calls. Both kernel-denied network probes completed as expected.

All three original child processes were reaped exactly once with no live
members in their anchored groups and with closed streams. The unit recorded
91 file descriptors, all closed once, and restored its guards. The original
aggregate `passed_process_custody` is **false** because one child exited 1;
the known process closure facts do not change that failed qualification.

The r1 synthetic AuthBus entry was explicitly disabled but included an empty
`config` object. The pinned original validator validates an entry whenever
`enabled || entryHasConfig` is true, and the actual AuthBus manifest requires
five fields. This is the concrete source-level defect addressed by the
prepared successor; the r1 receipt is retained without alteration. The r1
fixture also created `global.env`, whereas the original dotenv implementation
uses `gateway.env`. Creating the unused file does not prove that dotenv branch.

## Original r2 outcome and actual r3 successor

The r2 delta supplies five synthetic, credential-free AuthBus config
fields, uses the actual default `HOME/.openclaw` state layout and `gateway.env`
path, and requires successful original reads plus distinct harmless markers
from both dotenv files and config environment application. It keeps the
original fifteen case groups, three outer children, 45-second shared budget,
70-second supervisor budget, kernel restrictions, network refusals, and
production boundary. The original validator must also reject a private copy
with the previous empty disabled-plugin config.

Original runtime error messages and snapshot validation details are written
only to bounded, create-only, fsynced private diagnostic files in the new
fixture. Public receipts contain counts and booleans. This archive's assembly
and syntax records alone do not establish an actual pass.

The unique r2 job `1a1b2fccfc6-fc05-805c` completed with authoritative exit 1.
Its 26,869-byte original stdout has SHA-256
`a21d1c5584dac9535312343815fe8103a3c374f5c7c6efd1f255f51f82d16e42`.
The original unit process exited 0 and passed all fifteen case groups. Both
dotenv files were read three times and their harmless markers were observed;
the original validator rejected the earlier empty disabled-plugin config.
The enabled control was imported and registered once and its gateway-start
hook ran once. AuthBus was never imported or registered. Both SQLite handles,
187 unit file descriptors, and all three outer original processes closed.

The outer collector refused a 112-byte stderr warning. A bounded private read
matched it exactly to the single warning from the original valid config
snapshot and the pinned validator/logging source: a plugin disabled in config
still retains its config. Raw private diagnostic bytes and hashes are not
included. The r2 outer failure and original aggregate custody failure remain
unchanged; its successful unit assertions are recorded separately.

The r3 delta validates that precise original snapshot warning and admits only
the exact 112-byte warning from a successful unit with all fifteen groups,
alongside the existing empty-stderr behavior. Syntax children still require
empty stderr. Sixteen pure boundary tests reject other text, repetition,
prefixes, suffixes, reasons, failed units, missing assertions, and boolean
exit values.

The unique r3 job `1a1b3032450-fc05-8073` subsequently completed with
authoritative exit 0, complete durable logs, no timeout, and no retry. Its
30,836-byte stdout has SHA-256
`12f5a9acbfe16bd31a6c9f91a4b9bfa85e0967c30c12d31067fdbb3130aa4a9d`;
the two original read pages reproduce every byte through EOF. The shared
execution took 0.898767 seconds within the original 45/70-second budgets.

All fifteen actual case groups passed. The state and gateway dotenv files
were each read three times; their distinct markers and the config marker were
observed while the explicit fallback path remained selected. The original
empty-config validation negative and final new-selector rejection passed.
The positive control was imported, registered, and invoked once through the
original gateway-start hook. AuthBus was not imported or registered. Original
active/channel/session/hook registries were retired in memory afterward.

All three original children exited 0, were reaped once, had no live anchored
group members, and closed their streams. Original process custody passed.
Both SQLite handles and all 187 recorded unit descriptors closed once. The
single original mount probe completed within its fixed limit. The exact
112-byte warning was admitted, while the outer stderr remained empty. The
receipt explicitly retains `fullProductionGatewayQualified=false` and zero
production credential reads, writes, service mutations, and provider calls.

The reference directory contains exact public source bytes and original read
responses for the selector/configuration modules. Source pins establish the
observed installed implementation; the qualification still uses the installed
SDK and does not claim complete transitive dependency closure. Earlier gateway
loader sources and the original process custody qualification are referenced
by their existing immutable archives.

Passing this isolated qualification would establish the selected original
functions' behavior for the bounded synthetic inputs. Fresh production
argv/environment/configuration selection, actual running plugin memory,
external writers and consumers, valid provider credentials, complete database
and cache rollback, and production service transitions remain separate gates.
