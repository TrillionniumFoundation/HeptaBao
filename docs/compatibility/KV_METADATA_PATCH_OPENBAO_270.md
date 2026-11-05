# KV metadata PATCH CLI scope

The f2131e3c product Python CLI accepted `kv metadata get`, `put`, and
`delete`, but rejected `kv metadata patch` before configuration validation or
Client construction. The completed 272-case CLI corpus exercises the three
existing metadata commands. The 1459-case conversion corpus does not exercise
metadata PATCH through the CLI. Those earlier reports retain their original
source identity and finite scope.

The pinned official Linux binary SHA-256
`9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e`
reports OpenBao v2.7.0. Its actual `bao kv metadata patch -help` succeeds and
advertises repeated `-custom-metadata` and `-remove-custom-metadata` flags,
optional `-max-versions`, `-cas-required`, `-delete-version-after`, and mount
selection. This observation starts no service and supplies no credentials.
The public [2.7 KV guide](https://openbao.org/docs/secrets/kv/kv-v2/)
describes preserving unspecified custom metadata through that command. The
separate [metadata command page](https://openbao.org/docs/commands/kv/metadata/)
still lists only get/put/delete; the pinned binary resolves that discrepancy.

The product now accepts metadata PATCH through the existing executable CLI.
It emits one PATCH request to the discovered KV v2 metadata path, with
`application/merge-patch+json`. Set values remain strings and removal flags
become JSON null. Omitted settings are omitted from the payload; explicit
false and zero remain typed values. An empty delta is sent once. Metadata
PATCH never takes the data PATCH command's read/write fallback, including
after an HTTP 403. No preceding metadata read, mutation retry, server API
change, new credential source, redirect handling, or TLS exemption is added.
The existing strict Client validates namespace, TLS, response bounds, and
owner-only credential files.

The [public metadata PATCH API](https://openbao.org/docs/api/secret/kv/kv-v2/#patch-metadata)
requires the patch capability and JSON merge patch, without creating a new
data version. Native HTTP merge/PATCH/CAS and atomic refusal are already
covered by `kv_metadata_cas_live.py`; this change does not repeat that API
implementation or enlarge its claimed qualification.

Validation for this isolated increment is limited to nine original command
contracts, 31 existing in-memory KV command tests, and four owned Mac
loopback HTTPS/subprocess tests, with warnings as errors and bytecode
disabled. The TLS tests check actual typed null transmission, one mutation
after disconnect, refusal to follow a mutation redirect, and a rejected CA
chain before any HTTP request. They consume requested CLI output in memory
and save no product stdout, payload, bearer, or secret value to evidence.
Each test process and its owned descendants exited naturally.

The new fixed 64-case CLI checkset is
`qa/openbao-acceptance/kv_metadata_patch_cli_cases.json`: four interfaces
(product Python CLI and official bao CLI, each against native and official
servers), with 16 new metadata PATCH checks each. The executable
`kv_metadata_patch_cli_live.py` runs all four interfaces and rejects an
incomplete ordered trace. `run_kv_metadata_patch_cli_bound.py` independently
enforces the source/binary binding and Linux process ownership. HTTP 2
seconds, command 10 seconds, and outer 120 seconds remain fixed. Business
mutations and readback requests execute once. The native startup bridge is
limited to the inherited GET health readiness loop; certificate rejection
fails immediately. The official post-unseal default Client is also bound
to two seconds. Native cleanup attempts graceful termination first and
records any forced kill as a failed lane.

The controller's private binding manifest uses schema
`heptabao.kv-metadata-patch-cli-exact-binding.v1`, with `identity`,
`expected_interfaces`, `expected_cases_per_interface`, `expected_checks`
(64), and `budgets_seconds` (`all_http`: 2, `command`: 10, `outer`: 120).
`identity` explicitly separates clean `qa_source`, `cli_source`, and
`candidate_source`; records all imported QA source hashes, the three CLI
file hashes, actual candidate binary/build receipt hashes, and pinned
official binary/archive hashes. The build receipt must bind its own
candidate source, rather than whichever checkout hosts the QA controller.
The CLI subprocess uses `--cli-source` and always runs the requested real
Python CLI or pinned bao executable. There is no arbitrary endpoint option.

Pure QA contracts execute the actual Python dispatcher over an original
in-memory protocol and inject unmentioned-key loss, stringified null,
history alteration, unauthorized update, missing-key creation, unsafe
output, and invalid metadata types. Other contracts reject prefixes,
duplicate or reordered rows, non-boolean success values, mismatched source
custody, unsafe private receipts, changed budgets, and incomplete reports;
they exercise the actual two-second transport open and 120-second outer
awaiter. These contracts are not a native or official service trace.
The fixed 64 checks have not run against native or official services.
This increment does not claim those 64 checks, exact CLI success text, a
new 272-case qualification, or full CLI replacement.
