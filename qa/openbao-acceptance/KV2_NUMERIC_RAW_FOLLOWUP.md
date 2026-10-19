# Read-only continuation of the seven-number OpenBao 2.7.1 observation

The first Mac observation is retained as a failed diagnostic. Its seven writes
and seven reads all received definite responses; the failure occurred in the
raw tail, before the script published `raw_records`. The original script is
`cf1f7a475801b9d39072e8ba9878c912bf86f77d276395a43b8dc0c86e143305`.
The original summary is
`1281990796a3be2fc0064f0ffcb7fd2696b6bb7bf800e886e2534120e087481d`.

The original observed API lexemes were:

| Request number | Write status | GET status | Observed API number |
| --- | ---: | ---: | --- |
| `1.0` | 200 | 200 | `1` |
| `-0` | 200 | 200 | `-0` |
| `1e-6` | 200 | 200 | `0.000001` |
| `1e-7` | 200 | 200 | `1e-7` |
| `1e20` | 200 | 200 | `100000000000000000000` |
| `1e21` | 200 | 200 | `1e+21` |
| `1e400` | 400 | 404 | no payload |

The raw-tail script made an unjustified direct lookup of
`logical/<mount uuid>/salt`. The closed decoder already discovers the actual
KV storage root from its single `.../config` record. The failed receipt contains
only `KeyError`, without its key or stack, so the precise failing lookup and
actual storage-root layout remain unproven until the new read-only observation.
The follow-up uses the decoder's root discovery and publishes a nonsecret
projection of the actual root depth and whether the old assumption held.

## Execution contract

The operator copies the stopped numeric clone into a new private fixture,
rebinds its storage, TLS and listener paths, starts that copy, and stops it
after this command. The failed numeric fixture and the earlier failed migration
fixture remain preserved. This script starts or stops no server.

Use the existing complete source checkout and the original observation path:

```sh
python3 /absolute/path/kv2_271_numeric_raw_followup.py \
  --source-root /absolute/path/to/complete/source-checkout \
  --fixture-root /absolute/path/to/new-started-numeric-clone \
  --prior-summary /Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018/kv2-numeric-boundaries-official-mac-20261019-r1/observations/summary.json \
  --prior-summary-sha256 1281990796a3be2fc0064f0ffcb7fd2696b6bb7bf800e886e2534120e087481d \
  --private-work-root /absolute/path/to/new-followup-observations
```

The original summary's private `001-response.json` must remain alongside it.
The script checks that file's exact recorded hash and binds the new fixture's
identity and live health response to the original cluster. All token, identity,
configuration and prior-response reads retain the existing owner's private
file checks. The new output directory must not exist; its existing parent must
belong to the executing owner and must not be writable by a group or others.

The script enforces GET/LIST with no request body before every network dispatch.
It repeats the seven existing GETs and requires the observed number lexemes,
case labels and statuses to match the original response observations. It then
reads the mount registry, performs two bounded raw acquisitions with registry
rechecks, and requires the acquisitions to match. The existing closed raw
decoder validates the complete acquired history. The six accepted keys must
have exactly version one with a live payload; the rejected seventh key must
have no raw version or metadata. No POST is repeated.

Every raw and API HTTP request has a pending/result receipt, exact private
response bytes, a response hash and the owned child wait result. The original
120-second total budget, 15-second API request maximum and 5-second raw-reader
request maximum are retained. No request is retried or granted a fresh total
budget. The script never prints the token, raw salt or raw payload. Raw numeric
lexemes are synthetic test values and appear in the public projection.

## Evidence limits

`diagnostic_complete=true` will mean that this new observation actually completed
all reads and raw checks. It does not revise the old failed receipt, prove
HeptaBao migration, or itself certify the operator's clone cleanup and original
fixture preservation. The operator's separate receipt must supply those facts.
The fields `migration_qualified` and `original_fixture_unchanged_qualified` remain
false in this script's own result.

The local validation receipt records six tests for storage-root discovery,
ambiguity and boundary rejection, mutation denial, original receipt binding,
and exact lexical JSON observation. These tests did not run OpenBao or any
physical host. They also validated the retained actual failed summary against
the follow-up's prior-observation input contract.
