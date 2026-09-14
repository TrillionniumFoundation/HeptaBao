# HeptaBao Python HTTPS client and explicit CLI

This installable, standard-library-only package provides real network requests;
it is not the standalone Rust client/CLI contract models and is not a complete
OpenBao CLI, Agent or Proxy. Python >=3.11 is required. Qualified local execution
uses Python 3.13 on Linux; the private-file CLI requires POSIX descriptor flags.

## Install and invoke

From a trusted checkout, install `clients/python` into a dedicated environment,
or install the exact reviewed `heptabao_client` wheel with `pip --no-deps`.
The entry point is `heptabao` (equivalently `python -m heptabao`). No external
runtime dependency, Oracle executable or QA code is packaged.

Example for isolated development, with existing owner-only credential files:

```sh
umask 077
mkdir -m 700 /tmp/heptabao-client-responses
heptabao --address https://localhost:8200 --ca-file /private/ca.crt \
  --token-file /private/scoped.token \
  --output /tmp/heptabao-client-responses/read.json \
  read secret/data/example
```

The paths and address above are placeholders, not production defaults. The
response can contain a secret, so it goes to the specified new private file, not
stdout. The response directory must already be caller-owned with mode 0700 and
the destination must not exist. Credentials are supplied by an owner-only file,
never a raw `--token` argument. No implicit environment bearer fallback is used
by the CLI. Reads using finite-use credentials can still consume their use count.

## Commands and semantics

`read`, `list`, `write`, `delete`, `capabilities`, `wrap`, `unwrap`, `rewrap` and
`wrapping-lookup` issue explicit HTTPS requests. Mutating commands, and reads that
request wrapping, require `--allow-write`. JSON input is a private file supplied
with `--input`, or piped stdin with `--input -`; interactive secret entry and
arbitrary key=value argv parsing are intentionally absent. `read`/`write` accept
`--wrap-ttl`; `wrap` requires `--ttl`. Global options precede the subcommand.

Self `unwrap` and `wrapping-lookup` take a wrapping-token file and reject a second
bearer. `rewrap` instead requires an ordinary explicitly authorized caller plus a
wrapping-token file. `capabilities` supports self inspection or an explicit target
bearer/accessor file; the selector does not itself authorize inspection. Existing
credential/lease APIs can be called with `write` using reviewed private JSON.

## SDK boundary

```python
from heptabao import Client

# Obtain these variables from a trusted host configuration/credential channel.
client = Client(address, ca_file, bearer, namespace="", timeout=15)
response = client.request("GET", "/v1/secret/data/example", wrap_ttl="60s")
# Handle response.body in the dedicated consumer, not ordinary logs.
```

The SDK must receive a bearer value, but does not log it or expose it in repr.
`Response.status` and `.body` belong to the caller. The package exports `BaoError`,
`Client` and `Response`; private-file helpers remain implementation details.
The optional SDK `from_env` is an explicit call by an embedding host, not an
automatic CLI credential source. A host must review its own environment policy.

TLS uses an explicit CA with minimum TLS 1.2. Origins reject embedded credentials,
paths/query/fragment; redirects and ambient proxies are disabled. Request methods,
paths, header values, timeout and bounded JSON are validated, including duplicate
object-member rejection and explicit rejection of ambiguous namespace slashes.
Private token/input files are opened nonblocking before checking regular-file type,
so a FIFO cannot stall admission waiting for a writer. The configured socket timeout is not a proof of an
end-to-end deadline across every OS resolver or hostile transport behavior.

## Output, uncertainty and recovery

Private-file preflight occurs before dispatch; publication then uses an exclusive,
owner-bound, no-follow descriptor and atomic publication. The output is 0600.
A race or disk failure can still occur after a remote effect: diagnostics report
request/response progress but cannot certify whether that remote effect committed.
No command retries automatically, follows leader redirects, caches secrets or
starts a shell. Call the appropriate server recovery/metadata boundary before
making an explicit new mutating attempt. Do not retry OTP verification or unwrap
to test availability.

Exit 0 means an HTTP 2xx response was received and privately stored; exit 1 means
a received non-2xx response was privately stored; exit 2 means parsing, transport
or publication failed. Neither 0 nor receipt of a lease proves host SSH login,
external-provider success, production acceptance or complete compatibility.
Only fixed safe codes/status metadata appear on stdout/stderr. Python immutable
strings and interpreter copies are not guaranteed to be memory-zeroized; deployment
must account for process isolation, dumps and swap separately.

## Development and verification

```sh
python -m unittest discover -s clients/python/tests -p 'test_*.py' -v
python -m unittest discover -s qa/openbao-acceptance/tests -p 'test_*.py' -v
python qa/openbao-acceptance/client_live.py --binary /absolute/heptabao-server \
  --output /private/evidence/client-live.json
```

`client_live.py` launches fresh synthetic TLS state and real CLI subprocesses,
checks private outputs and secret-free diagnostics, and removes generated state.
QA's `bao_http.py` reuses the product transport rather than shipping QA in the
product. Package/wheel tests must bind the installed source files to this exact
checkout. Network SDK existence is not full SDK ecosystem parity. Agent auto-auth,
renewal/cache/template/sink orchestration, Proxy, complete CLI flags/output modes,
Windows protected files, upstream plugin workflows and independent operational
qualification remain separate implementation work.
