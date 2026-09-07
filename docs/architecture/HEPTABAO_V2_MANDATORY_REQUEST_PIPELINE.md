# HeptaBao V2 Mandatory Request Pipeline

The repository-owned request path is ordered as follows:

```text
request-id admission
  -> token validation
  -> entity state and group/direct policy expansion
  -> default-deny capability evaluation
  -> active namespace qualification
  -> enabled longest-prefix mount routing
  -> backend entry
  -> KV version commit
  -> post-commit confirmation
  -> completed response OR unknown-after-entry recovery reference
```

No later stage may compensate for a skipped earlier stage. Authentication is not authorization, routing is not authorization, and a successful inner write does not erase an outer post-entry uncertainty.

## Failure boundary

Everything before backend entry is `before entry`. A caller may submit a new request with a new request identifier after correcting input or state. Once a state mutation occurs, transport or confirmation failure is `unknown after entry` unless authoritative state proves the result. The original request identifier cannot be replayed.

## Namespace keying

The in-memory KV candidate derives an internal key from namespace identifier, mount identifier and backend-relative path. This prevents equal user paths in different namespaces from sharing one engine record.

## Evidence

The executable pipeline and injected-uncertainty tests live in `crates/heptabao-service-core/src/lib.rs`. Module-specific contracts are documented under `docs/modules/` and cross-cutting rules are in the engineering handbook.
