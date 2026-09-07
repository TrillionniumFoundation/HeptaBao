# HeptaBao V2 Mandatory Request Pipeline

The repository-owned request path is ordered as follows:

```text
token validation
  -> entity state and group/direct policy expansion
  -> active namespace qualification
  -> default-deny capability evaluation on the qualified namespace path
  -> enabled longest-prefix mount routing within the selected namespace
  -> bounded mutation request-ID admission
  -> backend entry
  -> KV version commit
  -> post-commit confirmation
  -> completed response OR unknown-after-entry recovery reference
```

No later stage may compensate for a skipped earlier stage. Authentication is not authorization, routing is not authorization, and a successful inner write does not erase an outer post-entry uncertainty. Request-ID admission is not allowed to precede authentication, namespace qualification or authorization.

## Failure boundary

Everything before backend entry is `before entry`. A caller may submit a corrected mutation with the same scoped request identifier when a rejected backend operation proves that no effect occurred. Once a state mutation occurs, transport or confirmation failure is `unknown after entry` unless authoritative state proves the result.

For the lifetime of this in-memory service instance, every completed mutation identifier is retained without eviction and every unresolved identifier remains bound to its exact operation until operator resolution. When the configured registry capacity is exhausted, a new unique mutation fails closed before backend entry. A retained identifier cannot be replayed to create a second effect. Restart loses this in-memory replay domain; durable production composition must persist the same identities before serving traffic.

## Namespace-bound authorization

Namespace qualification precedes policy evaluation. Root namespace `/secret/app` is authorized as `/secret/app`; the same user path in child namespace `team` is authorized as `/team/secret/app`. A policy for `/secret` therefore cannot access `/team/secret`, and a policy for `/team/secret` cannot access root `/secret`. Storage additionally derives its internal key from namespace identifier, mount identifier and backend-relative path, preventing equal qualified requests from sharing an engine record.

## Evidence

The executable pipeline, namespace-crossing regressions, capacity-saturation regressions and injected-uncertainty tests live in `crates/heptabao-service-core/src/lib.rs`. Module-specific contracts are documented under `docs/modules/` and cross-cutting rules are in the engineering handbook.
