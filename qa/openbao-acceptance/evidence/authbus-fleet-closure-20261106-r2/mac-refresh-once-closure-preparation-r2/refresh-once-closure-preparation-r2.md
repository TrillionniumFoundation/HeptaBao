# Refresh once: original transport closure preparation

This increment contains preparation and local fault qualifications only. Provider requests, production CAS and service mutations remain zero. It preserves the previously published core R1 and its 31/31 result.

## Core R2

`mac_refresh_once_controller_r2.mjs` passes 33 local cases with real local private files/fsync and synthetic provider, mutex, source, running-writer and raw-CAS capabilities. It now passes a separate provider receipt into the provider adapter. It awaits that original provider promise rather than racing it with the abort signal. The original HTTP budget remains at most 30 seconds, and the original outer deadline is unchanged.

If original-function settlement, context closure and actual transport closure are not all known, the core writes a private `UNKNOWN_TRANSPORT_MUTEX_RETAINED` terminal record and deliberately leaves the original mutex callback pending. It does not return or throw through the qualified SDK mutex's finally block. That prevents an abort acknowledgement from being mistaken for a safe unlock. The original owned supervisor retains its already established deadline and custody; the once slot and lock name are not replaced, retried or recreated. A late response cannot authorize another send or a CAS. The outer launcher must retain source ownership and distinguish worker termination from successful closure.

Case R19 delays the synthetic original provider's finally until after the abort signal and verifies that core completion waits for that original finally. Cases R32 and R33 verify zero mutex-release calls and zero CAS calls while transport or original-function closure remains unknown. Their local harness closes only its own synthetic fixture files after inspection; that teardown is not a production unlock protocol. The initial R2 32/33 result and its source preimage are retained separately. Its failed assertion expected the older negative-case error boundary; the final test checks the stronger transport gate, and the final source also adds the explicit UNKNOWN retention barrier.

## Source-bound provider hooks

`mac_refresh_provider_hooks_r1.mjs` constructs in-memory overlays of three whole-hash-bound installed SDK source files:

| SDK source | Prepared change |
| --- | --- |
| OpenAI OAuth flow | Check the selected refresh entry; clamp original options to the same absolute deadline and 30-second limit; call private durable response capture after the SDK's original bounded body reader and before its original JSON parser. |
| Fetch guard | Carry one private ticket through its original DNS/proxy/dispatcher preparation; use the controller's synchronous final-send latch; refuse redirects; suppress the optional generic request/body capture; record the original close helper's completion. |
| Runtime fetch | Preserve the SDK's request normalization and call the final native fetch exactly once through the same ticket. |

The registry requires the existing exact token endpoint, method, public client ID, selected refresh form, headers and owned dispatcher. It does not substitute a provider identity or broaden the selected profiles. It refuses mocked/custom global-fetch paths in production. Only the original final native fetch is invoked after the controller's durable UNKNOWN record and synchronous source/writer/mutex/ledger fences.

A dispatcher observer wraps the original object's original close/destroy methods to record their returned promises and settled state. It never issues an additional close/destroy call or retry. The original close helper returning is recorded separately from actual dispatcher closure. The provider wrapper awaits the original native-fetch and closure promises and checks the dispatcher's terminal closed/destroyed state. Until those observations are known, the core cannot admit CAS or the next owner. The original hook descriptors are restored after observation.

Thirty local synthetic registry/dispatcher fault cases pass. Six constructed source files pass local Node syntax checks; three are unchanged dependency sources and three are overlays. No installed SDK module, DNS, TLS or OAuth request was executed by those local tests. The actual Mac `closeDispatcher` implementation and its Undici runtime dependency still require whole-source capture and review before the isolated Mac qualification. Their promise behavior must be checked against these observers; the local fake dispatcher is not evidence of that behavior. Source-pinned and actually loaded-through-hook are separate per-file facts; a source pin does not prove execution of lazy or unused paths.

## Current gateway writer gate

The exact registered gateway lineage observation succeeded as job `1a1b2348f45-fc05-7cf1`. Loaded arguments matched the current plist; the current configuration generation predated the observed process birth and stayed unchanged. Those observations do not establish current plugin-memory flags. The next structural-argument projection, job `1a1b238f96d-fc05-7d05`, failed closed because it assumed the eight arguments began with `/bin/sh -c`. It exported no unknown argument value and performed no service, credential-store or provider action. Its original failure is retained.

The prepared R2 structural projection accepts only recognized shell-switch variants for interpretation and otherwise returns a redacted unknown structure. Eight local privacy/grammar cases pass, including argv0 aliases, login-shell syntax, a program omitted from ProgramArguments, private shell literals, private arguments and ambiguous duplicate switches. It has not yet executed on Mac. Recognizing a login shell will not qualify its startup-file environment or loaded plugin configuration.

If direct source binding cannot close the running-writer gate, the available original private restore material can support a separately reviewed, minimal owner-bound quiescence: revalidate the exact label, process birth, original loaded arguments and unchanged private plist/config; record one stop intent; perform one registration stop; prove the old process/group/children and label absent; execute only the fixed main3 once protocol; then restore the exact original service only when source outcomes and transport closures are known and the restoration's endpoint behavior is admitted. UNKNOWN refresh or stop outcomes cannot be turned into a fresh attempt or automatic restart. No such quiescence action has been dispatched.

Actual source generation/capsule after a known refresh, target KV CAS, provider application liveness, actual gateway consumption, client restart/rollback, production cutover and old OpenBao cleanup remain separate gates.
