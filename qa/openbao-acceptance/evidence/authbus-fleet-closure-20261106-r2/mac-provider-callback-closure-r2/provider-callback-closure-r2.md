# Provider dispatcher observer R2 and isolated Mac qualification preparation

The provider helper is prepared code. No real provider call, production CAS, production mutex acquisition, gateway stop, or client cutover occurred in this checkpoint.

## Concrete installed-source compatibility defect

The current SDK directory contains Undici 8.5.0. Its public `DispatcherBase.close()` Promise overload synchronously calls `this.close(callback)`. `destroy()` similarly calls its callback overload. The original close chain also calls `this.destroy()` asynchronously after its internal close completes. Separately, the SDK close helper may call `destroy()` after a 100 ms timer. Thus one logical original cleanup can legitimately include one outer close Promise, an internal callback call, and more than one outer destroy Promise with their internal callbacks.

The previous prepared observer rejected a second method call and required every method call to return a Promise. That shape is incompatible with the actual source. The original R1 source and its 30 synthetic tests are preserved. A new regression executes the exact captured DispatcherBase source with explicitly stubbed dependencies and demonstrates the old observer's rejection before its internal close work runs. This is a source-bound local harness reproduction, not an installed-Mac Agent result.

## Minimal R2 semantics

R2 preserves the original receiver, arguments, return object, callback, and thrown error. It does not issue a close or destroy, retry a cleanup, or reject a legitimate callback overload. It records each outer Promise and associates a synchronous internal callback overload with its outer original invocation. The original asynchronous close-to-destroy chain and the helper's timeout destroy are both observed. A bounded observation overflow or an unexpected shape makes closure unknown while the original cleanup still runs.

`settleOriginalPromises()` also waits for original Promises added by an asynchronous original cleanup chain. A helper return, a set `closed` property, an abort, or a settled destroy alone cannot substitute for all observed original Promises finishing. A rejected original acknowledgement remains unknown even if the actual Agent reports closed. The core R2 once ledger and mutex retention barrier are unchanged; the business native-send latch remains one-use.

The loader now pins eight public SDK source files and three public Undici files. It checks the actual SDK-anchored `require.resolve("undici")` path without requiring the lazy package. It records SDK hook loads separately. At a real runtime entry it inspects the already loaded package cache, requires the original direct Agent methods and original native fetch identity, and rejects the SDK's test override global. The loader does not force an unused lazy import to fabricate an observed-loaded claim. The three package files read here have not by themselves proved that the Mac loader resolved them; that is an actual qualification gate.

## Completed local evidence

The R2 local suite passed 40 of 40 cases. It includes the old 30-case scope with the cleanup observer expectation corrected and ten source-bound DispatcherBase/close-helper cases. In the original 100 ms timeout case, helper return is observed while the original close acknowledgement is still pending. Closure becomes known only after that original acknowledgement and all asynchronously added destroy Promises settle. All eight generated SDK source overlays also pass local Node syntax checks. These results do not establish provider availability or actual Mac native transport behavior.

## Prepared actual Mac isolation

`launch_provider_qualification_r1.py` is a create-only, source-pinned operation for a new private root. It retains a shared 45-second budget, three original owned children, a 70-second supervisor limit, the previously qualified custody helper, exact Node/Python/sandbox executable pins, and the original closure requirements. The two syntax children precede one bounded worker. The sandbox permits no network and denies production profile reads and writes; the worker also refuses database access and child creation. Cwd and ancestor directory literals are admitted without granting their subtrees.

The 16 planned cases cover actual installed SDK imports, actual Undici resolution/cache identity, empty real Agent close/destroy callback behavior, the original 100 ms helper with an explicitly delayed acknowledgement, and a lost acknowledgement that must stay unknown. The remaining flow cases deliberately install a fixture-only DNS answer and the SDK's official test runtime after disposing the production loader. They execute the already captured source overlays and original OAuth parser, with real empty Agent cleanup and synthetic Response objects at the native fetch boundary. Cases cover success, no redirect follow, HTTP refusal, invalid JSON, missing account identity, response-fsync refusal, the original one-MiB body limit, native-boundary rejection, and a source change before the final send.

All credentials in that future worker are synthetic. It does not contact OAuth, exercise a real socket, execute the production once controller, or perform a production write. Raw synthetic responses are durably captured before the original parser. Planned actual checks are not reported as passed until their original Mac terminal record and complete stdout are obtained. The actual-provider once operation still requires running-writer exclusion and final concrete launcher review.
