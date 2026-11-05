# Native R2 and OpenAI R4: separate actual runs

Both original executions passed on main with Node 22.23.3 and SDK 2026.7.1-2. This evidence set preserves all 11 original files byte for byte; it does not rerun either fixture or edit a historical result.

## Native R2

The original four scenarios retain the exact ordered 120 controller checks and 59 / 57 / 57 worker checks. Runtime 21-file pins use the two current R3 adapters and the actual R4 native binary (SHA 7e68ebb51d3440c30696a7f7456322e48d2a39e702709a27736b78f451ae591c). The complete run took 60.47783935 seconds under its original 180-second budget. The native process was actually SIGKILLed and reopened; three distinct SDK processes used the real owned SQLite store before and after that restart. Provider outcomes remain 1 / 0 / 1 / 1, with no repeated send after durable UNKNOWN. The provider and all credentials are synthetic fixture inputs, carried over verified owned HTTPS. No external provider or production migration is qualified.

The 120 + 59 + 57 + 57 = 293 assertions here are a different denominator from the older 293 real-credential canary events. This document does not repair or reclassify that older wrapper receipt.

## OpenAI R4

The exact 32-scenario inventory completed 432 checks in 40.845323799 seconds under its original 180-second budget. The final five cases use the actual installed SDK's Undici 8.5.0 fetch through its managed environment proxy. They complete the exact 1 / 0 / 1 / 1 / 0 CONNECT/provider vector, with zero mapped-fetch calls, proxy denials or upstream failures. The outer controller submitted one child, reaped its original Popen and observed an empty owned live session. Source, SDK and configuration remained unchanged; outside-home reads, external writes, external processes and external network attempts are all zero.

The `guard-after-await` case deliberately supplies the registered fault adapter before entering the actual SDK refresh/guard path; it is a final-guard veto, and is not described as a shared-manager positive result. This SDK profile uses a TLS control emulator. Its original `actualNativeHeptaBao`, `actualColdSdkProcess` and `realExternalProvider` fields remain false.

## Why the static qualification object remains false

`loadOwnedRefreshFunctions()` returns an `Object.freeze` value after loading and binding the three builtin provider functions and three OpenAI functions. It explicitly sets `openaiFacadeQualified: false`, `openaiTransportQualified: false` and `actualExecutionQualifiedByRunnerOnly: true`. This immutable discovery result is stored under `qualification`; it is not an end-of-run aggregate and the runner does not rewrite it. Actual execution is separately represented by `actualOpenAiFacade`, `actualUndiciRefreshTransport` and the completed per-scenario assertions. The raw static false values are retained exactly and are not silently turned into true.

These two completed runs cannot be combined into an inherited native OpenAI/cold qualification. The new native OpenAI profile requires its own native UNKNOWN observations, actual OpenAI final dispatch, distinct cold SDK workers and native SIGKILL/reopen within one independently bounded execution. No production switch, real external token refresh or full OpenBao replacement is claimed here.
