# Native OpenAI R1: one-submission outer controller

`qa/openbao-acceptance/authbus_native_openai_once.py` is a narrow derivative of the actual R4 OpenAI outer controller (base SHA-256 `faee8f81f5ed4441284804579b1fe261aaf304a409078683a27beebc97eb20ec`). Sixteen custody, input, SDK, source-staging and owned-session functions retain identical ASTs. The profile adds native artifact verification, the exact new 141 / 87 / 80 / 80 qualifier and the native Python entry. It keeps the original 180-second budget and the same private-ancestor SDK reader; it does not chmod or modify the installed SDK.

The controller accepts exactly these two arguments on main:

```sh
python3 -B /home/qian-qi/heptabao-next-gates-20261017/authbus-native-openai-r1-once-20261019.py \
  --packet /home/qian-qi/heptabao-next-gates-20261017/authbus-native-openai-r1-20261019.tar.gz \
  --run-root /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-native-openai-r1-actual-20261019-01
```

The source packet and embedded manifest have fixed SHA-256 and size constants. The archive must contain the exact 22 runtime files and manifest, all ordinary 0644 members; aliases, extra members, duplicates and SDK input drift are refused before execution. The SDK source closure remains 35 JavaScript modules, one activation file and two package/bin files. The actual native R5 build summary, source manifest, binary and Node executable are checked before running. The current Python interpreter is independently fingerprinted for the owned driver submission.

The run directory is a new, owner-only one-submission claim. Existing directories are never adopted or retried. It contains `controller.json`, `driver.stdout.log`, `driver.stderr.log`, staged `source/`, and the independent native fixture under `fixture/`. The authoritative original controller receipt is `fixture/public-receipt.json`; the three SDK receipts are `fixture/sdk/reports/{warm,cold-before-server,cold-after-server}.json`. Failed output remains in that owned directory for reconciliation. No new external provider or existing service is started or changed by the controller.

The one original deadline is passed as `--original-deadline-ns` to the native driver. Its existing Owner closes the original native, SDK and OpenSSL handles and verifies each child SID. The outer retained Popen/session helper closes the driver session. Passing requires both levels of receipts, exact source/SDK/product checks after execution and completion within the original budget. The terminal journal fsync has an additional original-clock recheck; late publication is written as failure.

The packet test can be run without a native binary or SDK:

```sh
python3 -B qa/openbao-acceptance/test_authbus_native_openai_once.py \
  --packet /absolute/path/to/source-packet.tar.gz -v
```

These packet tests and the helper AST comparison do not count as an actual native OpenAI run. The original native 120-check and SDK32 receipts are explicitly refused as evidence for this combined profile, and the new actual result remains pending at freeze.
