# HeptaBao V6 snapshot budget: scoped 15s / 30s qualification

**This is QA evidence, not release or production replacement authority.**

Source HEAD: e1c59a5b8284c698b17d16cf43b2f401e35916c2
Source tree: e4d293bd276d8be6c46b26b046065097254a143b
X230 execution binary SHA-256: 0bb9be5a6ae44095970552a3e71fc664b3780b45f24c4ad2386c8ee05e629fd5

## Original default 15-second failure

An isolated X230 Linux loopback HTTPS trial wrote 66 independently derived
2 MiB logical historical versions, exported more than 128 MiB of authenticated
native snapshot data, performed actual source restore and readback, and
successfully cold-unsealed the separate target. The target import did **not**
complete with an HTTP response. The preserved negative receipt has
passed=false, failure=RemoteDisconnected, server_timeout_overridden=false.

The bound target server log reports HBHTTP-RESPONSE-WRITE-FAILURE,
io_kind=timed_out, original_deadline_expired=true; authentication, typed
graph validation and object staging had consumed the original 15-second
transport deadline. A separate authoritative target check found the original
seed still present and no committed imported history. The unknown original
request was **not** retried or silently counted as success.

## Distinct configured-budget acceptance

A **new**, independent synthetic fixture of 66 x 2 MiB historical versions
was tested against the **same** source HEAD and native Linux binary, explicitly
setting timeout_seconds=30 in the actual server configurations while using
a 40-second client socket budget. The report retains both
default_server_timeout_seconds=15 and server_timeout_overridden=true.

Observed X230 results:

- authenticated native HTTPS archive: **139,781,694 bytes**
- target snapshot import: **HTTP 200** in **17,712 ms**
- **559/559** scoped assertions passed
- all 66 historic versions read against SHA-256 expectations after actual
  SIGKILL, target cold unseal and restart
- subsequent new version write, unchanged source and all owned-process exits
- no production endpoint, token, trusted certificate or config was changed

This closes the synthetic **configured 30-second budget** acceptance for one
X230 machine only. It does **not** change the default 15-second failure,
establish a portable latency SLA, authorize an automatic repeat of an
uncertain import, or prove migration of live production authority.

## Evidence gate and reproducibility

The companion v6_snapshot_budget_admission.py requires both receipts,
the failed server log, exact commit and exact binary SHA-256. It fails closed
on mismatched source/binary identity, rewritten default failure, missing
deadline logs, incomplete history/cold readback, duplicate imports, exceeded
configured budget, process leaks and incomplete cleanup.

    python3 -m unittest discover -s qa/openbao-acceptance -p test_v6_snapshot_budget_admission.py -v

    python3 qa/openbao-acceptance/v6_snapshot_budget_admission.py \
      --default-receipt default-15s-failed.public.json \
      --configured-receipt configured-30s-passed.public.json \
      --failed-server-log default-15s-server3.log \
      --source-commit e1c59a5b8284c698b17d16cf43b2f401e35916c2 \
      --server-sha256 0bb9be5a6ae44095970552a3e71fc664b3780b45f24c4ad2386c8ee05e629fd5

Private machine receipts stay in Mac/X230 operator evidence directories, not
in this public repo. The QA gate passed 13 positive/negative controls
separately on main Linux, X230 Linux and Mac. All independently computed the
same scoped result SHA-256:
cd6cea6d6ccf7c4815067b582f89db8ed12a02bffe5facba634946705e7e1955.

## Remaining blockers

- Mac T5 was 96% used; large new build artifacts need separate admitted space.
- Final integrated source must pass exact-head Mac/X230 native full serverlib
  and security matrices, and direct mixed-platform LAN fault tests.
- Default 15-second X230 large import still fails. Configured budget success
  does not itself prove default protocol compatibility.
- Full OpenBao 2.7.1 API, provider, identity/policy, PKI, audit and release-delta
  inventory, durable storage fault lifecycle and long-duration HA are open.
- Production authority credential custody, external migration, rollback and
  reproducible release qualification are open.

**Production cutover: false. Full OpenBao 2.7.1 replacement: false.**
