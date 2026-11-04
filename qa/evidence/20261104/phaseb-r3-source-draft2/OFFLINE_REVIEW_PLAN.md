# One offline R3 parse/components invocation — execution pending review

This is a separate source/parser gate. It starts neither candidate server nor
OpenBao CLI and cannot grant a product runtime pass.

1. Read the final source manifest from its exact Git blob. Build one stdin JSON:
   schema = heptabao.official271-native-cli-phaseb-r3.offline-input.v1,
   manifest_text = its complete original UTF-8 text,
   sources = the exact seven Python filenames listed by offline_review_runner_r3.py.
   Values are full already-verified source texts, not path names.
2. Bind the exact wrapper source SHA in the external runtime invocation. Use the
   actual selected Python with -I -S -B. Pass --manifest-sha256 and
   --external-wrapper-sha256 as exact public literals. Use --components for the
   one combined parse plus component invocation after root reviews this wrapper.
3. The wrapper reads at most 2 MiB stdin, verifies every source length/SHA/Git
   blob against that immutable manifest, and AST-parses/compiles all seven.
   References and binding are compile-only. No original or candidate main is
   entered.
4. It preloads stdlib, installs an audit guard rejecting open/os/socket/subprocess/
   ctypes/shutil/pty operations, and executes only the new controller/evidence
   module definitions plus their two pure component functions from memory.
   Components use explicitly synthetic dependency objects and memory captures.
   Actual NEW R3 controller stop/action/restore functions are called; no
   operating-system process, network, real archive upload or file write is used.
5. Component cases include gzip/tar corruption, nested audit/pair failures,
   JSON-escaped PEM literals, malformed successful mutation replies, restore
   readback/report failures, and the seed/cold/finish shared normal-stop budget.
   References are compile-only: these components do not execute or qualify the
   separate original timeout emergency SIGKILL + wait 5 s, which remains followed
   by at most the original one final normal 5+5 s cleanup allocation.
   Components do not impersonate any actual native product result.
6. One 30 s internal envelope covers parsing and components. The external
   single Python job may use 45 s to deliver its terminal output; it has no
   children to clean. Capture complete stdout/stderr and authoritative job status.
   Any failure is retained without changing observer predicates for a green run.
7. Root reviews the actual result before permitting concrete R10 host/artifact
   binding and read-only prepare. Physical snapshot CLI runtime remains a
   separately authorized fresh fixture.

The wrapper is executable review code, but has not been executed by its author.
The cloud execution environment remained unavailable. No passing Python
syntax/component receipt is included or implied by this package.
