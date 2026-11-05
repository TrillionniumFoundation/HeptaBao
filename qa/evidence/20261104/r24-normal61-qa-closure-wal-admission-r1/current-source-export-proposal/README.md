# 4e808 standalone source export — source proposal

This packet fixes one ROG source exporter and its inert publisher to commit `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` / tree `eba5e650bd080b8ad41ea52a2bc68867f541d255`. No source from this packet has run on a host.

## Existing source evidence

The original stage result `079369dac398d8fab512bd52c00657af7357467c` is preserved verbatim. It identifies the independent ROG source at `/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/source`, sole parent `1c66541993662f92cf717154e33717abedb2ea74`, 3,763 historical commits and 3,914 worktree leaves. Its 56 owned children were closed. This is source provenance, not product test qualification.

That stage's 29,953-byte bundle has a 495033 prerequisite. The proposed exporter creates a separate full bundle with no prerequisites, a single exact HEAD and the complete ancestry. The new bundle size, hash, version and receipt identity remain unresolved until the actual export.

## Minimal change and unchanged contract

The complete old 15,324-byte exporter and 4,813-byte publisher were recovered from the fixed original df026 inert request, not reconstructed from summaries. The exporter changes its documentation, source/output namespaces, exact head/tree/parent, history count and labels. All 20 functions and the exception class are byte-identical. The publisher changes its documentation, namespace, single exact source pin and schema labels. All five functions are byte-identical.

The exporter retains its original absolute 300 seconds, 90-second Git commands clipped to that deadline, TERM5/KILL5 cleanup, exact regular-file/full-SHA/full-identity reads, file-only Git protocol, source/refs/origin before-and-after checks, strict fsck, zero-prerequisite header check, create-only output, and post-publication final deadline guard. The inert request remains 60 seconds and export supervisor 330 seconds. Neither request changes the existing source tree or uses the Cargo target.

The new control directory is outside both the existing source and the new export directory. Inert publication only writes this one reviewed public source and its receipt, and compiles the Python source without executing it.

## Exact requests and separate stages

Both request JSON files are fully concrete SOURCE proposals. They are not execution authorization. The publisher has no additional argv requirement; the export request executes the exact source filename after actual inert readback has been accepted. The later desktop importer is a different program and will retain its required trailing self-SHA argument.

The subsequent carrier and importer will use the independent destination `/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-validation-source-r1`. Their actual input slots may only be filled from the new export and new transfer. Those operations are not dispatched by this packet.

## Validation

The included local offline verifier passed 70 checks: original source recovery, forward and inverse literal equality, complete strict diffs, unchanged definitions, exact source-stage identities and counts, exact carrier decoding and source pins, fresh namespace relationships, original limits, and both exact argv/stdin/cwd/key contracts. It parses/compiles four modules but executes none. It reads the preserved source-stage JSON with Python integers, without rounding nanosecond values. This validation does not confer host/export/transport/import or product qualification.
