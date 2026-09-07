# HeptaBao Licensing and Clean-Room Status

Status: `V2.1 / HB-BLK-EXT-001 / NO FINAL OUTBOUND LICENSE SELECTED`

This repository is not an OpenBao source-translation fork. HeptaBao is planned as an independent Rust implementation driven by approved public specifications, standards and versioned black-box Oracle observations.

## Current restrictions

- No final outbound license has been approved for HeptaBao implementation files.
- Do not redistribute or publish a release based on this repository until `HB-BLK-EXT-001` has an authentic signed legal disposition.
- Do not copy, mechanically translate, model-translate or lightly rewrite OpenBao source files into HeptaBao implementation crates.
- Do not copy upstream tests, generated protocol files, snapshots or fixtures into the clean-room implementation lane without source classification and license review.
- OpenBao source used by the Oracle/specification lane remains subject to its own MPL-2.0 notices and obligations.
- A change of programming language does not remove provenance, copyright, patent, trademark or license obligations.

## Required lanes

1. **Oracle / specification lane** — may inspect approved public behavior and sources; emits sanitized, implementation-independent specifications and fixtures.
2. **Independent implementation lane** — receives only approved specifications, public standards and sanitized fixtures.
3. **Interop-exception lane** — handles protocols or formats that cannot be determined reasonably by black-box behavior; requires file-level provenance, legal review, license classification and explicit containment.

No person or automation may move material between lanes without a recorded source classification, digest, reviewer and disposition.

Historical work package `H00-WP06`, retained by the main-line legal policy, maps to current external blocker `HB-BLK-EXT-001`. This mapping preserves the signed-disposition requirement and grants no redistribution or release authority.

## Required external legal outputs

- outbound implementation and documentation license decision;
- MPL-2.0 and interop-exception handling rules;
- contributor DCO/CLA policy;
- third-party dependency license policy;
- trademark and naming policy;
- patent and defensive-publication policy;
- cryptography/export-control disposition for intended distribution regions;
- public release and source-offer obligations;
- retention and destruction rules for upstream-derived research material.

Until those outputs are signed, all release and public compatibility authority remains false.
