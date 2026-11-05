# Fixed owned Mac QA metadata observation

This proposal isolates the three terms of the failed R4 QA guard. It observes only the one existing owned QA directory, with six held ancestor directory FDs and the fixed 27 T5 anchor strings. It follows no symlink and opens no regular-file body. It does not query UUID again or inherit the former guard result as a current fact.

The scanner reads at most 32 immediate members, with no recursion. Only names already in the frozen set of 20 public source basenames are emitted literally. Any other name is represented only by its SHA256 and lstat type/metadata. No readlink or member content read occurs. If EOF has not been observed before the 32-member bound, the probe refuses rather than reading a 33rd entry or claiming a complete inventory.

The public result reports directory identity stability, exact count and exact old-18 membership as three separate booleans. A completed metadata observation can truthfully report membership false. It is not a source, inert or runtime PASS and does not establish the precise state at the earlier refusal time.

All directory descriptors and the iterator have once-only closure records. The original five-second observation budget covers opening, scanning, final nine-field named/FD checks and closure. The supervisor is fixed at 60 seconds. The exact request is unsubmitted. There is no child, network, private input, file write, permission change, guard relaxation, inert replay or business action. The AST receipt only compiles this source without executing the module.
