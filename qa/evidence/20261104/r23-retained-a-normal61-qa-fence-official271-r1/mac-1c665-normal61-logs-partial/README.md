# Original failed Mac 1c665 normal61: command and small-stream archive

All 48 original command records and 94 bounded streams are complete and whole-SHA checked against the records. The original 44+7+9 groups passed, and the one added A-B-A test failed exit101 at the root-equality precondition. Every original child was reaped with no remaining group and no timeout. The overall result remains FAIL.

Two original Cargo stdout files are larger and are not claimed archived here. Their independent file_info pins match the recorded whole hashes. The first two version-pinned read calls returned original MCP timeout errors, which remain archived. No further chunks were submitted after those errors and no build or test was restarted. This packet supplements the previously root-closed core40 packet, not a new qualification or replacement final result.
