# Original BUILD terminal chain

The verifier independently rebuilds the 31 original native calls and 10 original observers/pages, SDK/native bindings, arm inputs, complete immutable payloads, continuous streams and final stdout. It invokes no native tools, product code, Cargo or Python. The actual result is 403 pure checks passing.

The first verifier incorrectly expected running process_status results to contain exit_code=null. The actual seven original running statuses have no exit_code field and report backend=systemd, ActiveState=active, SubState=running. The first verifier/error is retained; the corrected check explicitly requires that actual shape. No native original, candidate source, or runtime action was changed.

The normal-production-release-built row is a phase observation. The terminal exit is 1; the full detailed report, actual test results and detailed child/target facts remain unread at this archive boundary. No Cargo replay or target reuse is authorized by this packet.
