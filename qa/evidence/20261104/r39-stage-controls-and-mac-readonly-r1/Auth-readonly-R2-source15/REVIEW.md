# R2: remove two dynamic raw-body hashes

SOURCE ONLY; no slot initialization, Native request, managed effect, or cleanup.

The original child validator returns only an explicit typed projection and does not validate every allowed value (for example elapsedSeconds and optional sentinelFull9 are not projected). Publishing a whole raw terminal hash after that validator would still fingerprint unclassified bytes. R2 removes that raw SHA field and the analogous ready raw SHA. It retains current full9, byte count and every original typed gate/projection. Fixed Python/source/plan/plist SHA gates and outputs remain exact.

The two source hunks remove exactly these two output fields, with no I/O, error handling, parser, ownership or deadline change. The request is bound to the new source and fresh r2 key. The journal changes only slot, request pin and observer prefix. The previous 33-file packet remains immutable, including its 78 V8 source checks and unavailable local compile attempt; none was rerun or rewritten. This overlay performed 18 pure V8 exact checks and did not execute Python, SDK, Runtime or fake OS.

Parent zero can mean a complete bounded current observation with an original parser rejection. The original R4 managed scope remains UNKNOWN; there is no bootout, signal/reap of its managed PID, new generation, T5 access or credentials.
