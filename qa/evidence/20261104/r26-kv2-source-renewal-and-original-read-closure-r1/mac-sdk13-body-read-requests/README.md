# Fixed Mac SDK public body requests

These are the same thirteen typed requests previously frozen in body-plan.public.json. The three metadata operations are already closed and root-verified. No body request has been submitted. The packet separates each request into an immutable byte string for dispatch and evidence association; it introduces no new path, key, version, offset, limit or operation.

The first operation is the 6,047-byte loader body. The next eleven cover the 673,468-byte selector without gaps or overlap, and the last is the 3,135-byte registry body. Whole reconstruction is exactly 682,650 bytes. Each read uses the independently observed version. Original operation results are recovered via bounded immutable pages, not a second native read. Every admission and original result must be preserved before parsing. A missing ACK uses only the same typed key to reconcile. No SDK executes and no private body is exported.

The shared Runtime window remains required before the first start. This source packet itself is not authorization to occupy it or an assertion that the Runtime host transport has recovered.
