# Remaining Service audit-failure regression gate

The 23 existing Rust component-test sources remain separate: body framing 10, transport 7 (six socket/mTLS scenarios plus one constructor-only rejection), completion wire 4, and Auth 2. They have not been compiled or executed. None is evidence that an actual restore committed and then failed a Service response-audit gate.

Before repaired CLI behavior can be qualified, a separate bounded Service-level regression must use the actual Service/Auth/native state and actual historical publication receipt. The essential observations are:

1. Complete a real restore publication, retaining its original Auth admission, physical/native owner and historical recovery reference. Trigger a source-side post-publication delivery/audit rejection. Verify conservative UNKNOWN/no replay and preserve authority only from the actual retained historical receipt; a normal 503 must not erase a known attempted publication. Confirm the mutation outcome independently of the response.

2. On the ingress, consume an actual authenticated completion for that restore. Cause the first native delivery check to reject and the failure-response audit to fail. Verify UNKNOWN, retry_allowed=false, the authenticated root_attempted/recovery_reference, no exposed private download file, and the required recovery fence. The completion must come through actual authentication, not a deserialized JSON fixture presented as trusted evidence.

3. Exercise the second native delivery-check veto and its veto-audit failure after a completed response audit. The same authenticated historical fields must survive the reconstruction path. Private file capability must be dropped, and the original request must not be replayed.

4. Contrast a transport attempt with no authenticated completion and a failure before transport dispatch. An attempted but unresolved exchange can yield conservative UNKNOWN, yet attacker-provided response JSON must not create root authority or a recovery reference. A pre-dispatch failure must not invent a completed publication. Original admission/use counts and the same request clock remain assertions.

This is an explicit remaining gate specification, not new executed test coverage, not an authorized failure-injection run, and not an enlargement of C's 149-unique / 166-profile initial build denominator. Precise test source, injection points, bounds and execution request require their own review. A fresh current-candidate CLI B01–B05 result, with unchanged archive/content/audit/cold checks, remains necessary; the old B04/B05 failure is preserved.
