# B R2 node 2: cold failure source matrix

This is a source analysis of canonical `49503322c7f446e5eb41e7744f1fdbd7f1192ecc`, using the already terminal B R2 evidence. It does not start a product, replay a request, or select an inner cause from the generic 503.

The ledger's response hash matches the static local-publication mapper. The last selected route marker records state, barrier, record root and activation absent, with recovery_required=false. Cold activation publishes State/barrier late; its normal post-publication failure arms set recovery_required=true. These observations constrain the early cold path. They do not prove no durable local staging occurred, nor uniquely identify a failed helper.

The complete 18-row map is in EARLY_COLD_MATRIX.public.json. Every row identifies its exact direct callsites, collapsed rejection families, existing normal-build coverage, and the smallest useful discriminator. Distinct capacity, outcome-unknown and post-publication reconciliation responses remain separate.

## Existing normal timing comes first

HTTP execute_service_request calls begin_request_before. With HA present, this installs NativeV6RequestObservation and emits HBHA-REQUEST-TIMING-FAIL for a completed response >=500. Only health has a special request class; sys/unseal is ordinary. The record contains at most 64 static (scope, phase) buckets with bounded integer counters/times. Successful inner scopes are retained in a failed request's timing even though they emit no separate SYNC-FAIL.

The completed first projector deliberately selected two other marker types. It did not retrieve this JSON record type. A new reviewed passive projector can inspect the same stopped log under the same read/FD/deadline bounds. Source presence does not prove an actual record exists or that any ordinary record belongs to seq49; line numbers/order and absent/duplicate/invalid cases must remain explicit. No assumption is made about line 178.

## 3cb does not add cold-loader stages

The exact 3cb tree keeps all 3911 paths. Its five changed leaves are the runtime and four tests. Replacing only native_v6_committed_fresh_ingress_read in the 3cb runtime with its 495 counterpart restores the entire original runtime file byte for byte. That method's nine new phases do not instrument load_cold_native_ha, which calls native_v6_committed_read. A new 3cb binary cannot by itself fill these cold-loader/materialization/final-gate gaps.

## Evidence limits

- No request ID joins the old line 47/70 ReadIndex errors to the final failure; later successful unseals occur at lines 104/114.
- The final route marker is an internal state observation, not a persisted-effect receipt.
- Existing normal timing is bounded, thread-local, and logging errors are ignored by the application. Missing timing is not proof that no operation occurred.
- The original 91/98 and postcold 0/12 failure qualification remains unchanged. All old receipts remain immutable.
