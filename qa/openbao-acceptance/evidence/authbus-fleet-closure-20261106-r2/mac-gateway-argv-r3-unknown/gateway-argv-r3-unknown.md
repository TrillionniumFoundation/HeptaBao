# Gateway argv R3: unresolved launch outcome

The unique read-only R3 invocation used job `1a1b28476e2-fc05-7e5f` and key `heptabao-authbus-current-gateway-argv-readonly-20261106-r3`. Its original `process_start` reply reported `launch_unknown`. Two subsequent `process_status` calls for that exact job failed because its remote job directory was absent. A separate `file_info` call for the fixed R3 public result also reported that the R3 QA directory was absent.

These are preserved observations, not authoritative proof that the process never started or that its custody closed. The invocation has not been repeated under its original or a new key. No successful runtime classification or public source capture is claimed for R3.

The frozen source has a 30-second internal limit and a 45-second supervisor limit. It has no child, network, provider, credential-store, registry, or service mutation operation. Its only possible writes are create-only files in its dedicated QA directory. It reads the already captured private gateway restore record, checks the exact registered configuration generation, classifies a finite shell syntax set without publishing unknown arguments, and can copy a bounded set of public SDK files. All remote RPCs had returned before the Mac window was handed to the SDK owner. The local 14-case qualification remains a local-only claim.

The earlier R2 observation is unchanged. It proved the old private restore record and current configuration generation still matched and identified the public entry path, but did not interpret the two unknown shell arguments or prove the running plugin's in-memory configuration. No gateway quiescence, restart, provider refresh, production CAS, or cutover follows from this unresolved R3 attempt.
