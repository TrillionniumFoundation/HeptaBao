# Actual ROG service observation and bounded source refusal

The native read-only service query found the registered user `openclaw-gateway.service` active/running/enabled, with current PID 599954 and its exact invocation identity retained in the original response. The two held restart helpers were inactive. The system-scope units were not used as proof of user-scope state. This observation performed no service action.

Current-source observer job `1a1b279171a-fc05-7e2b`, operation key `rog-current-registered-client-readonly-observation-20261106-r1`, is failed/exit 1 with complete durable output: 5284-byte stdout and no stderr, after 0.0068159319926053286 seconds. It failed with the fixed code `source_parent_ownership` while entering the first public-plugin pin; no plugin file was qualified and the final source/lifetime fence was not reached. The code does not establish which particular ancestor violated the predicate. A fixed-path metadata-only follow-up can observe that without changing permissions or replaying this operation.

All 17 returned observation descriptors closed. No auth-database contents were read, no child or network connection was opened, no credential values or digests were published, and no production service or configuration was changed. Partial single-point observations of configuration and six database file identities are retained as such; they are not a complete source or active-writer qualification. The one registered OAuth profile count is not asserted to be the number of actual credential objects.

The original source and original runtime launch/status/read responses are preserved losslessly, including all numeric JSON tokens and `bytes_hex`. `result.stdout.original.json` is the exact decoded stdout text rather than a reserialized object.

The older source-preparation operation `1a1b14de59a-fc05-779f` remains UNKNOWN. Reading its original PTY identity returned an unknown-terminal error; reading its original job returned a missing job-directory error. Neither response is authoritative proof of non-execution or closure. No new-key replay, cancellation or cleanup of that unknown operation was performed. Unrelated runtime-history entries are not exported.

ROG has not passed production credential I/O, gateway restart or complete rollback, and its traffic has not been switched. Full replacement and legacy cleanup remain unqualified.
