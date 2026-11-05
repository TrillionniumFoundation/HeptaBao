# Runtime identity reference: exact scope

The whole public reference is `fc559bec715e95fee000b65c54c083f4fdd43450` (171,794 bytes; SHA-256 `98344ab61981793fa8b6cda92d777c62639dd6d61b4e3b6db0e94bb96f011fe5`). These findings describe that reference only.

## Inventory responses

Both `list_jobs` and `list_jobs_page` expose five fields: id, host, created_unix_ms, execution_mode and launch_state. They do not expose request_digest, idempotency_key or argv. The unpaginated response is explicitly non-authoritative and is refused if its complete MCP wire encoding exceeds 1 MiB; it does not return a partial inventory. The unpaginated path reads/validates every JSON record before host filtering and sorts matching rows by creation time. The page path projects the same five fields and sorts by id. A time-window match narrows candidates; it does not establish the original request binding.

## Controller record and remote request differ

The controller record path is `runtime_config().state_dir/jobs/{id}.json`; the configured state_dir value is not established by the source alone. JobRecord includes host, ssh_target, remote_job_dir, executable, args, cwd, env_keys, created_unix_ms, idempotency_key, request_fingerprint and optional full request_digest. The reference publishes this record before remote launch.

For the operator Python path, remote_job_dir is generated from the configured remote_state_dir plus `/jobs/{id}`. The original current normal5 ACK observes `/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs/1a1abd1f635-fc05-50c9`; this is one exact known record, not a guessed path for the unknown LAN job.

The remote launch request includes job_id/job_dir/unit, request_digest and a digest-valued request_fingerprint, platform, execution_mode, executable, args, cwd, env, stdin, timeout and resource flags. It does not contain host or idempotency_key. The start code adds default_cwd, launch_nonce and terminal_publication_protocol, removes stdin into an exclusively created stdin.bin and records stdin_path. It writes request.json with O_EXCL and synchronizes it before launching. Its nice value is normalized to 0 even when the original typed Option was null. Consequently remote request.json must not be treated as the original typed input or used alone to recompute the original request digest. This review never opens stdin.bin or any job directory.

## State remains unresolved

The LAN process_start timed out without an observed job ID. Only one submission occurred. There are no subsequent Runtime observations on this line. Its terminal status, effects and cleanup remain UNKNOWN. A new key, repeated business submission, invented cursor or assumed absence is not justified by this source analysis.
