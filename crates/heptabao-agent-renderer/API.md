# Private process API

The executable accepts one newline-delimited JSON initial frame with `template`
and integer `timeout_ms` in 1..=60000. A frame is bounded to 1 MiB including its
newline, template source to 64 KiB, rendered output to 64 KiB, nesting to 64, and
secret calls to 128. Range iteration and evaluator steps have separate bounds.

During evaluation the helper may emit `{"op":"secret","path":"..."}`. The
owner replies with `{"ok":true,"secret":...}` or refuses the operation. Only
the owner may authorize or perform a secret request. On successful completion the
helper emits a result with `op`, `ok`, `output`, `secret_calls` and `steps`.
Failures emit the fixed category `template_render_blocked` and exit unsuccessfully.
These examples illustrate private framing, not a public authenticated service.

The library entry `run_stdio() -> std::process::ExitCode` implements that same
single-session worker. It owns no persistent store, endpoint, token or sink path.
The caller must retain and close the original pipes and enforce the outer process
deadline; the evaluator does not replace that owner.
