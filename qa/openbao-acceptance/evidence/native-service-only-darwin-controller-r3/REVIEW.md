# Darwin process custody R3 — actual Mac evidence

R2 retained the original Popen and repeated WNOWAIT but incorrectly required Darwin waitid.si_uid to equal the account UID. The existing owned Mac probe reported si_uid=0 for a uid501 child. The original actual R2 run failed both synthetic process checks before any Rust compile; those receipts remain below.

R3 binds the real effective UID from ps together with PID, PPID, PGID and lstart. It retains live SID/PGID checks, fresh matching zombie observation on ESRCH, repeated identical WNOWAIT events, same original Popen and one final reap. It never interprets ESRCH as an empty group. The original command budget (1800 seconds), compiler commands, target lock, source pins and 55-test denominator are unchanged.

Validation: eleven local mocked identity checks passed, including actual observed zero si_uid and wrong process UID rejection. On the physical Mac, both original synthetic process cases passed; normal exit needed no signal, and a leader that exited before its same-group child retained custody through SIGTERM cleanup and final reap. The original native-Service-only cargo check and test --no-run then passed against exact 9770 source. This is a compilation result; zero Rust tests were executed by the native-only controller. The separate 55/55 scoped Mac run retains its own earlier receipt and scope.

This controller fix is not HA qualification, a production cutover or proof of full OpenBao replacement. R2 failures and prior probe remain unchanged.
