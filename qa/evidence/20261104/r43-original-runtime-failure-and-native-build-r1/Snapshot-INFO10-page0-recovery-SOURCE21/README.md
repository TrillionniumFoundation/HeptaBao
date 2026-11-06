# Closed INFO result delivery recovery — SOURCE only

The original file_info operation is already completed/inactive. Its first immutable result page returned a transport error. This successor proposes one separately recorded read of the same operation ID, offset 0 and limit 8192. It does not reissue file_info, create a future, or reset the failed call.

The only source changes are a guarded preparation entry, a recovery-specific whole-page EOF check, and one gfRun dispatch branch. Existing invoke and close functions are unchanged. All original request, SDK, failure and counters remain available. The original failed call remains called=true; the new call starts called=false only after a separate exact root approval and external arm.

36 isolated V8 source/fake-archive checks passed. No Native call, filesystem operation, Python, Rust, or candidate execution occurred. A fresh root GO and lane allocation remain required.
