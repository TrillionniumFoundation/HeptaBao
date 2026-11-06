# R5 source mechanical supplement

The immutable core17 source/request/journal remains unchanged. This supplement publishes the already executed 93-check pure V8 verifier, result, exact helper sources and full public-probe input source. Its interface is verifyFixedCrashR5Source(files, publicProbeSource); the original core manifest is retained as source-core.manifest.original.json.

The two original source-builder failures occurred before the candidate was frozen, before a Native call and before any Git mutation; they are preserved as separate error-history JSON. The first was an indentation-sensitive exact-literal mismatch, the second was a schema literal occurring twice (main and fallback) while the builder initially required one occurrence. The unsubmitted draft journal temporarily retained the old request pin; the frozen core journal binds the correct new request, and the draft is retained solely as history. None was used for Native admission.

This source verification is not actual runtime, SDK, credential or product qualification. The R5 read-only observation is separately preserved in full108 tree 4a27344fe587b316b2238986b6237879a710ed9f. The source passed root's independent 56 checks before that execution. No additional Native action is requested or authorized here.
