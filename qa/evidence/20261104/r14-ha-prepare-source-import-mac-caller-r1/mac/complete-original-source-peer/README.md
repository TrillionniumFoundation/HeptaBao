# Mac current outer: independent source review

This package preserves review of immutable tree `0aca624b5d051ed55a62943a06b638c9b3090129`. It does not change that package or authorize a host run.

The two confirmed cross-module entry failures are the obsolete mandatory helper and the model-declaration LF mismatch. `components/result.public.json` is the original output of a successful offline execution with 36 expected-negative/proposed-closure records. The component script executes only selected pure AST functions/assertions after a no-I/O audit hook. It does not import the complete modules, connect to SQLite or a network, spawn a child, or inspect current host state.

The proposed after expression is a narrow counterexample closure, not qualification of an author successor that has not yet been read. The original capture library and the materializer global digest remain unchanged. Review limitations and the author's separately reported temporary-socket closure issue are explicit in `review.public.json`.

Reproduction: place the four original public source files beside the component script, then run `python3 -I -S -B cross_module_negative_r1.py`. The script reads only those source files and itself before enabling the audit hook.
