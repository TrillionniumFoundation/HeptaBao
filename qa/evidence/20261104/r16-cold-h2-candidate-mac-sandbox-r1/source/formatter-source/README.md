# Cold/H2 normal candidate input formatting

Source-only, exact four public Rust inputs. The fixed request has not been submitted. Original formatter lifecycle, helpers, stdin bound, rustfmt arguments and 50/10/60 second caps are unchanged. Only the fresh owned root, source pins and base provenance changed. Normal Rust build, tests and product operations are outside this request.

The two newly added cold tests and six H2 tests have Result/? error handling, without new lint suppression. The old test drafts and original failures remain preserved. Source AST checks here execute only Python parsing/compilation and finite string/hash checks; they do not import the candidate controller or run Rust.

After actual formatting and full source review, root may freeze a new canonical candidate based on 3cb. The future build retains the exact original 44+7 and adds one separately named shared 600-second group containing two cold helper tests, the entire existing actual cold missing/corrupt repair test, and the six H2 helper tests. No new candidate inherits the old build or test qualification.
