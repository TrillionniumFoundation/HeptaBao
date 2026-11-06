# Current576 default libtest compilation fix — source proposal

Fix the four actual compiler errors preserved in compile.stderr.original.txt. Exactly three test source leaves change. Two existing HaProcess fixtures gain the same feature gates as the production fields, with absent snapshot callback and empty server-pin map. Two existing zero-transition assertions use stable ExactSizeIterator::len. No product logic, dependency, test name, expected outcome, timeout, audit assertion, or test selection changes. The unused-mut warning is retained.

This source-only proposal still requires independent review and compilation/runtime execution. It carries no production or replacement qualification.
