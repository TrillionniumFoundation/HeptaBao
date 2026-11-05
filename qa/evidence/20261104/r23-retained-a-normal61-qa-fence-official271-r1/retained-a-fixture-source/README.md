# Same-root republication regression: preserve the actual first A projection

SOURCE ONLY. Proposed parent: 1c66541993662f92cf717154e33717abedb2ea74.
The prior actual Mac run remains original 60 PASS plus additional 1 FAIL.
No new compile, normal test, fixture, source commit or PR is claimed.

## Determinate failure
The original helper publishes a newly generated V5-to-V6 projection on every call.
service_records_v6.rs line 679 generates its object_address_key randomly each time.
Root encoding and its keyed identity include that key. The third migration is
therefore not a republication of the first complete V6 A root. Actual failure was
the unchanged assertion comparing third.root_digest() with first.root_digest().
It occurred before old_same_root_selection and before the warm/cold repair cases.
See the original immutable core and source-cause packet; the production fix was
not reached by this failing regression.

## Exact scope
Only the new regression module changes. The existing shared installer tests and
all production Rust source are unchanged. The original test name, all 30
assertion lines, and every byte from the third-root equality through the final
cold reopens are unchanged. The intermediate B write and its old publish helper
are unchanged. No assertion is removed and no address key is overridden.

The new test-local helper is mechanically derived from the existing real
publish helper. Its only substitutions are its name/first parameter, entering
and checking the retained plan's existing absolute deadline rather than making
another projection, and passing the already-borrowed plan directly. Its actual
closure validation, ciphertext copy, intent, Raft Stage and Publish calls are
otherwise exact. Each call constructs a new closure/proposal and publication
intent; no old sealed publication or read-authority certificate is reused.

## Lifetime and request boundaries
1. Within the original 15-second scope, the service makes the first real A plan.
   That plan owns its canonical root/bytes, candidate and complete Arc-backed
   objects. It does not hold a mutable borrow of the service.
2. The first A is published using that plan and its original deadline.
3. The two target owners install A under the unchanged request scopes.
4. A real B mutation and a new B publication use the existing helper unchanged.
5. The third publication borrows the same immutable A plan, creates a new intent
   with current B as predecessor, and enters the first plan's original deadline.
   An expired A plan is rejected before preparing new ciphertext. No deadline
   field is overwritten or refreshed. The Raft publication still receives that
   original absolute deadline from the fresh proposal.
6. The original equality, generation +2, migration-source and increasing-index
   assertions must pass before the unchanged stale-cursor/warm/cold assertions.

The retained A plan's 15-second lifetime therefore also spans the intermediate
work. This is stricter than resetting a new 15-second plan on the third call.
There is no promise that an overdue fixture is rescued; it must fail rather
than extend its plan or repeat an unknown operation.

## Verification completed
Exact four-hunk forward/reverse reconstruction; new helper inverse mapping to
the original shared helper; exact existing B block and all downstream checks.
Whole source membership is tied to the actual 1c665 tree. These are source
checks, not Rust compilation or test execution.

## Next admitted validation
Run the existing pinned formatter against this one new module in a fresh owned
format root, retain original and formatted bytes/diff. Then the root coordinator
may create a distinct source identity and admit actual Rust compilation and the
separate A-to-B-to-A regression plus the unchanged 60. Original 15-second scopes,
600-second group cap and both platform outer/build caps remain unchanged.
