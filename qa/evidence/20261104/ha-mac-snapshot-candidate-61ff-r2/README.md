# Mac snapshot candidate control correction r2

The original source-stage job `1a1a7f36e68-fc05-2d11` failed with exit 1 at Python `compile(stage_source)` before executing the stage source. The missing `finally: os.close(fd)` in `hash_owned` has now been added in both stage and build scripts. The original request, scripts, authoritative terminal result, complete raw read result and 431 byte stderr remain retained. This was a control-script syntax failure; it did not execute source preparation or product validation.

Only the two missing finally blocks change between r1 and r2 source. The same fresh root remains required and its existence is rechecked; no partial stage is reused. Runtime control filenames remain unchanged because the original stage source never created the directory. A separate fixed-Python compile-only request verifies both complete repaired source hashes before the new stage request can run. Neither that syntax job nor source staging starts Cargo or a product service.

The original 240 second source stage, 300 second build preparation, shared 1,800 second Cargo budget, normal profile, ten exact tests, release-lock clone, WNOWAIT cleanup and all qualification limits remain unchanged. No candidate runtime success is claimed by this correction.
