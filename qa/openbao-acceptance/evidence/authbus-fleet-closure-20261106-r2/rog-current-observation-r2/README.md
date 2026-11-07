# ROG current source observation r2: original failure retained

The original observer `1a1b298b70e-fc05-7ed6` failed with exit 1 and complete, durable output. It read and pinned all eight registered public AuthBus plugin files, then rejected the selected SDK package at `bounded_owned_source_file`. All 81 returned descriptors closed. It read no credential database contents, imported no SDK, started no children, opened no network connection and performed no service or production mutation.

The r2 change is confined to the observed `extensions` ancestor (UID/GID 1000, mode 0775) beneath the held, unchanged private `LIVE` directory (mode 0700). It does not relax private-input, leaf-file or other ancestor checks. The later SDK metadata observation established a distinct package-file mode of 0664 outside that private enclosure. The r3 observer therefore reports that package only as an untrusted group-writable observation; it does not silently admit it for execution.

The original r1 and r2 failures, the earlier unknown source-preparation job and its original identity remain separate. A later successful bounded observation is not proof that the unknown job never executed, that running gateway memory matches current files, or that writer exclusion, credential migration, restart or rollback has been qualified.
