# Fixed six SQLite file-header observation

Original Mac job `1a1b354e332-fc05-8220` completed with authoritative exit zero, complete durable 1,278-byte stdout and zero stderr. Source is frozen at SHA-256 `8bcb6623e3087e231e88fa31b54815a6b460bf5e7e048e67ed9ae95b025480f2` (5,992 bytes).

Only the first 20 bytes of each already registered database were read twice. Offsets 18 and 19 are the SQLite write/read file-format versions; offsets 16 and 17 were not used to infer mode. Slot 0 has rollback format and absent WAL/SHM/journal. Slots 1–4 have WAL format, an empty WAL, nonempty SHM and no journal. Slot 5 has WAL format, nonempty WAL/SHM and no journal. These are header observations, not a `journal_mode` PRAGMA result or proof of current writers.

All six original files, sidecar identities or absence, and held parent chains retained exact full-nine-field identities across the observation. All 22 original descriptors closed once. Total database reads were 240 bytes. No SQL connection, credential row, child, network call, provider request, service action or source write occurred. The parent process and runtime launch are accounted for by the original job authority; `childCount=0` means no inner child.

This observation does not authorize a keeper, provider refresh or production restart. It invalidates the prepared assumption that all six sources require nonempty WALs. The maintenance design will prefer complete writer quiescence followed by a new generation; any read-only SQLite/actual SDK bridge remains an independently bound implementation requirement. No old frozen capture is promoted to latest.

`read.original.json` retains the original runtime text and hex payload and EOF offsets. `stdout.original.json` is the exact original 1,278-byte stdout. No raw database header, identity, credential, configuration digest or private identifier was published.
