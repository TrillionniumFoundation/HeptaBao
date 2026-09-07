# External completion evidence

This directory contains only fail-closed input templates for `HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007`.

Every committed template is `UNEXECUTED` and non-authoritative. It is not evidence that an operator, reviewer, legal function, incident team, key custodian, Oracle lane, storage laboratory or reproduction environment exists. A populated candidate must be held under the declared custody system and admitted with the exact source identities through `scripts/validate_external_completion_evidence_v1.py --require-closure`.

Do not commit restricted raw Oracle captures, private vulnerability details, production credentials, private signing keys or destructive-laboratory secrets here. Commit only an approved sanitized object or immutable restricted reference.
