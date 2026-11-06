# Independent row-to-KV-key reconciliation supplement

The original actual r3 projection, its 8/8 success, and the 21-file actual evidence tree remain unchanged. The first independent local checker reconstructed every original two-table row commitment and checked the complete globally ordered opaque ID list. A further review identified that it did not explicitly bind each individual row's source identity to its expected opaque KV key.

The r2 independent checker adds a mapping from `(agent_slot, table, original_primary_key)` to the expected opaque ID after primary-key sorting, then requires each actual row's `record_id` and `kv_key` to equal that mapping. It uses only the already obtained complete private output, binding and small original capture manifest. Root executed this narrow additional verification successfully; no database, product, remote process or new projection attempt was run. The original checker and report are preserved in `projection-r3-actual/`.

The v2 report closes the row-routing relation as well as retaining the original full-row commitment, native file identity and terminal checks. Private input bytes and content fingerprints are not included. The projection covers the two designated auth tables of the five captured agents; formal KV2/API, HA, AuthBus and cutover remain unqualified.
