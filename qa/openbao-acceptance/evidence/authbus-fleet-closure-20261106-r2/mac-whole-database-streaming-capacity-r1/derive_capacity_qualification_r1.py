#!/usr/bin/env python3
"""Add one measured-size synthetic primary database to the qualified lifecycle."""
import ast
import difflib
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / "mac-whole-sqlite-streaming-r1-work"
raw = (PRIOR / "whole_sqlite_streaming_r1.py").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a"
(HERE / "whole_sqlite_streaming_r1.py").write_bytes(raw)
source = (PRIOR / "qualify_whole_sqlite_streaming_r1.py").read_text()
source = source[:source.index("\ndef run_snapshot_mechanism(")]
source = source.replace("def run_qualification(", "def run_capacity_qualification(")
source = source.replace("qualification.streaming.r1", "qualification.capacity.r1")
prefix = '''MINIMUM_PRIMARY_BYTES = 2469126144
MAXIMUM_PRIMARY_BYTES = MINIMUM_PRIMARY_BYTES + 32 * 1048576
PAYLOAD_BYTES = 1048576
PAYLOAD_ROWS = (MINIMUM_PRIMARY_BYTES + PAYLOAD_BYTES - 1) // PAYLOAD_BYTES


def capacity_payload(ordinal):
    need(type(ordinal) is int and 1 <= ordinal <= PAYLOAD_ROWS, "fixed_capacity_payload_ordinal")
    tag = ("heptabao-synthetic-full-state-%08x|" % ordinal).encode()
    return (tag * (PAYLOAD_BYTES // len(tag) + 1))[:PAYLOAD_BYTES]


def fill_capacity_database(store, row):
    store.query(row, "CREATE TABLE capacity_payload(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
    store.query(row, "BEGIN")
    row["transaction"] = True
    for ordinal in range(1, PAYLOAD_ROWS + 1):
        store.remaining()
        store.query(row, "INSERT INTO capacity_payload VALUES(?,?)", (ordinal, capacity_payload(ordinal)))
        if ordinal % 64 == 0 and ordinal != PAYLOAD_ROWS:
            store.query(row, "COMMIT")
            row["transaction"] = False
            store.query(row, "BEGIN")
            row["transaction"] = True
    store.query(row, "COMMIT")
    row["transaction"] = False
    pages = store.query(row, "PRAGMA page_count", limit=1)[0][0]
    page_size = store.query(row, "PRAGMA page_size", limit=1)[0][0]
    need(type(pages) is type(page_size) is int and page_size == 4096
         and MINIMUM_PRIMARY_BYTES <= pages * page_size <= MAXIMUM_PRIMARY_BYTES,
         "synthetic_primary_covers_actual_observed_capacity")
    return {"logicalBytes": pages * page_size, "pageCount": pages, "pageSize": page_size,
            "payloadRows": PAYLOAD_ROWS, "payloadBytesEach": PAYLOAD_BYTES,
            "minimumRequiredBytes": MINIMUM_PRIMARY_BYTES, "maximumAllowedBytes": MAXIMUM_PRIMARY_BYTES}


'''
source = source.replace("def run_capacity_qualification(", prefix + "def run_capacity_qualification(")
needle = '            keeper = store.connect(path, readonly=True, role="old-readonly-keeper")\n'
assert source.count(needle) == 1
source = source.replace(needle, '''            if ordinal == 0:
                report["capacity"] = fill_capacity_database(store, row)
'''+needle)
needle = '        check("six_actual_nonempty_wal_namespaces",'
assert source.count(needle) == 1
source = source.replace(needle, '''        check("primary_logical_size_at_least_current_measured_database", report["capacity"]["logicalBytes"] >= MINIMUM_PRIMARY_BYTES)
'''+needle)
needle = '        check("primary_logical_size_at_least_current_measured_database", report["capacity"]["logicalBytes"] >= MINIMUM_PRIMARY_BYTES)\n'
assert source.count(needle) == 1
source = source.replace(needle, '''        # Measure the final source generation after the synthetic fresh-token
        # writes, which can allocate pages beyond the initial payload fill.
        final_pages = store.query(rows[0], "PRAGMA page_count", limit=1)[0][0]
        final_page_size = store.query(rows[0], "PRAGMA page_size", limit=1)[0][0]
        need(type(final_pages) is type(final_page_size) is int and final_page_size == 4096
             and MINIMUM_PRIMARY_BYTES <= final_pages * final_page_size <= MAXIMUM_PRIMARY_BYTES,
             "final_synthetic_primary_capacity_before_baseline")
        report["capacity"]["allocationLogicalBytes"] = report["capacity"]["logicalBytes"]
        report["capacity"].update(logicalBytes=final_pages * final_page_size, pageCount=final_pages)
'''+needle)
needle = '        check("six_keepers_remain_old",'
assert source.count(needle) == 1
source = source.replace(needle, '''        check("both_primary_baseline_archives_cover_actual_size", baseline[0]["archiveBytes"] == report["capacity"]["logicalBytes"])
'''+needle)
needle = '            candidates.append(store.capture(path, store.namespace(path), slot=ordinal, phase="candidate"))\n'
assert source.count(needle) == 1
source = source.replace(needle, '''            if ordinal == 0:
                store.query(row, "UPDATE capacity_payload SET payload=zeroblob(?) WHERE id=?", (PAYLOAD_BYTES, PAYLOAD_ROWS))
'''+needle)
needle = '                    need(len(profiles) == 3 and all(value["access"].startswith("fresh-committed-") for value in profiles.values()),\n                         "restore_does_not_rewind_fresh_provider_epoch")\n'
assert source.count(needle) == 1
source = source.replace(needle, needle+'''                    need(store.query(read, "SELECT count(*) FROM capacity_payload", limit=1) == [(PAYLOAD_ROWS,)],
                         "restored_all_large_payload_rows")
                    for payload_ordinal in range(1, PAYLOAD_ROWS + 1):
                        store.remaining()
                        actual = store.query(read, "SELECT payload FROM capacity_payload WHERE id=?", (payload_ordinal,), limit=1)
                        need(len(actual) == 1 and len(actual[0]) == 1 and type(actual[0][0]) is bytes
                             and actual[0][0] == capacity_payload(payload_ordinal),
                             "every_restored_large_payload_exact_synthetic_source")
                    report["capacity"]["allRestoredPayloadRowsComparedToOriginalSyntheticInput"] = True
''')
needle = '        check("three_synthetic_fresh_credentials_not_rewound", True)\n'
assert source.count(needle) == 1
source = source.replace(needle, needle+'''        check("every_large_payload_byte_matches_original_synthetic_input", report["capacity"]["allRestoredPayloadRowsComparedToOriginalSyntheticInput"])
''')
ast.parse(source)
assert '.serialize(' not in source and source.count('MINIMUM_PRIMARY_BYTES = 2469126144') == 1
out = HERE / "qualify_whole_sqlite_capacity_r1.py"
out.write_text(source)
diff = "".join(difflib.unified_diff((PRIOR / "qualify_whole_sqlite_streaming_r1.py").read_text().splitlines(True),
    source.splitlines(True), fromfile="qualified-small/qualify_whole_sqlite_streaming_r1.py",
    tofile="capacity/qualify_whole_sqlite_capacity_r1.py"))
(HERE / "small-to-capacity-qualification.diff").write_text(diff)
print({"bytes":len(source.encode()), "sha256":hashlib.sha256(source.encode()).hexdigest(),
       "sameCoreSha256":hashlib.sha256(raw).hexdigest()})
