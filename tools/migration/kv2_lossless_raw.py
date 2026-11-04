"""Strict OpenBao 2.7 KV2 raw projection, established from compiled black-box records."""
import datetime
from dataclasses import dataclass
import decimal
import hashlib
import json
import re

MAX_RECORD = 1024 * 1024
MAX_RECORDS = 10000
MAX_FIELDS = 20000
MAX_TOTAL = 64 * 1024 * 1024
NATIVE_RAW_RECORDS = 100000
NATIVE_LOGICAL_PATHS = 50000
NATIVE_OWNER_RECORDS = 100000

class DecodeError(ValueError):
    pass

def need(ok, label):
    if not ok:
        raise DecodeError(label)

@dataclass(frozen=True)
class Bounds:
    """Immutable decoder policy; legacy callers retain their exact old limits."""
    record_bytes: int = MAX_RECORD
    total_bytes: int = MAX_TOTAL
    record_count: int = MAX_RECORDS

    def __post_init__(self):
        need(type(self.record_bytes) is int and type(self.total_bytes) is int
             and type(self.record_count) is int and 0 < self.record_count <= NATIVE_RAW_RECORDS
             and 0 < self.record_bytes <= 4 * 1024 * 1024
             and self.record_bytes <= self.total_bytes <= MAX_TOTAL,
             "invalid decoder bounds")


LEGACY_BOUNDS = Bounds()
NATIVE_LARGE_BOUNDS = Bounds(record_bytes=4 * 1024 * 1024, record_count=NATIVE_RAW_RECORDS)


def varint(raw, pos):
    value = 0
    start = pos
    for shift in range(0, 70, 7):
        need(pos < len(raw), "truncated varint")
        byte = raw[pos]
        pos += 1
        need(shift != 63 or byte <= 1, "varint overflow")
        value |= (byte & 127) << shift
        if byte < 128:
            need(pos == start + 1 or byte != 0, "noncanonical varint")
            return value, pos
    raise DecodeError("varint overflow")

def message(raw, allowed, repeated=(), *, bounds=LEGACY_BOUNDS):
    need(isinstance(raw, bytes) and len(raw) <= bounds.record_bytes, "record bound")
    out = {}
    pos = count = 0
    while pos < len(raw):
        tag, pos = varint(raw, pos)
        field, wire = tag >> 3, tag & 7
        need(field in allowed and wire == allowed[field], "unknown protobuf field or wire")
        if wire == 0:
            value, pos = varint(raw, pos)
        else:
            size, pos = varint(raw, pos)
            need(size <= len(raw) - pos, "truncated protobuf bytes")
            value = raw[pos:pos + size]
            pos += size
        count += 1
        need(count <= MAX_FIELDS, "protobuf field bound")
        if field in repeated:
            out.setdefault(field, []).append(value)
        else:
            need(field not in out, "duplicate protobuf scalar")
            out[field] = value
    return out

def utf8(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("invalid UTF8") from exc

def boolean(value):
    need(value in (0, 1), "invalid protobuf bool")
    return value == 1

def timestamp(raw, *, bounds=LEGACY_BOUNDS):
    parts = message(raw, {1: 0, 2: 0}, bounds=bounds)
    seconds, nanos = parts.get(1, 0), parts.get(2, 0)
    need(seconds <= 253402300799 and 0 <= nanos < 1000000000, "timestamp range")
    value = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    fraction = ("." + str(nanos).zfill(9).rstrip("0")) if nanos else ""
    return value.strftime("%Y-%m-%dT%H:%M:%S") + fraction + "Z"

def duration(raw, *, bounds=LEGACY_BOUNDS):
    parts = message(raw, {1: 0, 2: 0}, bounds=bounds)
    seconds, nanos = parts.get(1, 0), parts.get(2, 0)
    need(seconds * 1000000000 + nanos <= 315360000 * 1000000000
         and 0 <= nanos < 1000000000, "duration exceeds current native import bound")
    fraction = ("." + str(nanos).zfill(9).rstrip("0")) if nanos else ""
    return str(seconds) + fraction + "s"

def config(raw, *, bounds=LEGACY_BOUNDS):
    fields = message(raw, {1: 0, 2: 0, 3: 2, 400: 0}, bounds=bounds)
    return {"max_versions": fields.get(1, 0),
            "cas_required": boolean(fields.get(2, 0)),
            "metadata_cas_required": boolean(fields.get(400, 0)),
            "delete_version_after": duration(fields.get(3, b""), bounds=bounds)}

def pairs(values, *, bounds=LEGACY_BOUNDS):
    out = {}
    for raw in values:
        entry = message(raw, {1: 2, 2: 2}, bounds=bounds)
        key = utf8(entry.get(1, b""))
        need(key not in out, "duplicate protobuf map key")
        out[key] = utf8(entry.get(2, b""))
    return out

def key_metadata(raw, *, bounds=LEGACY_BOUNDS):
    fields = message(raw, {1: 2, 2: 2, 3: 0, 4: 0, 5: 2, 6: 2,
                           7: 0, 8: 0, 9: 2, 10: 2, 400: 0, 401: 0}, (2, 10), bounds=bounds)
    name = utf8(fields.get(1, b""))
    need(name and len(name.encode()) <= 1024 and not name.startswith("/")
         and all(x not in ("", ".", "..") for x in name.split("/"))
         and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\\%?#"
                     for c in name), "logical key exceeds current native canonical bound")
    versions = {}
    for raw_map in fields.get(2, []):
        item = message(raw_map, {1: 0, 2: 2}, bounds=bounds)
        index = item.get(1, 0)
        need(index > 0 and str(index) not in versions, "duplicate or zero version")
        vm = message(item.get(2, b""), {1: 2, 2: 2, 3: 0}, bounds=bounds)
        need(1 in vm, "version creation timestamp missing")
        versions[str(index)] = {"created_time": timestamp(vm[1], bounds=bounds),
                               "deletion_time": timestamp(vm[2], bounds=bounds) if 2 in vm else "",
                               "destroyed": boolean(vm.get(3, 0)),
                               "source_deletion_time": "",
                               "data": None}
    current, floor = fields.get(3, 0), fields.get(4, 0)
    need(floor <= current and all(floor <= int(v) <= current for v in versions),
         "version range")
    expected = 0 if current == 0 else current - max(floor, 1) + 1
    need(current <= (1 << 63) - 1 and len(versions) == expected
         and (current != 0 or floor == 0), "incomplete current native retained history")
    need(current == 0 or str(current) in versions, "current version record missing")
    metadata = {"created_time": timestamp(fields[5], bounds=bounds) if 5 in fields else "",
                "updated_time": timestamp(fields[6], bounds=bounds) if 6 in fields else "",
                "current_version": current, "oldest_version": floor,
                "current_metadata_version": fields.get(401, 0),
                "max_versions": fields.get(7, 0),
                "cas_required": boolean(fields.get(8, 0)),
                "metadata_cas_required": boolean(fields.get(400, 0)),
                "delete_version_after": duration(fields.get(9, b""), bounds=bounds),
                "custom_metadata": pairs(fields[10], bounds=bounds) if 10 in fields else None,
                "versions": versions}
    return name, metadata

def unicode_scalar(value):
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DecodeError("unpaired JSON Unicode surrogate") from exc

def unique_object(items):
    out = {}
    for key, value in items:
        unicode_scalar(key)
        need(key not in out, "duplicate JSON key")
        out[key] = value
    return out

def lossless_json(raw, *, bounds=LEGACY_BOUNDS):
    def invalid_constant(_):
        raise DecodeError("invalid JSON constant")
    need(isinstance(raw, bytes) and len(raw) <= bounds.record_bytes, "JSON UTF8 byte bound")
    try:
        value = json.loads(utf8(raw), object_pairs_hook=unique_object,
                           parse_int=decimal.Decimal, parse_float=decimal.Decimal,
                           parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("invalid bounded lossless JSON") from exc
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        need(count <= 100000 and depth <= 128, "JSON structural bound")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            unicode_scalar(item)
    return value

def dumps_lossless(value):
    if isinstance(value, decimal.Decimal):
        need(value.is_finite(), "nonfinite JSON number")
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(dumps_lossless(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + dumps_lossless(v)
                              for k, v in value.items()) + "}"
    raise DecodeError("unexpected JSON value type")


SNAPSHOT_SOURCE_SCHEMA = "heptabao.openbao270-complete-snapshot-source.v1"
SNAPSHOT_SOURCE_COMMIT = "ca305a02daa68b203325daa1b25c18d7a252d4b3"
SNAPSHOT_SOURCE_BINARY_SHA256 = "9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e"
SNAPSHOT_CONFIG_SOURCE_SHA256 = "d771bfdae489d5fe78dc4299c223a11efe903d17fd5d864f607bf1e1060be9bd"


@dataclass(frozen=True)
class _SnapshotSource:
    """An externally pinned witness; it is not a self-attesting Raft proof.

    The backup/recovery owner must first qualify complete cold raw equality and
    every metadata locator, then pin this witness outside the file being read.
    Immutable bytes are kept so callers cannot mutate a cached dictionary after
    admission. The decoder rechecks the full supplied raw set against it.
    """
    raw: bytes
    sha256: str


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _uuid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None


def _keys(value, fields):
    return isinstance(value, dict) and set(value) == set(fields.split())


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def snapshot_raw_manifest(records):
    """Canonical path/length/value-SHA witness; actual raw values stay private."""
    need(isinstance(records, list) and 0 < len(records) <= NATIVE_RAW_RECORDS, "snapshot raw count")
    need(all(isinstance(row, (list, tuple)) and len(row) == 2 and isinstance(row[0], str)
             and isinstance(row[1], bytes) for row in records), "snapshot raw row shape")
    digest = hashlib.sha256(b"HBKV2-SNAPSHOT-RAW1\n")
    total = paths = 0; previous = None
    for path, raw in sorted(records, key=lambda row: row[0]):
        need(isinstance(path, str) and isinstance(raw, bytes) and path != previous,
             "snapshot duplicate or invalid raw record")
        unicode_scalar(path); encoded = path.encode("utf-8")
        need(0 < len(encoded) <= 65536 and len(raw) <= NATIVE_LARGE_BOUNDS.record_bytes,
             "snapshot raw frame bound")
        total += len(raw); paths += len(encoded)
        need(total <= MAX_TOTAL and paths <= MAX_TOTAL, "snapshot raw aggregate bound")
        digest.update(len(encoded).to_bytes(8, "big")); digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big")); digest.update(hashlib.sha256(raw).digest())
        previous = path
    return {"records": len(records), "raw_bytes": total, "path_bytes": paths, "sha256": digest.hexdigest()}


def _snapshot_document(raw, expected_sha256):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 131072 and _digest(expected_sha256)
         and hashlib.sha256(raw).hexdigest() == expected_sha256, "snapshot witness external pin")
    try:
        value = json.loads(utf8(raw), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(DecodeError("snapshot witness constant")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DecodeError("invalid snapshot witness JSON") from error
    need(_keys(value, "schema source mount snapshot spool inventory configuration evidence")
         and value["schema"] == SNAPSHOT_SOURCE_SCHEMA, "snapshot witness schema")
    source, mount, snapshot, spool, inventory, configuration, evidence = (
        value[key] for key in ("source", "mount", "snapshot", "spool", "inventory", "configuration", "evidence"))
    need(source == {"version": "2.7.0", "git_commit": SNAPSHOT_SOURCE_COMMIT,
                    "binary_sha256": SNAPSHOT_SOURCE_BINARY_SHA256}, "unsupported snapshot source build")
    need(_keys(mount, "path namespace uuid backend_uuid") and mount["namespace"] == ""
         and _uuid(mount["uuid"]) and _uuid(mount["backend_uuid"]), "snapshot mount identity")
    name = mount["path"]
    need(isinstance(name, str), "snapshot canonical mount")
    unicode_scalar(name)
    need(isinstance(name, str) and name.endswith("/") and not name.startswith("/")
         and len(name.encode("utf-8")) <= 1024
         and all(p not in ("", ".", "..") for p in name[:-1].split("/"))
         and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\\%?#" for c in name),
         "snapshot canonical mount")
    need(_keys(snapshot, "sha256 state_sha256 index term") and _digest(snapshot["sha256"])
         and _digest(snapshot["state_sha256"]) and _integer(snapshot["index"], 1, (1 << 63) - 1)
         and _integer(snapshot["term"], 1, (1 << 63) - 1), "snapshot frontier")
    need(_keys(spool, "sha256 bytes records raw_bytes path_bytes roots") and _digest(spool["sha256"])
         and _integer(spool["records"], 1, NATIVE_RAW_RECORDS)
         and _integer(spool["raw_bytes"], 0, MAX_TOTAL) and _integer(spool["path_bytes"], 1, MAX_TOTAL)
         and _integer(spool["bytes"], 17, 2 * MAX_TOTAL + 16 * NATIVE_RAW_RECORDS)
         and spool["bytes"] == spool["raw_bytes"] + spool["path_bytes"] + 16 * spool["records"]
         and isinstance(spool["roots"], list) and 1 <= len(spool["roots"]) <= 128
         and all(isinstance(p, str) and len(p.split("/")) == 4
                 and p.split("/")[0] == "logical" and p.split("/")[3] == ""
                 and _uuid(p.split("/")[1]) and _uuid(p.split("/")[2]) for p in spool["roots"])
         and spool["roots"] == sorted(set(spool["roots"])), "snapshot complete spool identity")
    root = "logical/" + mount["uuid"] + "/" + mount["backend_uuid"] + "/"
    need(root in spool["roots"], "snapshot mount absent from spool")
    need(_keys(inventory, "records raw_bytes path_bytes sha256 logical_paths retained_versions payload_versions")
         and _integer(inventory["records"], 1, spool["records"])
         and _integer(inventory["raw_bytes"], 0, spool["raw_bytes"])
         and _integer(inventory["path_bytes"], 1, spool["path_bytes"])
         and _digest(inventory["sha256"]) and _integer(inventory["logical_paths"], 0, NATIVE_LOGICAL_PATHS)
         and _integer(inventory["retained_versions"], 0, NATIVE_OWNER_RECORDS)
         and _integer(inventory["payload_versions"], 0, inventory["retained_versions"])
         and 1 + inventory["logical_paths"] + inventory["retained_versions"] <= NATIVE_OWNER_RECORDS,
         "snapshot native inventory bounds")
    need(_keys(configuration, "origin raw_sha256 source_code_sha256")
         and configuration["source_code_sha256"] == SNAPSHOT_CONFIG_SOURCE_SHA256
         and ((configuration["origin"] == "actual_raw_protobuf" and _digest(configuration["raw_sha256"]))
              or (configuration["origin"] == "exact_270_absent_record_default"
                  and configuration["raw_sha256"] is None)), "snapshot config provenance")
    need(_keys(evidence, "capture restore tree values locator oracle predicate")
         and all(_digest(evidence[key]) for key in ("capture", "restore", "tree", "values", "locator", "oracle"))
         and evidence["predicate"] == "two_cold_raw_equal_and_every_metadata_current_get_locator_exact",
         "snapshot completeness evidence pins")
    return value


def admit_snapshot_source(raw, expected_sha256):
    """Expected SHA must come from the already-qualified backup owner, not this file."""
    _snapshot_document(raw, expected_sha256)
    return _SnapshotSource(raw, expected_sha256)


def snapshot_provenance(source, bundle_bytes):
    need(isinstance(source, _SnapshotSource) and isinstance(bundle_bytes, bytes)
         and len(bundle_bytes) <= MAX_TOTAL, "snapshot provenance inputs")
    value = _snapshot_document(source.raw, source.sha256)
    return {"schema": "heptabao.openbao270-snapshot-bundle-provenance.v1",
            "source_witness_sha256": source.sha256, "source": value["source"],
            "mount": value["mount"], "snapshot": value["snapshot"], "inventory": value["inventory"],
            "configuration": value["configuration"], "evidence": value["evidence"],
            "bundle_bytes": len(bundle_bytes), "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "successful_export_receipt_required": True,
            "source_config_record_synthesized": False, "source_modified": False,
            "snapshot_sealed_checksum_cryptographically_verified": False,
            "unrelated_auxiliary_lifecycle_qualified": False,
            "live_source_current_frontier_qualified": False, "target_import_qualified": False,
            "formal_live_export_5_360_qualified": False}


def decode_records(records, *, bounds=LEGACY_BOUNDS, source=None):
    need(isinstance(bounds, Bounds) and isinstance(records, list)
         and 0 < len(records) <= bounds.record_count, "record count")
    source_document = None
    if source is not None:
        need(isinstance(source, _SnapshotSource) and bounds == NATIVE_LARGE_BOUNDS,
             "snapshot source requires explicit native-large profile")
        source_document = _snapshot_document(source.raw, source.sha256)
        observed = snapshot_raw_manifest(records)
        need(all(source_document["inventory"][key] == observed[key]
                 for key in ("records", "raw_bytes", "path_bytes", "sha256")),
             "snapshot supplied raw set differs from complete witness")
    by_path = {}
    total = 0
    for path, raw in records:
        need(isinstance(path, str) and isinstance(raw, bytes) and path not in by_path,
             "duplicate or invalid raw record")
        need(len(raw) <= bounds.record_bytes, "record bound")
        total += len(raw)
        need(total <= bounds.total_bytes, "aggregate record bound")
        by_path[path] = raw
    if source_document is None:
        roots = [p[:-6] for p in by_path if p.endswith("/config")]
        need(len(roots) == 1, "unique mount config required")
        root = roots[0]
    else:
        mount = source_document["mount"]
        root = "logical/" + mount["uuid"] + "/" + mount["backend_uuid"] + "/"
        configuration = source_document["configuration"]
        if root + "config" in by_path:
            need(configuration["origin"] == "actual_raw_protobuf"
                 and hashlib.sha256(by_path[root + "config"]).hexdigest() == configuration["raw_sha256"],
                 "snapshot physical config differs from witness")
        else:
            need(configuration["origin"] == "exact_270_absent_record_default"
                 and configuration["raw_sha256"] is None, "snapshot config absence not witnessed")
    need(root.endswith("/") and all(p.startswith(root) for p in by_path), "mount boundary")
    salt = by_path.get(root + "salt")
    need(isinstance(salt, bytes) and 0 < len(salt) <= 1024, "actual raw salt required")
    auxiliary = {"config", "salt", "upgrading", "archive/metadata", "policy/metadata"}
    version_records = {}
    entries = {}
    for path, raw in by_path.items():
        relative = path[len(root):]
        if relative in auxiliary:
            continue
        if relative.startswith("versions/"):
            need(re.fullmatch(r"versions/[0-9a-f]{3}/[0-9a-f]{61}", relative) is not None,
                 "version storage locator shape")
            version_records[path] = raw
        elif relative.startswith("metadata/"):
            name, meta = key_metadata(raw, bounds=bounds)
            need(name not in entries, "duplicate logical metadata")
            entries[name] = meta
        else:
            raise DecodeError("unrecognized raw KV record")
    consumed = set()
    for name, meta in entries.items():
        for index, vm in meta["versions"].items():
            digest = hashlib.sha256(salt + (name + "|" + index).encode()).hexdigest()
            path = root + "versions/" + digest[:3] + "/" + digest[3:]
            if vm["destroyed"]:
                need(path not in version_records, "destroyed version retains payload")
                continue
            need(path in version_records and path not in consumed, "version payload missing or aliased")
            fields = message(version_records[path], {1: 2, 2: 2, 3: 2}, bounds=bounds)
            vm["source_deletion_time"] = timestamp(fields[3], bounds=bounds) if 3 in fields else ""
            need(1 in fields and 2 in fields, "version payload fields missing")
            need(timestamp(fields[2], bounds=bounds) == vm["created_time"], "version creation mismatch")
            data = lossless_json(fields[1], bounds=bounds)
            need(isinstance(data, dict), "version data must be object")
            vm["data"] = data
            consumed.add(path)
    need(consumed == set(version_records), "orphan raw version payload")
    retained_versions = sum(len(meta["versions"]) for meta in entries.values())
    if bounds == NATIVE_LARGE_BOUNDS:
        need(len(entries) <= NATIVE_LOGICAL_PATHS
             and 1 + len(entries) + retained_versions <= NATIVE_OWNER_RECORDS,
             "native-large joint path and retained record bound")
    if source_document is not None:
        inventory = source_document["inventory"]
        need(len(entries) == inventory["logical_paths"] and len(version_records) == inventory["payload_versions"]
             and retained_versions == inventory["retained_versions"],
             "snapshot logical or retained history coverage differs")
    return {"schema": "openbao270-kv2-lossless-v1",
            "config": config(by_path[root + "config"] if root + "config" in by_path else b"", bounds=bounds),
            "entries": entries}

