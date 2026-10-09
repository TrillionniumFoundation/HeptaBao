"""Strict OpenBao 2.7 KV2 raw projection, established from compiled black-box records."""
import datetime
import decimal
import hashlib
import json
import re

MAX_RECORD = 1024 * 1024
MAX_RECORDS = 10000
MAX_FIELDS = 20000
MAX_TOTAL = 64 * 1024 * 1024

class DecodeError(ValueError):
    pass

def need(ok, label):
    if not ok:
        raise DecodeError(label)

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

def message(raw, allowed, repeated=()):
    need(isinstance(raw, bytes) and len(raw) <= MAX_RECORD, "record bound")
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

def timestamp(raw):
    parts = message(raw, {1: 0, 2: 0})
    seconds, nanos = parts.get(1, 0), parts.get(2, 0)
    need(seconds <= 253402300799 and 0 <= nanos < 1000000000, "timestamp range")
    value = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    fraction = ("." + str(nanos).zfill(9).rstrip("0")) if nanos else ""
    return value.strftime("%Y-%m-%dT%H:%M:%S") + fraction + "Z"

def duration(raw):
    parts = message(raw, {1: 0, 2: 0})
    seconds, nanos = parts.get(1, 0), parts.get(2, 0)
    need(seconds * 1000000000 + nanos <= 315360000 * 1000000000
         and 0 <= nanos < 1000000000, "duration exceeds current native import bound")
    fraction = ("." + str(nanos).zfill(9).rstrip("0")) if nanos else ""
    return str(seconds) + fraction + "s"

def config(raw):
    fields = message(raw, {1: 0, 2: 0, 3: 2, 400: 0})
    return {"max_versions": fields.get(1, 0),
            "cas_required": boolean(fields.get(2, 0)),
            "metadata_cas_required": boolean(fields.get(400, 0)),
            "delete_version_after": duration(fields.get(3, b""))}

def pairs(values):
    out = {}
    for raw in values:
        entry = message(raw, {1: 2, 2: 2})
        key = utf8(entry.get(1, b""))
        need(key not in out, "duplicate protobuf map key")
        out[key] = utf8(entry.get(2, b""))
    return out

def key_metadata(raw):
    fields = message(raw, {1: 2, 2: 2, 3: 0, 4: 0, 5: 2, 6: 2,
                           7: 0, 8: 0, 9: 2, 10: 2, 400: 0, 401: 0}, (2, 10))
    name = utf8(fields.get(1, b""))
    need(name and len(name.encode()) <= 1024 and not name.startswith("/")
         and all(x not in ("", ".", "..") for x in name.split("/"))
         and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\\%?#"
                     for c in name), "logical key exceeds current native canonical bound")
    versions = {}
    for raw_map in fields.get(2, []):
        item = message(raw_map, {1: 0, 2: 2})
        index = item.get(1, 0)
        need(index > 0 and str(index) not in versions, "duplicate or zero version")
        vm = message(item.get(2, b""), {1: 2, 2: 2, 3: 0})
        need(1 in vm, "version creation timestamp missing")
        versions[str(index)] = {"created_time": timestamp(vm[1]),
                               "deletion_time": timestamp(vm[2]) if 2 in vm else "",
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
    metadata = {"created_time": timestamp(fields[5]) if 5 in fields else "",
                "updated_time": timestamp(fields[6]) if 6 in fields else "",
                "current_version": current, "oldest_version": floor,
                "current_metadata_version": fields.get(401, 0),
                "max_versions": fields.get(7, 0),
                "cas_required": boolean(fields.get(8, 0)),
                "metadata_cas_required": boolean(fields.get(400, 0)),
                "delete_version_after": duration(fields.get(9, b"")),
                "custom_metadata": pairs(fields[10]) if 10 in fields else None,
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

def lossless_json(raw):
    def invalid_constant(_):
        raise DecodeError("invalid JSON constant")
    need(isinstance(raw, bytes) and len(raw) <= MAX_RECORD, "JSON UTF8 byte bound")
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

def decode_records(records):
    need(isinstance(records, list) and 0 < len(records) <= MAX_RECORDS, "record count")
    by_path = {}
    total = 0
    for path, raw in records:
        need(isinstance(path, str) and isinstance(raw, bytes) and path not in by_path,
             "duplicate or invalid raw record")
        need(len(raw) <= MAX_RECORD, "record bound")
        total += len(raw)
        need(total <= MAX_TOTAL, "aggregate record bound")
        by_path[path] = raw
    roots = [p[:-6] for p in by_path if p.endswith("/config")]
    need(len(roots) == 1, "unique mount config required")
    root = roots[0]
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
            name, meta = key_metadata(raw)
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
            fields = message(version_records[path], {1: 2, 2: 2, 3: 2})
            vm["source_deletion_time"] = timestamp(fields[3]) if 3 in fields else ""
            need(1 in fields and 2 in fields, "version payload fields missing")
            need(timestamp(fields[2]) == vm["created_time"], "version creation mismatch")
            data = lossless_json(fields[1])
            need(isinstance(data, dict), "version data must be object")
            vm["data"] = data
            consumed.add(path)
    need(consumed == set(version_records), "orphan raw version payload")
    return {"schema": "openbao270-kv2-lossless-v1",
            "config": config(by_path[root + "config"]), "entries": entries}
