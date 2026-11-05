# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Private bounded native searches; no shell, executable or arbitrary target input."""
import contextlib
import fcntl
import io
import json
import os
import re
import resource
import signal
import stat
import sys
import time
import unicodedata
import zipfile
import xml.etree.ElementTree as ET

TERMINAL = {"completed", "limited", "cancelled", "failed", "interrupted"}
CAPS = {"entries": 10000, "results": 1000, "bytes": 64 * 1024 * 1024,
        "seconds": 30, "depth": 64, "file_bytes": 4 * 1024 * 1024,
        "result_bytes": 2 * 1024 * 1024, "jobs": 1024, "active": 8}
DOCUMENT_EXPANSION = 16 * 1024 * 1024
DOCUMENT_TEXT = 4 * 1024 * 1024
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
COVERAGE_SCOPE = "selected_authorized_regular_single_link_files"


class DocumentLimit(ValueError):
    pass


def coverage_statistics(stats, state="running", reason=None):
    reasons = [label for key, label in (
        ("skipped_large", "file_size_limit"),
        ("skipped_document_unavailable", "document_parser_unavailable"),
        ("skipped_document_limited", "document_budget_limit"),
        ("skipped_document_invalid", "document_decode_failed"),
        ("skipped_binary_or_non_utf8", "unsupported_binary_or_non_utf8"),
        ("unreadable", "unreadable_or_changed")) if stats.get(key, 0)]
    traversal_complete = state == "completed" and reason is None
    if not traversal_complete:
        reasons.append(reason or ("search_in_progress" if state == "running" else "scan_incomplete"))
    stats.update(coverage_complete=traversal_complete and not reasons,
                 coverage_reasons=sorted(set(reasons)), traversal_complete=traversal_complete,
                 coverage_scope=COVERAGE_SCOPE)


class StopSearch(Exception):
    def __init__(self, state, reason):
        self.state, self.reason = state, reason


def absolute(path):
    if not isinstance(path, str) or not path.startswith("/") or len(path.encode()) > 4096:
        raise ValueError("absolute path of at most 4096 bytes required")
    if any(x in path for x in ("\x00", "\n", "\r")) or any(x in (".", "..") for x in path.split("/")):
        raise ValueError("unsafe path component")
    return path.rstrip("/") or "/"


def private(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("search state must be owned private mode 0700")


def open_dir(path, create=False):
    path = absolute(path)
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        for name in path.split("/"):
            if not name:
                continue
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            next_fd = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_json(fd, name, value):
    temporary = "." + name + "." + os.urandom(8).hex()
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    try:
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        with os.fdopen(output, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=fd)


def read_json(fd, name):
    file_fd = os.open(name, FLAGS, dir_fd=fd)
    with os.fdopen(file_fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("ordinary search state file required")
        data = handle.read(16385)
        if len(data) > 16384:
            raise ValueError("oversize search state")
        return json.loads(data)


def job_id(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid search identity")
    return value


def authorized_root(request):
    root = absolute(request["root"])
    roots = [absolute(p) for p in request["allowed_roots"]]
    if not any(root == p or p == "/" or root.startswith(p + "/") for p in roots):
        raise ValueError("search root not authorized")
    return root


def protected_path(target, prefixes):
    # macOS volumes may alias names by case and canonical Unicode normalization.
    # Conservatively deny such aliases even when a particular volume is case-sensitive.
    if sys.platform == "darwin":
        target = unicodedata.normalize("NFD", target).casefold()
        prefixes = [unicodedata.normalize("NFD", prefix).casefold() for prefix in prefixes]
    return any(target == prefix or prefix == "/" or target.startswith(prefix + "/") for prefix in prefixes)


def reconcile(fd, record):
    # Never reattach or signal a PID whose identity cannot be proved after restart.
    if record["state"] not in TERMINAL and time.time() > record["deadline"] + 5:
        record.update(state="interrupted", reason="worker_deadline_without_terminal_receipt", snapshot_ready=False)
        coverage_statistics(record.setdefault("statistics", {}), record["state"], record["reason"])
        write_json(fd, "record.json", record)
    return record


def snapshot(fd, record, cursor, limit):
    if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0 or cursor > CAPS["results"]:
        raise ValueError("invalid search cursor")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 32:
        raise ValueError("search page limit must be 1..32")
    response = {"state": record["state"], "reason": record.get("reason"),
                "snapshot_ready": record.get("snapshot_ready", False),
                "statistics": record.get("statistics", {}), "results": [], "next_cursor": None}
    count = record.get("committed_results", record.get("statistics", {}).get("results", 0)
                       if response["snapshot_ready"] else 0)
    committed_bytes = record.get("committed_result_bytes", record.get("result_bytes", 0))
    if (not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= CAPS["results"]
            or not isinstance(committed_bytes, int) or isinstance(committed_bytes, bool)
            or not 0 <= committed_bytes <= CAPS["result_bytes"] or bool(count) != bool(committed_bytes)):
        raise ValueError("invalid committed search prefix")
    response.update(committed_results=count, committed_result_bytes=committed_bytes,
                    progressive=record["state"] not in TERMINAL)
    if cursor > count:
        raise ValueError("cursor exceeds committed search prefix")
    if not count:
        if record["state"] not in TERMINAL:
            response["next_cursor"] = cursor
        return response
    result_fd = os.open("results.ndjson", FLAGS, dir_fd=fd)
    page_bytes = 0
    with os.fdopen(result_fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > CAPS["result_bytes"]
                or info.st_size < committed_bytes or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("invalid committed snapshot")
        remaining = committed_bytes
        for index in range(count):
            line = handle.readline(min(8193, remaining + 1))
            if not line.endswith(b"\n") or len(line) > 8192 or len(line) > remaining:
                raise ValueError("invalid snapshot row size")
            remaining -= len(line)
            if cursor <= index < cursor + limit:
                if page_bytes + len(line) > 65536:
                    break
                response["results"].append(json.loads(line))
                page_bytes += len(line)
            if index + 1 >= cursor + limit:
                break
    next_cursor = cursor + len(response["results"])
    if next_cursor < count or record["state"] not in TERMINAL:
        response["next_cursor"] = next_cursor
    return response


def options(request):
    mode = request.get("query_mode")
    literal = request.get("literal_search")
    if mode not in (None, "literal", "regex", "glob") or (literal is not None and not isinstance(literal, bool)):
        raise ValueError("invalid query mode")
    if literal is not None and mode is not None and mode != ("literal" if literal else "regex"):
        raise ValueError("conflicting query modes")
    mode = mode or ("regex" if literal is False else "literal")
    if mode == "glob" and request["kind"] != "files":
        raise ValueError("glob mode requires file search")
    context = request.get("context_lines", 0)
    if not isinstance(context, int) or isinstance(context, bool) or not 0 <= context <= 10:
        raise ValueError("context_lines must be 0..10")
    for key in ("ignore_case", "early_termination", "include_hidden"):
        if not isinstance(request.get(key, False), bool):
            raise ValueError("boolean search option required")
    excludes = request.get("exclude_patterns", [])
    file_pattern = request.get("file_pattern")
    if not isinstance(excludes, list) or len(excludes) > 32:
        raise ValueError("invalid exclusions")
    patterns = [] if file_pattern is None else [part.strip() for part in file_pattern.split("|") if part.strip()] if isinstance(file_pattern, str) else [None]
    if len(patterns) > 16 or (isinstance(file_pattern, str) and len(file_pattern.encode()) > 512):
        raise ValueError("invalid file glob filter")
    for pattern in patterns + excludes:
        if (not isinstance(pattern, str) or not 1 <= len(pattern.encode()) <= 512
                or any(x in pattern for x in ("\0", "\n", "\r"))):
            raise ValueError("invalid file glob filter")
    query = request["query"]
    if not isinstance(query, str) or not 1 <= len(query.encode()) <= 512 or any(x in query for x in ("\0", "\n", "\r")):
        raise ValueError("invalid query")
    insensitive = request.get("ignore_case", False)
    fold = str.casefold if insensitive else lambda value: value
    program = request.get("glob_program")
    if program is None:
        if patterns or excludes or mode == "glob":
            raise ValueError("controller-compiled glob program required")
        program = {"version": 1, "file_rules": [], "exclude_rules": [], "query_rules": None}
    if (not isinstance(program, dict) or set(program) != {"version", "file_rules", "exclude_rules", "query_rules"}
            or program["version"] != 1 or isinstance(program["version"], bool)
            or len(json.dumps(program)) > 128 * 1024):
        raise ValueError("invalid compiled glob program")
    def rules(values, cap):
        if not isinstance(values, list) or len(values) > cap:
            raise ValueError("invalid compiled glob rule count")
        compiled = []
        for value in values:
            if (not isinstance(value, dict) or set(value) != {"regex", "include", "only_dir"}
                    or not isinstance(value["include"], bool) or not isinstance(value["only_dir"], bool)
                    or not isinstance(value["regex"], str) or not 1 <= len(value["regex"]) <= 16384
                    or not value["regex"].isascii()):
                raise ValueError("invalid compiled glob rule")
            compiled.append((re.compile(value["regex"].encode("ascii"), re.DOTALL), value["include"], value["only_dir"]))
        return compiled
    file_rules = rules(program["file_rules"], 16)
    exclude_rules = rules(program["exclude_rules"], 32)
    query_rules = rules(program["query_rules"], 1) if mode == "glob" else None
    if mode != "glob" and program["query_rules"] is not None:
        raise ValueError("unexpected compiled query glob")
    def selects(choices, value, is_dir=False, default_all=False):
        decision = is_dir or default_all or not any(include for _, include, _ in choices)
        encoded = value.encode("utf-8")
        for expression, include, only_dir in choices:
            if (not only_dir or is_dir) and expression.fullmatch(encoded) is not None:
                decision = include
        return decision
    if mode == "regex":
        expression = re.compile(query, re.IGNORECASE if insensitive else 0)
        matches = lambda value: expression.search(value) is not None
    elif mode == "glob":
        matches = lambda value: selects(query_rules, value)
    else:
        matches = lambda value: fold(query) in fold(value)
    def excluded(path, is_dir=False):
        return (not selects(exclude_rules, path, is_dir, True)
                or (is_dir and (not selects(file_rules, path, True)
                                or (query_rules is not None and not selects(query_rules, path, True)))))
    return matches, lambda path: selects(file_rules, path), excluded, mode


@contextlib.contextmanager
def bounded_pdf_parser():
    from pypdf import PdfReader, filters
    names = ("ZLIB_MAX_OUTPUT_LENGTH", "LZW_MAX_OUTPUT_LENGTH", "RUN_LENGTH_MAX_OUTPUT_LENGTH",
             "MAX_DECLARED_STREAM_LENGTH", "MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH")
    if not all(hasattr(filters, name) for name in names):
        raise ImportError("installed PDF parser lacks bounded stream support")
    previous = {name: getattr(filters, name) for name in names}
    decode = filters.decode_stream_data
    safe = {"/FlateDecode", "/Fl", "/LZWDecode", "/LZW", "/RunLengthDecode", "/RL",
            "/ASCIIHexDecode", "/AHx", "/ASCII85Decode", "/A85"}
    def bounded_decode(stream):
        codecs = stream.get("/Filter", ())
        if hasattr(codecs, "get_object"):
            codecs = codecs.get_object()
        if not isinstance(codecs, (list, tuple)):
            codecs = [codecs]
        if len(codecs) > 8 or any(str(codec) not in safe for codec in codecs):
            # Text streams never need image codecs, including decoders that
            # would launch an external helper or allocate an unbounded image.
            raise ValueError("unsupported PDF text stream codec")
        parameters = stream.get("/DecodeParms", ())
        if hasattr(parameters, "get_object"):
            parameters = parameters.get_object()
        if not isinstance(parameters, (list, tuple)):
            parameters = [parameters]
        for item in parameters:
            if hasattr(item, "get_object"):
                item = item.get_object()
            if not hasattr(item, "get"):
                continue
            dimensions = [item.get(key, default) for key, default in
                          (("/Columns", 1), ("/Colors", 1), ("/BitsPerComponent", 8))]
            dimensions = [value.get_object() if hasattr(value, "get_object") else value for value in dimensions]
            if (any(not isinstance(value, int) or not 1 <= value <= 32768 for value in dimensions)
                    or dimensions[0] * dimensions[1] * dimensions[2] > 32768):
                raise DocumentLimit("PDF predictor row exceeds budget")
        result = decode(stream)
        if len(result) > DOCUMENT_EXPANSION:
            raise DocumentLimit("PDF stream expansion exceeds budget")
        return result
    try:
        for name in names:
            setattr(filters, name, DOCUMENT_EXPANSION)
        filters.decode_stream_data = bounded_decode
        yield PdfReader
    finally:
        filters.decode_stream_data = decode
        for name, value in previous.items():
            setattr(filters, name, value)


def document_text(data, suffix, checkpoint):
    """Yield descriptor-bound embedded text only; never resolve relationships or external links."""
    used = 0
    def bounded(text):
        nonlocal used
        used += len(text.encode("utf-8"))
        if used > DOCUMENT_TEXT:
            raise DocumentLimit("document text budget exceeded")
        return text
    if suffix == ".pdf":
        with bounded_pdf_parser() as PdfReader:
            document = PdfReader(io.BytesIO(data), strict=True)
            if document.is_encrypted:
                raise ValueError("encrypted PDF")
            if len(document.pages) > 500:
                raise DocumentLimit("PDF page budget exceeded")
            for number, page in enumerate(document.pages, 1):
                checkpoint()
                contents = page.get_contents()
                if contents is not None and len(contents.get_data()) > DOCUMENT_EXPANSION:
                    raise DocumentLimit("PDF page expansion exceeds budget")
                yield {"format": "pdf", "page": number}, bounded(page.extract_text() or "")
        return
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        members = package.infolist()
        if (len(members) > 2048 or len({item.filename for item in members}) != len(members)
                or sum(item.file_size for item in members) > DOCUMENT_EXPANSION):
            raise DocumentLimit("OOXML expansion exceeds budget")
        for item in members:
            if (item.flag_bits & 1 or item.filename.startswith("/")
                    or ".." in item.filename.split("/") or "\\" in item.filename):
                raise ValueError("unsafe OOXML package")
        def xml(name):
            checkpoint()
            raw = package.read(name)
            declarations = raw.replace(b"\0", b"").lower()
            if b"<!doctype" in declarations or b"<!entity" in declarations:
                raise ValueError("XML declarations refused")
            root = ET.fromstring(raw)
            if sum(1 for _ in root.iter()) > 200000:
                raise DocumentLimit("XML element budget exceeded")
            return root
        if suffix == ".docx":
            names = [item.filename for item in members if re.fullmatch(r"word/(document|header\d+|footer\d+)\.xml", item.filename)]
            if "word/document.xml" not in names:
                raise ValueError("missing DOCX body")
            namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
            for name in sorted(names):
                for index, paragraph in enumerate(xml(name).iter(namespace + "p"), 1):
                    checkpoint()
                    text = "".join(node.text or "" if node.tag == namespace + "t" else "\t" if node.tag == namespace + "tab" else "\n" if node.tag in (namespace + "br", namespace + "cr") else "" for node in paragraph.iter())
                    yield {"format": "docx", "part": name, "paragraph": index}, bounded(text)
        else:
            namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
            shared = []
            if "xl/sharedStrings.xml" in package.namelist():
                for item in xml("xl/sharedStrings.xml").iter(namespace + "si"):
                    shared.append(bounded("".join(node.text or "" for node in item.iter(namespace + "t"))))
            for name in sorted(item.filename for item in members if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", item.filename)):
                for cell in xml(name).iter(namespace + "c"):
                    checkpoint()
                    kind = cell.get("t")
                    value = cell.find(namespace + "v")
                    text = value.text or "" if value is not None else ""
                    if kind == "s":
                        index = int(text)
                        if not 0 <= index < len(shared):
                            raise ValueError("invalid shared-string reference")
                        text = shared[index]
                    elif kind == "inlineStr":
                        text = "".join(node.text or "" for node in cell.iter(namespace + "t"))
                    formula = cell.find(namespace + "f")
                    if formula is not None:
                        text = "=" + (formula.text or "") + ("\n" + text if text else "")
                    address = cell.get("r", "")
                    if not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", address):
                        raise ValueError("invalid worksheet cell address")
                    yield {"format": "xlsx", "part": name, "cell": address}, bounded(text)


def search(fd, request, record):
    stats = {"entries": 0, "files": 0, "bytes": 0, "results": 0,
             "skipped_symlinks": 0, "skipped_special": 0, "skipped_large": 0,
             "skipped_binary_or_non_utf8": 0, "skipped_hardlinks": 0, "skipped_protected": 0, "unreadable": 0,
             "extracted_documents": 0, "skipped_document_unavailable": 0, "skipped_document_invalid": 0,
             "skipped_document_limited": 0}
    coverage_statistics(stats)
    budget = request["limits"]
    encoded = request["query"].encode("utf-8")
    if not encoded or len(encoded) > 512 or b"\n" in encoded or b"\r" in encoded or b"\0" in encoded:
        raise ValueError("query must contain 1..512 UTF-8 bytes and no NUL/newlines")
    for key, cap in (("entries", CAPS["entries"]), ("results", CAPS["results"]),
                     ("bytes", CAPS["bytes"]), ("seconds", CAPS["seconds"])):
        if not isinstance(budget[key], int) or isinstance(budget[key], bool) or not 1 <= budget[key] <= cap:
            raise ValueError("invalid resource budget")
    if request["kind"] not in ("files", "content"):
        raise ValueError("unknown search kind")
    matches, included, excluded, mode = options(request)
    root = authorized_root(request)
    protected = [absolute(path) for path in request.get("protected_roots", [])]
    root_fd = open_dir(root)
    result_fd = os.open("results.ndjson", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=fd)
    result_bytes = 0
    start = time.monotonic()

    def checkpoint():
        if time.monotonic() - start >= budget["seconds"]:
            raise StopSearch("limited", "time_limit")
        try:
            os.stat("cancel", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise StopSearch("cancelled", "owner_requested_stop")

    def alarm(_number, _frame):
        raise StopSearch("limited", "time_limit")

    def append(value):
        nonlocal result_bytes
        checkpoint()
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        while len(data) > 8192 and (value.get("context_before") or value.get("context_after")):
            # Keep the match even when unusual escaped filenames/context would
            # otherwise make a valid row exceed the transport's fixed cap.
            before, after = value.get("context_before", []), value.get("context_after", [])
            before.pop(0) if len(before) >= len(after) else after.pop()
            value["context_truncated"] = True
            data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(data) > 8192 and "preview" in value:
            value["preview"] = value["preview"].encode("utf-8")[:128].decode("utf-8", "ignore")
            value["preview_truncated"] = True
            data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(data) > 8192 or result_bytes + len(data) > CAPS["result_bytes"]:
            raise StopSearch("limited", "result_bytes_limit")
        output.write(data)
        result_bytes += len(data)
        stats["results"] += 1
        # Publish only after data is durable. Readers bound themselves to this
        # atomic receipt's prefix, so later appends cannot expose partial rows.
        output.flush()
        os.fsync(output.fileno())
        coverage_statistics(stats)
        record.update(snapshot_ready=False, statistics=stats.copy(),
                      committed_results=stats["results"], committed_result_bytes=result_bytes)
        write_json(fd, "record.json", record)
        if stats["results"] >= budget["results"]:
            raise StopSearch("limited", "result_limit")

    def scan_text(content, relative, location=None):
        context = request.get("context_lines", 0)
        # Retain a bounded window, not splitlines() for the whole file.
        from collections import deque
        previous = deque(maxlen=context)
        pending = deque()
        lines = enumerate(io.StringIO(content), 1)
        def clipped(line, size):
            raw = line.rstrip("\r\n").encode("utf-8")
            return raw[:size].decode("utf-8", "ignore"), len(raw) > size
        def line_value(number, line):
            text, truncated = clipped(line, 64)
            return {"line": number, "text": text, "truncated": truncated}
        for _ in range(context + 1):
            item = next(lines, None)
            if item is not None:
                pending.append(item)
        while pending:
            checkpoint()
            number, line = pending.popleft()
            if matches(line):
                preview, truncated = clipped(line, 512)
                value = {"path": relative, "line": number, "preview": preview,
                         "preview_truncated": truncated}
                if location is not None:
                    value["document"] = location
                if context:
                    value["context_before"] = list(previous)
                    value["context_after"] = [line_value(n, text) for n, text in pending]
                append(value)
            if context:
                previous.append(line_value(number, line))
            item = next(lines, None)
            if item is not None:
                pending.append(item)

    def read_content(directory_fd, name, relative):
        checkpoint()
        try:
            file_fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=directory_fd)
        except OSError:
            stats["unreadable"] += 1
            return
        with os.fdopen(file_fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                stats["skipped_special"] += 1
                return
            if info.st_nlink != 1:
                stats["skipped_hardlinks"] += 1
                return
            if info.st_size > CAPS["file_bytes"]:
                stats["skipped_large"] += 1
                return
            stats["files"] += 1
            remaining = min(CAPS["file_bytes"] + 1, budget["bytes"] - stats["bytes"])
            if remaining <= 0:
                raise StopSearch("limited", "read_bytes_limit")
            chunks = []
            while remaining > 0:
                checkpoint()
                piece = source.read(min(65536, remaining))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
                stats["bytes"] += len(piece)
            if stats["bytes"] >= budget["bytes"]:
                raise StopSearch("limited", "read_bytes_limit")
            data = b"".join(chunks)
            if len(data) > CAPS["file_bytes"]:
                stats["skipped_large"] += 1
                return
            after = os.fstat(source.fileno())
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                stats["unreadable"] += 1
                return
            suffix = os.path.splitext(name)[1].lower()
            if suffix in (".docx", ".xlsx", ".xlsm", ".pdf"):
                try:
                    for location, content in document_text(data, suffix, checkpoint):
                        scan_text(content, relative, location)
                    stats["extracted_documents"] += 1
                except StopSearch:
                    raise
                except ImportError:
                    stats["skipped_document_unavailable"] += 1
                except Exception as error:
                    if isinstance(error, DocumentLimit) or type(error).__name__ == "LimitReachedError":
                        stats["skipped_document_limited"] += 1
                    else:
                        stats["skipped_document_invalid"] += 1
                return
            try:
                if b"\0" in data:
                    raise UnicodeError()
                content = data.decode("utf-8")
            except UnicodeError:
                stats["skipped_binary_or_non_utf8"] += 1
                return
            scan_text(content, relative)

    def walk(directory_fd, relative, depth):
        checkpoint()
        if depth > CAPS["depth"]:
            raise StopSearch("limited", "depth_limit")
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                checkpoint()
                if stats["entries"] >= budget["entries"]:
                    raise StopSearch("limited", "entry_limit")
                stats["entries"] += 1
                name = entry.name
                if not request.get("include_hidden", False) and name.startswith("."):
                    continue
                if len(os.fsencode(name)) > 255:
                    stats["unreadable"] += 1
                    continue
                try:
                    name.encode("utf-8")
                except UnicodeError:
                    stats["unreadable"] += 1
                    continue
                path = name if not relative else relative + "/" + name
                target = root.rstrip("/") + "/" + path
                if protected_path(target, protected):
                    stats["skipped_protected"] += 1
                    continue
                if len(path.encode("utf-8", "surrogateescape")) > 1024:
                    raise StopSearch("limited", "relative_path_limit")
                try:
                    info = entry.stat(follow_symlinks=False)
                    if excluded(path, stat.S_ISDIR(info.st_mode)):
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        stats["skipped_symlinks"] += 1
                    elif stat.S_ISDIR(info.st_mode):
                        child = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=directory_fd)
                        try:
                            walk(child, path, depth + 1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        if not included(path):
                            continue
                        # Opening descriptor-bound paths prevents symlink exchange from escaping the root.
                        if request["kind"] == "files":
                            file_fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=directory_fd)
                            try:
                                opened = os.fstat(file_fd)
                                if opened.st_nlink != 1:
                                    stats["skipped_hardlinks"] += 1
                                elif stat.S_ISREG(opened.st_mode) and matches(path):
                                    append({"path": path})
                                    equal = str.casefold if request.get("ignore_case", False) else lambda value: value
                                    if (request.get("early_termination", False) and mode == "literal"
                                            and equal(name) == equal(request["query"])):
                                        raise StopSearch("completed", "exact_filename_match")
                            finally:
                                os.close(file_fd)
                        else:
                            read_content(directory_fd, name, path)
                    else:
                        stats["skipped_special"] += 1
                except OSError:
                    stats["unreadable"] += 1

    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, budget["seconds"])
    state, reason = "completed", None
    try:
        with os.fdopen(result_fd, "wb") as output:
            try:
                walk(root_fd, "", 0)
            except StopSearch as stopped:
                state, reason = stopped.state, stopped.reason
            except BaseException:
                state, reason = "failed", "native_worker_error"
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                output.flush()
                os.fsync(output.fileno())
    finally:
        os.close(root_fd)
    coverage_statistics(stats, state, reason)
    record.update(state=state, reason=reason, snapshot_ready=True, statistics=stats,
                  finished_unix_ms=int(time.time() * 1000), result_bytes=result_bytes,
                  committed_results=stats["results"], committed_result_bytes=result_bytes)
    write_json(fd, "record.json", record)


def main(request):
    identity = job_id(request["search_id"])
    owner = job_id(request["owner"])
    state_path = absolute(request["state_dir"]) + "/search"
    base = open_dir(state_path, create=True)
    private(base)
    lock_fd = os.open(".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=base)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        if request["action"] == "start":
            authorized_root(request)
            options(request)
            # Limit both permanent state growth and concurrent detached workers.
            total = active = owned = 0
            with os.scandir(base) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    total += 1
                    if total >= CAPS["jobs"]:
                        raise ValueError("search receipt quota reached")
                    other_fd = os.open(entry.name, FLAGS | os.O_DIRECTORY, dir_fd=base)
                    try:
                        other = reconcile(other_fd, read_json(other_fd, "record.json"))
                    finally:
                        os.close(other_fd)
                    if other["state"] not in TERMINAL:
                        active += 1
                        owned += other["owner"] == owner
            if active >= CAPS["active"] or owned >= 4:
                raise ValueError("active search quota reached")
            os.mkdir(identity, 0o700, dir_fd=base)
        fd = os.open(identity, FLAGS | os.O_DIRECTORY, dir_fd=base)
        private(fd)
        try:
            if request["action"] == "start":
                record = {"owner": owner, "state": "running", "snapshot_ready": False,
                          "deadline": time.time() + request["limits"]["seconds"], "statistics": {}}
                coverage_statistics(record["statistics"])
                write_json(fd, "record.json", record)
                child = os.fork()
                if child == 0:
                    os.close(lock_fd)
                    os.setsid()
                    if os.fork() != 0:
                        os._exit(0)
                    devnull = os.open("/dev/null", os.O_RDWR)
                    for stream in (0, 1, 2):
                        os.dup2(devnull, stream)
                    if devnull > 2:
                        os.close(devnull)
                    try:
                        # Darwin refuses RLIMIT_AS; its buffers remain structurally bounded by the same file/read/result caps.
                        if sys.platform == "linux":
                            resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
                        resource.setrlimit(resource.RLIMIT_CPU, (10, 12))
                        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
                        search(fd, request, record)
                    except BaseException:
                        record.update(state="failed", reason="native_worker_setup_error", snapshot_ready=False)
                        coverage_statistics(record["statistics"], record["state"], record["reason"])
                        with contextlib.suppress(BaseException):
                            write_json(fd, "record.json", record)
                    os._exit(0)
                os.waitpid(child, 0)
                return {"state": "running", "snapshot_ready": False}
            record = reconcile(fd, read_json(fd, "record.json"))
            if record["owner"] != owner:
                raise ValueError("search unavailable to this session")
            if request["action"] == "stop":
                if record["state"] not in TERMINAL:
                    cancel = os.open("cancel", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=fd)
                    os.fsync(cancel)
                    os.close(cancel)
                    os.fsync(fd)
                return {"state": record["state"], "stop_requested": record["state"] not in TERMINAL}
            if request["action"] == "results":
                return snapshot(fd, record, request.get("cursor", 0), request.get("limit", 32))
            if request["action"] == "status":
                return {"state": record["state"], "reason": record.get("reason"),
                        "snapshot_ready": record.get("snapshot_ready", False),
                        "statistics": record.get("statistics", {})}
            raise ValueError("unknown search action")
        finally:
            os.close(fd)
    finally:
        os.close(lock_fd)
        os.close(base)


if __name__ == "__main__":
    try:
        print(json.dumps(main(json.load(sys.stdin)), ensure_ascii=True, separators=(",", ":")))
    except Exception:
        # Paths and filesystem exceptions must not leak through denied references.
        print(json.dumps({"error": "native search request refused"}), file=sys.stderr)
        sys.exit(1)
