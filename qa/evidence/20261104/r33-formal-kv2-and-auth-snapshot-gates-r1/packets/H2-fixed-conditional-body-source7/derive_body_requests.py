"""Pure request materializer; no I/O, Runtime, product, or module execution authority."""
import copy
import re

def derive_body_requests(config, receipt_observation, binding_observation):
    """Inputs must come from the two independently closed original file_info chains."""
    if config["schema"] != "heptabao.H2-stage.conditional-body-config.v1":
        raise ValueError("config schema")
    if config["ready"] is not False or config["runtime_GO"] is not False:
        raise ValueError("proposal must not claim execution authority")
    if config["chunk_cap"] != 16384 or config["planned_bytes"] != 38845:
        raise ValueError("fixed body scope")
    expected = config["expected"]
    if len(expected) != 2 or [x["role"] for x in expected] != ["receipt", "binding"]:
        raise ValueError("fixed metadata roles")
    versions = {}
    current_metadata = {}
    for exp, observed in zip(expected, (receipt_observation, binding_observation)):
        if observed["request"] != exp["metadata_request"]:
            raise ValueError("original metadata request mismatch")
        admission, status, info = observed["admission"], observed["status"], observed["info"]
        if admission["operation_id"] != status["operation_id"]:
            raise ValueError("metadata observer ID")
        if admission["tool_name"] != "file_info" or status["tool_name"] != "file_info":
            raise ValueError("metadata tool")
        if (status["async_state"], status["result_state"], status["owned_future_active"],
                status["payload_available"]) != ("completed", "stored_observed", False, True):
            raise ValueError("metadata observer not fully closed")
        if observed["original_payload_verified_whole"] is not True:
            raise ValueError("metadata original payload not whole")
        if info["path"] != exp["path"] or info["size"] != exp["bytes"] or info["sha256"] != exp["sha256"]:
            raise ValueError("metadata content pin mismatch")
        md = info["metadata"]
        if info["mode"] != 384 or md["mode"] != 384:
            raise ValueError("fixed file mode")
        if (md["uid"], md["gid"], md["link_count"], md["metadata_platform"]) != (1000, 1000, 1, "linux"):
            raise ValueError("fixed file identity")
        version = info["version"]
        if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?::(?:0|[1-9][0-9]*)){4}", version):
            raise ValueError("exact native version")
        dev, ino, size, mtime, ctime = map(int, version.split(":"))
        if size != info["size"] or dev <= 0 or ino <= 0:
            raise ValueError("version metadata mismatch")
        if exp["role"] == "binding" and version != exp["expected_stage_writer_version"]:
            raise ValueError("binding changed from original stage writer")
        versions[exp["role"]] = version
        current_metadata[exp["role"]] = {
            "device": dev, "inode": ino, "uid": md["uid"], "gid": md["gid"],
            "permission_mode": md["mode"], "links": md["link_count"], "bytes": size,
            "mtime_ns": mtime, "ctime_ns": ctime, "version": version,
        }
    # Both original file_info observations have passed before any request is returned.
    expected_ranges = (("receipt", 0, 16384), ("receipt", 16384, 12231), ("binding", 0, 10230))
    if len(config["templates"]) != 3:
        raise ValueError("fixed three bodies")
    requests = []
    for template, (role, offset, limit) in zip(config["templates"], expected_ranges):
        req = copy.deepcopy(template["request"])
        args = req["operation"]["arguments"]
        exp = expected[0 if role == "receipt" else 1]
        if template["role"] != role or template["expected_bytes"] != limit:
            raise ValueError("fixed body role")
        if (req["operation"]["tool"], args["host"], args["path"], args["offset"],
                args["limit"], args["expected_version"]) != ("binary_read", "desktop", exp["path"], offset, limit, None):
            raise ValueError("fixed body request")
        args["expected_version"] = versions[role]
        requests.append(req)
    if len({req["idempotency_key"] for req in requests}) != 3:
        raise ValueError("fixed distinct body keys")
    return {
        "schema": "heptabao.H2-stage.materialized-body-proposal.v1",
        "runtime_GO": False,
        "requests": requests,
        "current_metadata": current_metadata,
        "planned_bytes": 38845,
        "request_transformation": "Only each expected_version null is replaced by its original independently closed file_info version.",
        "before_each_submission": "Persist the exact request and a separate completed external intent; one returned native future at a time; stop on error.",
    }

