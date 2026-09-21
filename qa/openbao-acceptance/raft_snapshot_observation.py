"""Read only a synthetic fixture's framed Raft bundle; export no stored content."""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
from pathlib import Path
import stat
import zlib

MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAGIC = b"HBRSB001"


def inspect_bundle(path: Path, expected_format: int = 2) -> dict:
    if expected_format not in (1, 2):
        raise ValueError("unsupported_expected_snapshot_format")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("snapshot_artifact_not_bounded_regular_file")
    with path.open("rb") as stream:
        encoded = stream.read(MAX_ARTIFACT_BYTES + 1)
    if not 20 <= len(encoded) <= MAX_ARTIFACT_BYTES or encoded[:8] != MAGIC:
        raise ValueError("snapshot_artifact_bad_frame")
    payload = encoded[16:-4]
    if int.from_bytes(encoded[8:16], "little") != len(payload):
        raise ValueError("snapshot_artifact_bad_length")
    if int.from_bytes(encoded[-4:], "little") != zlib.crc32(payload):
        raise ValueError("snapshot_artifact_bad_checksum")
    try:
        bundle = json.loads(payload)
        snapshot = bundle["current_snapshot"]
        data = snapshot["data"]
        if type(bundle["format_version"]) is not int or bundle["format_version"] != expected_format:
            raise ValueError("snapshot_artifact_wrong_format")
        if expected_format == 1:
            if not isinstance(data, list) or any(type(v) is not int or not 0 <= v <= 255 for v in data):
                raise ValueError("snapshot_legacy_representation_mismatch")
            decoded = bytes(data)
        else:
            if not isinstance(data, str) or not data.isascii() or "=" in data:
                raise ValueError("snapshot_compact_representation_mismatch")
            decoded = base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
            if base64.b64encode(decoded).decode().rstrip("=") != data:
                raise ValueError("snapshot_compact_not_canonical")
        state = json.loads(decoded)
        if not isinstance(state, dict) or not isinstance(bundle["state"], dict):
            raise ValueError("snapshot_state_not_object")
        if state.get("last_applied_log") != snapshot["meta"].get("last_log_id"):
            raise ValueError("snapshot_metadata_mismatch")
        if state.get("last_membership") != snapshot["meta"].get("last_membership"):
            raise ValueError("snapshot_membership_mismatch")
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        raise ValueError("snapshot_artifact_invalid_content") from None
    return {"format_version": expected_format, "artifact_bytes": len(encoded),
            "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
            "snapshot_bytes": len(decoded), "canonical_representation": True,
            "checksum_verified": True, "metadata_matches_snapshot": True}


COMPACT_MILESTONES = frozenset({
    "leader_compact_snapshot_observed", "prejoin_logs_really_purged",
    "learner_compact_snapshot_observed", "learner_recovers_pre_purge_state",
    "failover_after_membership_changes", "failover_preserves_pre_snapshot_value",
    "reopened_compact_snapshot_observed", "reopened_preserves_pre_snapshot_value",
    "post_change_forwarding_preserves_committed_data", "snapshot_receipt_has_no_secrets",
    "compact_snapshot_complete",
})


def complete_compact_scenarios(scenarios: list[str]) -> bool:
    from online_evidence import complete_checks
    return (bool(scenarios) and scenarios[-1] == "compact_snapshot_complete"
            and complete_checks([{"case": case, "passed": True} for case in scenarios],
                                required_cases=COMPACT_MILESTONES))
