"""Compatibility shim: qualification and product clients share one transport.

Oracle evidence helpers remain here, outside the distributable client package.
"""
from pathlib import Path
import sys
import re
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "clients/python"))
from heptabao.transport import (BaoError, Client, Response, SafeArgumentParser,
    MAX_BODY, canonical, digest, decode_json, private_read, private_json, transport_diagnostic,
    private_write, private_write_text, endpoint, key_path, NoRedirect)

# Strict versions for source inventory and scoped recreation only. This is
# not asset-completeness, cutover or rollback authority.
MIGRATION_SOURCE_VERSIONS = frozenset(("2.6.2", "2.7.0", "2.7.1"))

def supported_migration_source_version(version: object) -> bool:
    return type(version) is str and version in MIGRATION_SOURCE_VERSIONS


def distinct_endpoints(left: Client, left_health: dict, right: Client, right_health: dict):
    if left.address == right.address or left_health["cluster_id"] == right_health["cluster_id"]:
        raise BaoError("same_endpoint_or_cluster_rejected")


def verify_oracle_identity(receipt: dict, oracle: Client, health: dict, *, version="2.6.2") -> dict:
    if not supported_migration_source_version(version):
        raise BaoError("oracle_identity_unsupported_version")
    required = {"product", "version", "artifact_sha256", "provenance_url", "endpoint", "cluster_id"}
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        raise BaoError("oracle_identity_receipt_incomplete")
    if (receipt["product"] != "OpenBao" or receipt["version"] != version
            or health["version"] != version or receipt["cluster_id"] != health["cluster_id"]
            or endpoint(receipt["endpoint"]) != oracle.address
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["artifact_sha256"])
            or receipt["artifact_sha256"] == "0" * 64
            or receipt["provenance_url"] != "https://github.com/openbao/openbao/releases/tag/v" + version):
        raise BaoError("oracle_identity_receipt_mismatch")
    return {"product": "OpenBao", "version": version, "artifact_sha256": receipt["artifact_sha256"],
            "basis": "operator_artifact_attestation_plus_verified_tls_and_live_health",
            "independent_binary_attestation": False}
