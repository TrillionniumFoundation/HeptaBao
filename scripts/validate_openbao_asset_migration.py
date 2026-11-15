#!/usr/bin/env python3
"""Validate the closed-world OpenBao 2.6.2 -> HeptaBao asset migration ledger."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "planning/HEPTABAO_OPENBAO_ASSET_MIGRATION_V1.json"
EXPECTED = {
    "system_configuration", "policies_acl", "namespaces", "auth_mounts",
    "identity_entities_aliases_groups", "tokens_and_revocation",
    "kv_v2_data_history_metadata", "transit_keys_ciphertexts",
    "pki_keys_roles_certs_revocation", "ssh_roles_credentials",
    "database_config_roles_leases", "other_secret_engines",
    "leases_and_revocation_state", "audit_configuration", "storage_ha_metadata",
    "wrapping_cubbyhole_ephemeral", "external_provider_configuration", "application_consumers",
}
ALLOWED = {
    "BOUNDED_ADAPTER", "PREFLIGHT_ONLY", "NO_SAFE_TRANSFER_IMPLEMENTED",
    "DO_NOT_TRANSFER_LIVE_AUTHORITY", "RECREATE_AND_VERIFY",
    "DO_NOT_IMPORT_RAW_FORMAT", "EPHEMERAL_DO_NOT_MIGRATE",
}


def load(path: Path = LEDGER) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(doc: dict) -> list[str]:
    errors: list[str] = []
    if doc.get("schema") != "heptabao.openbao-asset-migration.v1": errors.append("wrong schema")
    if doc.get("source_product") != "OpenBao" or doc.get("source_version") != "2.6.2": errors.append("wrong frozen source baseline")
    for flag in ("full_asset_migration_authority", "cutover_authority", "rollback_authority"):
        if doc.get(flag) is not False: errors.append(f"{flag} must remain false until external admission")
    rows = doc.get("assets")
    if not isinstance(rows, list): return errors + ["assets must be an array"]
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(set(ids)): errors.append("duplicate asset id")
    if set(ids) != EXPECTED: errors.append("asset denominator drift")
    for row in rows:
        if not isinstance(row, dict):
            errors.append("asset row must be an object"); continue
        aid = row.get("id", "<missing>"); disposition = row.get("disposition")
        if disposition not in ALLOWED: errors.append(f"{aid}: invalid disposition")
        if not row.get("required_exit"): errors.append(f"{aid}: missing required_exit")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"{aid}: missing evidence")
        else:
            for rel in evidence:
                path = ROOT / rel
                if not path.is_file() or path.is_symlink(): errors.append(f"{aid}: missing evidence path {rel}")
        adapter = row.get("adapter")
        if disposition == "BOUNDED_ADAPTER":
            if not isinstance(adapter, str) or not adapter: errors.append(f"{aid}: bounded adapter missing executable path")
            elif not (ROOT / adapter).is_file() or (ROOT / adapter).is_symlink(): errors.append(f"{aid}: adapter path missing or symlinked")
        elif adapter is not None:
            errors.append(f"{aid}: adapter must be null for disposition {disposition}")
    return errors


def main() -> int:
    doc = load(); errors = validate(doc)
    if errors:
        for error in errors: print(f"FAIL: {error}")
        return 1
    bounded = sum(row["disposition"] == "BOUNDED_ADAPTER" for row in doc["assets"])
    print(f"openbao-asset-migration: PASS ({len(EXPECTED)} asset classes; {bounded} bounded adapters; authority=false)")
    return 0


if __name__ == "__main__": raise SystemExit(main())
