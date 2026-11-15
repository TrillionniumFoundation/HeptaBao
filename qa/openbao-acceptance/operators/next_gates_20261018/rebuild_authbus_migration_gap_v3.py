#!/usr/bin/env python3
"""Rebuild a NEW v3 scanner from four verified public inventory receipts.

This does not recreate the missing v2 PLAN, its manifest, or any old run receipt.
Local source generation only; no host scan, network, SDK, or credentials.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
HOSTS = ("main", "macbook-pro", "rog", "pocket4")
EXPECTED = {
    "main": (29580, "a5083d6c99800054eb50155dafe033fd7429fdec48d8b440569eae5678e62452"),
    "macbook-pro": (24261, "4445db0b874b12f27a11f2f9dab2d9d261dc6457acf827623f840e1705a560fd"),
    "rog": (22917, "0a10171367de4b7588177f750e65bddef9219a5769615667b356ad0c1602440a"),
    "pocket4": (17586, "7282f921223de2fb7ea32a7c39298322e65d22350f0a8e871ed87e3f3a8da293"),
}
RECOVERED = {
    "authbus_migration_gap_inventory_v2.body-recovered.py.txt": "b4f0a4b036fe0491898e790819e91baaaeed74a13b544cd86a025c6fef4d25f9",
    "authbus_migration_gap_inventory_v2_tests.py": "992731b0eb5108fbafab4c5065c6e262946928f7da1cff01e396f5fc50591639",
    "run_authbus_migration_gap_v2_r1.py": "c15e14a8ae8247d748301921128f248a2e04f8eeec566bbdefc8626481e420d7",
    "run_authbus_migration_gap_v2_r1_tests.py": "fcd1fef5ea200a10c4764a8d881720bce20908aa428dbbfc705170ac51dbce5d",
}
BOUNDS = {
    "hard_alarm_seconds": 24, "maximum_code_bytes": 262144,
    "maximum_config_bytes": 2097152, "maximum_depth": 2,
    "maximum_json_depth": 32, "maximum_json_nodes": 20000,
    "per_directory_entries": 64, "seconds": 20, "sqlite_header_bytes": 16,
    "total_directories": 96, "total_entries": 2048, "total_read_bytes": 16777216,
}
ENTRYPOINT_FIELDS = {
    "exists", "gid", "mode", "mtime_ns", "operation_indicators", "path",
    "path_references", "sha256", "size", "uid", "environment_field_names",
    "launch_label", "launch_program", "directives",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def pretty(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def original(name):
    raw = (HERE / name).read_bytes()
    assert sha(raw) == RECOVERED[name], (name, "recovered_source_changed")
    return raw.decode()


def build_plan():
    records, inputs = [], {}
    for host in HOSTS:
        name = "authbus-current-inventory-r1-" + host + ".json"
        raw = (HERE / "local-r8-evidence" / name).read_bytes()
        assert (len(raw), sha(raw)) == EXPECTED[host], (host, "original_receipt_mismatch")
        value = json.loads(raw)
        assert value["schema"] == "authbus-current-client-source-metadata-v1"
        assert value["host_label"] == host and value["read_only"] is True
        assert all(value[k] is False for k in ("production_mutation", "credentials_exported", "provider_called", "sdk_imported"))
        records.append({"host": host, "name": name, "bytes": len(raw), "sha256": sha(raw), "created_at": value["created_at"]})
        inputs[host] = value
    receipt_set = {"schema": "authbus-migration-gap-source-receipts-v3", "receipts": records}
    plan = {
        "schema": "authbus-migration-gap-allowlist-v3", "read_only": True,
        "reconstruction": "New v3 derived from verified original four-host public receipts; not the missing v2 PLAN or manifest.",
        "source_receipt_set": receipt_set,
        "source_receipt_set_sha256": sha(canonical(receipt_set)),
        "bounds": BOUNDS, "hosts": {},
        "pending_boundaries": [
            {"id": "x230_owner_source", "status": "pending_not_inspected", "paths": [], "basis": "Retained reviewed boundary; no verified owner/path receipt among these four inputs."},
            {"id": "ai395_owner_source", "status": "pending_not_inspected", "paths": [], "basis": "A configured provider reference does not inspect its host; no owner/path authority supplied."},
            {"id": "private_ci_client_sources", "status": "pending_not_inspected", "paths": [], "basis": "Retained reviewed boundary; no private-CI owner/path authority supplied."},
        ],
    }
    for record in records:
        host, d = record["host"], inputs[record["host"]]
        flattened = {}
        for group in d["backup_references"]:
            assert group["contents_not_read"] is True
            for item in group["references"]:
                if item["path"] in flattened:
                    assert flattened[item["path"]] == item
                flattened[item["path"]] = item
        backups = []
        for path, item in sorted(flattened.items()):
            name = PurePosixPath(path).name
            kind = "authbus_runtime_state" if name == "authbus" else "relay_runtime_state" if name == "authbus-relay" else "backup_reference"
            backups.append({"path": path, "kind": kind, "baseline": {k: v for k, v in item.items() if k != "path"}})
        missing = []
        for item in d["client_store_metadata"]:
            if item["directory"].get("exists") is not False:
                continue
            agents = [a for a in d["agents"] if a.get("agent_dir") == item["agent_dir"]]
            assert len(agents) == 1
            agent = agents[0]
            missing.append({"agent_id": agent["id"], "agent_dir": item["agent_dir"],
                            "configured_model": agent["model"],
                            "existing_file_references": [x["path"] for x in item["files"]]})
        startups, dependencies = [], []
        relay_entries = [x for x in d["entrypoints"] if "/Library/LaunchAgents/ai.openclaw.authbus-relay." in x.get("path", "") and x["path"].endswith(".plist")]
        for item in sorted(relay_entries, key=lambda x: x["path"]):
            startups.append({"path": item["path"], "label": item["launch_label"],
                             "sha256": item["sha256"], "existing_path_references": item["path_references"]})
        relay_prefix = d["home"] + "/.openclaw/authbus-relay/"
        for path in sorted({p for item in relay_entries for p in item["path_references"] if p.startswith(relay_prefix)}):
            relative = path[len(relay_prefix):]
            if relative.startswith("auth/"):
                inspection = "metadata_only"
            elif relative.startswith("bin/"):
                inspection = "pure_code_or_binary_metadata"
            elif relative == "config/cliproxy.runtime.yaml":
                inspection = "endpoint_yaml"
            elif relative == "state/bridge.json":
                inspection = "endpoint_json"
            else:
                raise AssertionError("unreviewed_relay_dependency")
            dependencies.append({"path": path, "inspection": inspection})
        plan["hosts"][host] = {
            "receipt": {k: v for k, v in record.items() if k != "host"},
            "expected_home": d["home"], "expected_uid": d["config"]["uid"], "expected_platform": d["platform"],
            "config": {k: d["config"][k] for k in ("path", "sha256")},
            "secretrefs": [{k: x[k] for k in ("id", "path", "source")} for x in d["secret_providers"]],
            "binding_files": [{"kind": kind, "path": item["path"]} for kind, item in sorted(d["authbus"]["binding_files"].items())],
            "backup_runtime": backups, "missing_agents": missing,
            "relay_startups": startups, "relay_dependencies": dependencies,
            "reused_existing_store_metadata": d["client_store_metadata"],
            "reused_entrypoint_metadata": [{k: v for k, v in item.items() if k in ENTRYPOINT_FIELDS} for item in d["entrypoints"]],
            "baseline_configured_agent_scope_count": len(d["agents"]),
        }
        assert all(x["source"] == "file" for x in plan["hosts"][host]["secretrefs"])
    counts = {key: sum(len(h[key]) for h in plan["hosts"].values()) for key in ("secretrefs", "binding_files", "backup_runtime", "missing_agents", "relay_startups", "relay_dependencies")}
    assert counts == {"secretrefs": 19, "binding_files": 12, "backup_runtime": 38, "missing_agents": 2, "relay_startups": 4, "relay_dependencies": 8}, counts
    assert {x["agent_id"] for x in plan["hosts"]["main"]["missing_agents"]} == {"trillionnium-os-agent", "hepta-luna-teacher"}
    assert sum(h["baseline_configured_agent_scope_count"] for h in plan["hosts"].values()) == 21
    return plan


def build_schema(plan, plan_digest):
    """Structural/schema gate; exact execution provenance also needs controller validation."""
    qualification = {"allClientsAndBackupsMigrated": False, "backupRestoreQualified": False,
                     "providerLivenessQualified": False, "productionCutoverQualified": False,
                     "legacyCleanupQualified": False, "metadataOnly": True}
    properties = {
        "schema": {"const": "authbus-migration-gap-metadata-v3"},
        "created_at": {"type": "string"}, "host_label": {"enum": list(HOSTS)},
        "host_label_is_caller_asserted": {"const": True}, "read_only": {"const": True},
        "qualification": {"const": qualification}, "source_binding": {"type": "object"},
        "configuration_references": {"$ref": "#/$defs/metadata"},
        "missing_agents": {"type": "array"}, "secretref_metadata": {"type": "array"},
        "authbus_binding_metadata": {"type": "array"}, "backup_runtime_entries": {"type": "array"},
        "relay_startups": {"type": "array"}, "relay_dependencies": {"type": "array"},
        "reused_evidence": {"type": "object", "required": ["freshly_scanned", "observed_at", "client_store_metadata", "entrypoint_metadata"],
                            "additionalProperties": False, "properties": {
                                "freshly_scanned": {"const": False}, "observed_at": {"type": "string"},
                                "client_store_metadata": {"type": "array"}, "entrypoint_metadata": {"type": "array"}}},
        "pending_boundaries": {"const": plan["pending_boundaries"]},
        "gaps": {"type": "array", "items": {"type": "object"}},
    }
    for key in ("network_called", "subprocess_called", "sql_called", "sdk_imported",
                "credential_file_payloads_read", "credential_values_emitted", "production_mutation"):
        properties[key] = {"const": False}
    bounds = {key: {"const": value} for key, value in plan["bounds"].items()}
    bounds.update({
        "elapsed_seconds": {"type": "number", "minimum": 0, "maximum": 31},
        "bytes_read": {"type": "integer", "minimum": 0, "maximum": plan["bounds"]["total_read_bytes"]},
        "directory_entries_seen": {"type": "integer", "minimum": 0, "maximum": plan["bounds"]["total_entries"]},
        "directories_enumerated": {"type": "integer", "minimum": 0, "maximum": plan["bounds"]["total_directories"]},
        "bounds_hit": {"type": "array", "uniqueItems": True, "items": {"enum": ["original_time_budget", "total_read_bytes", "total_directories", "per_directory_entries", "total_entries", "maximum_depth"]}},
        "content_read_operations": {"type": "array", "items": {"$ref": "#/$defs/read_operation"}},
        "filesystem_interruption_requires_caller_process_timeout": {"const": True},
    })
    properties["execution_bounds"] = {"type": "object", "additionalProperties": False, "required": sorted(bounds), "properties": bounds}
    cases = []
    for host in HOSTS:
        selected = plan["hosts"][host]
        fields = {
            "source_binding": {"const": {"receipt_set_sha256": plan["source_receipt_set_sha256"],
                                          "allowlist_canonical_sha256": plan_digest, "original_metadata_receipt": selected["receipt"]}},
            "configuration_references": {"properties": {"path": {"const": selected["config"]["path"]}}},
        }
        for output, planned in (("secretref_metadata", "secretrefs"), ("authbus_binding_metadata", "binding_files"),
                                ("backup_runtime_entries", "backup_runtime"), ("missing_agents", "missing_agents"),
                                ("relay_startups", "relay_startups"), ("relay_dependencies", "relay_dependencies")):
            items = []
            for item in selected[planned]:
                path_key = "planned_agent_dir" if planned == "missing_agents" else "path"
                checks = {path_key: {"const": item["agent_dir"] if planned == "missing_agents" else item["path"]}}
                if planned == "secretrefs":
                    checks.update({k: {"const": False} for k in ("contents_read", "payload_opened", "credential_source_qualified", "migration_complete")})
                if planned == "binding_files" or (planned == "relay_dependencies" and item["inspection"] == "metadata_only"):
                    checks["contents_read"] = {"const": False}
                if planned == "backup_runtime":
                    checks.update({k: {"const": False} for k in ("restore_qualified", "backup_consistency_verified", "full_tree_enumerated")})
                if planned == "missing_agents":
                    checks.update({k: {"const": False} for k in ("owner_sdk_inspection_qualified", "migration_complete")})
                required = [key for key in checks if key != "full_tree_enumerated"]
                items.append({"type": "object", "required": required, "properties": checks})
            sequence = {"type": "array", "minItems": len(items), "maxItems": len(items)}
            if items:
                sequence.update(prefixItems=items, items=False)
            fields[output] = sequence
        cases.append({"if": {"properties": {"host_label": {"const": host}}}, "then": {"properties": fields}})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:heptabao:authbus-migration-gap-metadata-v3",
        "title": "New v3 bounded public metadata receipt",
        "$comment": "Metadata/projection nested objects intentionally allow producer-specific metadata fields. This is not a credential redactor. Accept public payloads only with the hash-frozen producer and strict controller source/scope/read validator; old reused arrays are equality-checked there.",
        "type": "object", "additionalProperties": False, "required": sorted(properties),
        "properties": properties, "allOf": cases,
        "$defs": {
            "metadata": {"type": "object", "required": ["path", "contents_read"], "properties": {"path": {"type": "string"}, "contents_read": {"type": "boolean"}}},
            "read_operation": {"type": "object", "additionalProperties": False,
                "required": ["path", "profile", "bytes", "header_only"],
                "properties": {"path": {"type": "string", "pattern": "^/"}, "profile": {"enum": ["database_magic", "executable_magic", "approved_config", "approved_metadata_projection"]},
                               "bytes": {"type": "integer", "minimum": 0, "maximum": plan["bounds"]["maximum_config_bytes"]}, "header_only": {"type": "boolean"}},
                "allOf": [{"if": {"properties": {"profile": {"enum": ["database_magic", "executable_magic"]}}},
                           "then": {"properties": {"bytes": {"maximum": 16}, "header_only": {"const": True}}},
                           "else": {"properties": {"header_only": {"const": False}}}},
                          {"if": {"properties": {"profile": {"const": "approved_metadata_projection"}}},
                           "then": {"properties": {"bytes": {"maximum": plan["bounds"]["maximum_code_bytes"]}}}}]},
        },
    }


def main():
    plan = build_plan()
    plan_raw = canonical(plan)
    body = original("authbus_migration_gap_inventory_v2.body-recovered.py.txt")
    body = body.replace("metadata receipts.\n\nThe embedded allowlist comes from the reviewed migration manifest, not from\nfilesystem discovery.", "metadata receipts.\n\nThe v3 allowlist is derived from four SHA-verified original public receipts.\nIt is a new version, not a reconstruction of the missing v2 manifest or PLAN.")
    body = body.replace("authbus-migration-gap-metadata-v2", "authbus-migration-gap-metadata-v3")
    body = body.replace("__PLAN_BYTES_MISSING__", plan_raw.decode())
    body = body.replace("manifest_sha256", "receipt_set_sha256")
    before = "    def read_bound(self, count):\n        self.gate()\n        if self.bytes_read + count > self.bounds['total_read_bytes']:\n            self.hits.add('total_read_bytes')\n            raise BudgetExceeded('total_read_bytes')\n        self.bytes_read += count\n"
    after = "    def read_bound(self, count):\n        # os.read already returned: account actual bytes even across the deadline.\n        self.bytes_read += count\n        if self.bytes_read > self.bounds['total_read_bytes']:\n            self.hits.add('total_read_bytes')\n            raise BudgetExceeded('total_read_bytes')\n        self.gate()\n"
    assert body.count(before) == 1
    body = body.replace(before, after)
    env = "    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):\n        ep = endpoint(env.get(key))\n        if ep:\n            projected.append({'field': 'EnvironmentVariables/' + key,\n                              'direction': 'configured_upstream_or_proxy', 'endpoint': ep})\n"
    assert body.count(env) == 1
    body = body.replace(env, "    # v3 is names-only for every environment field, including proxy variables.\n")
    scanner_raw = body.encode()
    ast.parse(body, feature_version=(3, 9))
    controller = original("run_authbus_migration_gap_v2_r1.py")
    controller = controller.replace("v2", "v3")
    controller = controller.replace("SCANNER_BYTES = 117575", "SCANNER_BYTES = " + str(len(scanner_raw)))
    controller = controller.replace("06a423e7464cb61bcac202be04ba2b8c0c6b3da2ddb91955efaf1d1061cabca5", sha(scanner_raw))
    controller = controller.replace("c6fa1b227e030f068864bfec0db33ebd52ed4918c7f1fedd71967da41c00e320", sha(plan_raw))
    controller = controller.replace("MANIFEST_SHA256", "SOURCE_RECEIPT_SET_SHA256").replace("manifest_sha256", "receipt_set_sha256")
    controller = controller.replace("232d76d2c60ccfa3df1507c53031b962a844e753947d283a8059ba0c6b0e3be8", plan["source_receipt_set_sha256"])
    controller = controller.replace('if sha(canonical(plan)) != PLAN_SHA256 or plan["source_receipt_set_sha256"] != SOURCE_RECEIPT_SET_SHA256:', 'if (sha(canonical(plan)) != PLAN_SHA256\n            or plan["source_receipt_set_sha256"] != SOURCE_RECEIPT_SET_SHA256\n            or sha(canonical(plan["source_receipt_set"])) != SOURCE_RECEIPT_SET_SHA256):')
    ast.parse(controller, feature_version=(3, 9))
    scanner_tests = original("authbus_migration_gap_inventory_v2_tests.py").replace("v2", "v3")
    scanner_tests = scanner_tests.replace("self.assertEqual(len(projection['endpoints']), 2)", "self.assertEqual(len(projection['endpoints']), 1)\n        self.assertTrue(all(not x['field'].startswith('EnvironmentVariables/') for x in projection['endpoints']))")
    regression = '''    def test_read_returning_after_deadline_is_charged_and_not_qualified(self):
        self.config.write_text('{}')
        inspector = self.inspector()
        original_read = SCANNER.os.read
        actual = []
        def late_read(fd, size):
            value = original_read(fd, size)
            actual.append(len(value))
            inspector.budget.deadline = 0
            return value
        with mock.patch.object(SCANNER.os, 'read', side_effect=late_read):
            with self.assertRaises(SCANNER.BudgetExceeded):
                inspector.fs.read(str(self.config), 4096, 'approved_config')
        self.assertEqual(actual, [2])
        self.assertEqual(inspector.budget.bytes_read, sum(actual))
        self.assertEqual(inspector.fs.content_reads, [])
        self.assertIn('original_time_budget', inspector.budget.hits)

'''
    marker = "    def test_tree_depth_and_entry_bounds_are_visible(self):"
    assert scanner_tests.count(marker) == 1
    scanner_tests = scanner_tests.replace(marker, regression + marker)
    controller_tests = original("run_authbus_migration_gap_v2_r1_tests.py").replace("v2", "v3")
    outputs = {
        "authbus_migration_gap_inventory_v3.py": body,
        "authbus_migration_gap_allowlist_v3.json": pretty(plan),
        "authbus_migration_gap_source_receipts_v3.json": pretty(plan["source_receipt_set"]),
        "authbus_migration_gap_schema_v3.json": pretty(build_schema(plan, sha(plan_raw))),
        "authbus_migration_gap_inventory_v3_tests.py": scanner_tests,
        "run_authbus_migration_gap_v3_r1.py": controller,
        "run_authbus_migration_gap_v3_r1_tests.py": controller_tests,
    }
    for name, text in outputs.items():
        (HERE / name).write_text(text)
    print(pretty({"schema": "authbus-migration-gap-v3-generation-summary", "new_version": True,
                  "old_plan_recovered": False, "real_hosts_scanned": 0,
                  "allowlist_canonical_sha256": sha(plan_raw),
                  "source_receipt_set_sha256": plan["source_receipt_set_sha256"],
                  "outputs": {name: {"bytes": len(text.encode()), "sha256": sha(text.encode())} for name, text in outputs.items()}}))


if __name__ == "__main__":
    main()
