#!/usr/bin/env python3
"""DirectLAN98 plus a separately counted official OpenBao 2.7.1 history chain.

The original 98 checks and lifecycle are unchanged. After their synthetic data
cleanup, import the exact full34 native-large bundle from an existing successful
kv2_271_lossless_native_live run into a mount created before V6 activation.
Verify all 19 versions against the actual official API responses, then snapshot,
observe a version-20 mutation, restore, kill the leader, rejoin it cold and cold
restart all three physical nodes. This is synthetic evidence, never cutover.

Additional arguments: --official-full34-root PATH and
--official-full34-summary-sha256 SHA256. Other arguments are the DirectLAN98
runner's exact source/build/host/port bindings. Input evidence stays read-only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time

import kv2_271_lossless_native_live as exact
import native_v6_ha_direct_lan_live as direct
import official_openbao_launcher as official

native, base = direct.native, direct.base
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WIRE = HERE / "native_v6_ha_official_history_wire.py"
MIGRATE = ROOT / "tools/migration/openbao271_kv2_native_large_migrate.py"
MOUNT = "oracle271"
IMPORT_ROUTE = "sys/migration/openbao/kv2/native-large?mount=" + MOUNT
SNAPSHOT = "sys/storage/raft/snapshot"
EXPORT = "sys/migration/openbao/kv2/export?mount=" + MOUNT
EXTRA_CHECKS = frozenset("official271_" + name for name in (
    "source_evidence_bound", "mount_created_before_activation", "pristine_before_import",
    "native_large_import_once", "capacity_full34", "import_all_hosts_readindex", "import_raw_history_exact",
    "snapshot_download_once", "snapshot_v6_ha_contract", "post_snapshot_mutation_once",
    "snapshot_restore_once", "restore_publication_advanced", "restore_all_hosts_readindex", "restore_raw_history_exact",
    "leader_stopped", "successor_elected", "successor_history_exact",
    "old_leader_cold_rejoin_readindex", "all_nodes_cold_restart", "cold_all_hosts_history_exact", "cold_raw_history_exact",
    "soft_deleted_payload_undelete_exact", "destroyed_payload_remains_absent",
    "data_cas_denied_without_effect", "metadata_cas_denied_without_effect",
    "metadata_cas_counter_exact", "history_cleanup_once", "mutation_effects_observed",
    "inputs_and_binaries_unchanged", "report_excludes_runtime_secrets",
))


def need(value, label):
    if not value:
        raise base.FixtureError("official271_" + label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def admit_source(root, summary_sha256):
    """Bind source API observations and lossless raw history, not a pass flag alone."""
    root = Path(root)
    need(root.is_absolute() and root.resolve(strict=True) == root, "source_root_identity")
    inputs = {}

    def read(name, maximum=exact.ARCHIVE_BYTES):
        path = root / name
        raw = exact.private_read(path, maximum)
        inputs[str(path)] = digest(raw)
        return raw

    summary_raw = read("summary.json", 4 * exact.MIB)
    need(digest(summary_raw) == summary_sha256, "source_receipt_pin")
    receipt = exact.decode(summary_raw)
    checks = receipt.get("checks", [])
    need(receipt.get("schema") == "heptabao.openbao271-kv2-lossless-native-live.v1"
         and receipt.get("status") == "passed" and receipt.get("profile") == "full34"
         and receipt.get("official_version") == "2.7.1" and receipt.get("migration_lane") == "native-large"
         and receipt.get("full34_qualified") is True and receipt.get("synthetic_only") is True
         and receipt.get("source_unchanged_at_cleanup") is True
         and len(checks) == len(exact.CHECKS)
         and {row.get("case") for row in checks} == set(exact.CHECKS)
         and all(row.get("passed") is True for row in checks), "source_cohort")
    identity = receipt.get("official_identity", {})
    pins = official.PINNED_RELEASES["2.7.1"].values()
    need(identity.get("product") == "OpenBao" and identity.get("version") == "2.7.1"
         and identity.get("storage") == "pebbledb" and bool(identity.get("cluster_id"))
         and identity.get("tls_verified") is True and identity.get("synthetic_only") is True
         and identity.get("server_mode") == "server_not_dev"
         and identity.get("archive_member_matches_executable") is True
         and identity.get("provenance_url") == "https://github.com/openbao/openbao/releases/tag/v2.7.1"
         and any(all(identity.get(key) == value for key, value in pin.items()) for pin in pins),
         "source_official_identity")
    raw = read("source-bundle.json", 64 * exact.MIB)
    exports = [row for row in receipt.get("migration_invocations", []) if row.get("operation") == "export"]
    need(len(exports) == 1 and exports[0].get("status") == "completed"
         and exports[0].get("retried") is False
         and exports[0].get("receipt", {}).get("lane") == "native-large"
         and exports[0]["receipt"].get("sha256") == digest(raw)
         and exports[0]["receipt"].get("bytes") == len(raw), "source_export_binding")
    bundle = exact.decode(raw)
    need(set(bundle) == {"schema", "config", "entries"}
         and bundle["schema"] == "openbao270-kv2-lossless-v1"
         and set(bundle["entries"]) == {"history"}, "source_bundle_shape")
    entry = bundle["entries"]["history"]
    need(entry["current_version"] == 19 and entry["max_versions"] == 25
         and bundle["config"]["max_versions"] == 25
         and set(entry["versions"]) == {str(v) for v in range(1, 20)}, "all_19_versions_retained")
    metadata = {key: value for key, value in entry.items() if key != "versions"}
    metadata["versions"] = {}
    expected, api_payloads, rows = {}, {}, receipt.get("source_api_wire_observations", [])
    need(len(rows) == 19, "source_api_denominator")
    for version in range(1, 20):
        key, item = str(version), entry["versions"][str(version)]
        need(exact.same_json_tokens(item["data"], None if version == 2 else exact.payload(version, 17, 2 * exact.MIB)),
             "source_raw_payload")
        matching = [row for row in rows if row.get("path") == "secret/data/history?version=" + key]
        source_raw = read("source-api-oracle/version-" + key.zfill(4) + ".json", exact.JSON_BYTES)
        need(len(matching) == 1 and matching[0].get("endpoint") == "source"
             and matching[0].get("method") == "GET" and matching[0].get("status") == 200
             and matching[0].get("same_response_decoded") is True
             and matching[0].get("body_bytes") == len(source_raw)
             and matching[0].get("body_sha256") == digest(source_raw), "source_api_response_binding")
        body = exact.decode(source_raw)["data"]
        need(body["metadata"]["version"] == version, "source_api_version")
        api_payloads[key] = body["data"]
        vm = {field: item[field] for field in ("created_time", "deletion_time", "destroyed")}
        metadata["versions"][key] = vm
        version_metadata = {**vm, "version": version, "custom_metadata": entry["custom_metadata"]}
        expected[key] = {"status": 404 if version < 3 else 200,
                         "data": {"data": None if version < 3 else body["data"],
                                  "metadata": version_metadata}}
    original = {"config": bundle["config"], "metadata": metadata, "versions": expected}
    need(bool(metadata["versions"]["1"]["deletion_time"])
         and metadata["versions"]["1"]["destroyed"] is False
         and metadata["versions"]["2"]["destroyed"] is True
         and digest(exact.canonical(original)) == receipt.get("source_history_sha256"),
         "source_actual_observed_history_digest")
    return raw, original, api_payloads, inputs, identity


def begin_binary(ledger, node, method, route, raw, stage, timeout):
    """Use the existing durable ledger, with the actual binary body digest."""
    ledger._require(ledger.nodes.get(node.node_id) == node, "fixture_recovery_node_binding_changed")
    ledger._verify_custody()
    sequence = ledger.sequence + 1
    ledger._write(f"mutation-{sequence:05d}.intent.json", {
        "schema": "heptabao.synthetic-fixture-mutation-intent.v1", "fixture_run_id": ledger.run_id,
        "sequence": sequence, "node_id": node.node_id, "stage": stage, "method": method,
        "route": route, "recorded_before_dispatch_unix_seconds": time.time(),
        "original_http_budget_seconds": timeout, "request_body_sha256": digest(raw),
        "request_body_bytes": len(raw), "body_digest_scope": "exact-wire-body",
        "dispatch_attempts_allowed": 1, "automatic_retry": False})
    ledger.sequence = sequence
    ledger.public_receipt["mutation_intents"] += 1
    return sequence


def archive_contract(path):
    names = ["meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed"]
    small, hashes, observed, size, magic = {}, {}, [], 0, b""
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            need(member.isfile() and member.name in names and member.name not in observed
                 and 0 <= member.size <= 130 * exact.MIB, "snapshot_member")
            observed.append(member.name)
            value, count, kept = hashlib.sha256(), 0, bytearray()
            with archive.extractfile(member) as source:
                while chunk := source.read(64 * 1024):
                    if member.name == "state.bin" and not count:
                        magic = chunk[:8]
                    count += len(chunk)
                    value.update(chunk)
                    if member.name != "state.bin":
                        need(count < 8192, "snapshot_small_member_bound")
                        kept.extend(chunk)
            need(count == member.size, "snapshot_member_size")
            hashes[member.name] = value.hexdigest()
            if member.name == "state.bin":
                size = count
            else:
                small[member.name] = bytes(kept)
    need(observed == names, "snapshot_member_order")
    meta = json.loads(small["meta.json"])
    binding = meta.get("seal_identity", {})
    need(set(meta) == {"format", "state_format", "generation", "state_bytes", "seal_identity"}
         and meta["format"] == "heptabao-native-ha-object-snapshot-v1"
         and meta["state_format"] == "heptabao-encrypted-ha-object-backup/HBV6HA01"
         and meta["state_bytes"] == size and size >= 34 * exact.MIB and magic == b"HBV6HA01"
         and type(meta["generation"]) is int and meta["generation"] >= 0
         and set(binding) == {"format", "sha256"}
         and binding["format"] == "heptabao-seal-metadata-digest-v1"
         and re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]) is not None
         and small["SHA256SUMS"] == (hashes["meta.json"] + "  meta.json\n"
                                    + hashes["state.bin"] + "  state.bin\n").encode()
         and bool(small["SHA256SUMS.sealed"]), "snapshot_v6_ha_binding")
    return {**meta, "state_sha256": hashes["state.bin"]}


class OfficialHistoryRun(direct.DirectLanRun):
    required_checks = direct.DIRECT_CHECKS | EXTRA_CHECKS

    def __init__(self, *args):
        super().__init__(*args)
        self.bundle, self.original, self.api_payloads, self.inputs, identity = admit_source(
            self.args.official_full34_root, self.args.official_full34_summary_sha256)
        spec = importlib.util.spec_from_file_location("official_history_native_large", MIGRATE)
        self.migration = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.migration
        spec.loader.exec_module(self.migration)
        for path in (Path(__file__), WIRE, Path(exact.__file__), Path(official.__file__), MIGRATE,
                     MIGRATE.with_name("kv2_native_large_http_once.py"),
                     MIGRATE.with_name("openbao270_kv2_migrate.py"),
                     MIGRATE.with_name("kv2_lossless_raw.py")):
            self.source_files[str(path.resolve())] = base.sha256_file(path)
        self.report.update({"schema": "heptabao.native-v6-direct-lan-official271-history.v1",
            "runner_sha256": base.sha256_file(Path(__file__)),
            "official_history_chain_qualified": False,
            "official_source_receipt_sha256": self.args.official_full34_summary_sha256,
            "official_source_identity": identity, "official_bundle_sha256": digest(self.bundle),
            "separate_direct_lan_required_count": len(direct.DIRECT_CHECKS),
            "separate_official_history_required_count": len(EXTRA_CHECKS),
            "native_large_http_budget_seconds": self.migration.REQUEST_SECONDS,
            "native_large_tls_scope": "actual CLI Client; enrolled IP SAN plus pinned fixture CA PEM; no leaf-pin option",
            "history_and_snapshot_tls_scope": "CA, enrolled IP SAN and enrolled leaf digest on each exact connection",
            "official_history_api_precision_scope": "same actual OpenBao 2.7.1 API numeric projection",
            "ha_raw_storage_precision_qualified": False,
            "ha_raw_storage_precision_scope": "actual HA committed-read lossless export; all 19 raw versions after import, restore and all-node cold restart",
            "ha_raw_storage_witness_scope": "single-version witness unsupported for HA; full admitted lossless export used instead",
            "official_chain_mutations": [], "official_history_observations": [],
            "unknown_effect_policy": "never replay; stop owned processes; retain private credentials, intents and outcomes; unresolved effect never qualifies"})

    def check(self, name, condition, **details):
        super().check(name, condition, **details)
        self.update_cohort_counts()
        if name == "native.complete" and condition is True:
            self.report["official_history_chain_qualified"] = True
            self.report["native_ha_backup_verified"] = True
            self.report["ha_raw_storage_precision_qualified"] = True
            self.report["uncovered"] = [item for item in self.report["uncovered"]
                                        if item != "native_ha_snapshot_export_restore"]

    def update_cohort_counts(self):
        self.report["separate_direct_lan_passed_count"] = sum(
            row["passed"] is True and row["case"] in direct.DIRECT_CHECKS for row in self.checks)
        self.report["separate_official_history_passed_count"] = sum(
            row["passed"] is True and row["case"] in EXTRA_CHECKS for row in self.checks)

    def cleanup(self):
        result = super().cleanup()
        self.update_cohort_counts()
        self.checkpoint()
        return result

    def verify_inputs(self):
        return all(digest(exact.private_read(Path(path))) == expected for path, expected in self.inputs.items())

    def prepare(self):
        self.check("official271_source_evidence_bound", self.verify_inputs(), versions=19,
                   live_payload_bytes=34 * exact.MIB, source_api_response_count=19)
        super().prepare()
        self.ca_sha256 = base.sha256_file(self.work / "ca.crt")

    def provision_fixture_kv2(self, node):
        result = super().provision_fixture_kv2(node)
        status, _ = self.request(node, "POST", "sys/mounts/" + MOUNT,
                                 {"type": "kv", "options": {"version": "2"}})
        self.check("official271_mount_created_before_activation", status == 204)
        return result

    def wire(self, node, method, path, body=None, *, archive_in=None, archive_out=None):
        need(node in self.nodes and node.api_connect_port is None, "exact_direct_node")
        raw = b"" if body is None else exact.canonical(body)
        if archive_in is not None:
            raw = exact.private_read(archive_in)
        mutation = method not in ("GET", "LIST")
        intent = begin_binary(self.recovery, node, method, path, raw, self.stage, 15) if mutation else None
        started, process, outcome, recorded = time.monotonic(), None, None, False
        packet = {"ip": node.ip, "port": node.api_port, "ca_file": str(self.work / "ca.crt"),
            "ca_sha256": self.ca_sha256, "leaf_sha256": self.peers[str(node.node_id)]["certificate_sha256"],
            "token": self.root_token, "method": method, "path": path,
            "body": None if body is None else base64.b64encode(raw).decode(),
            "archive_in": None if archive_in is None else str(archive_in),
            "archive_sha256": None if archive_in is None else digest(raw),
            "archive_out": None if archive_out is None else str(archive_out)}
        try:
            process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(WIRE)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, errors = process.communicate(json.dumps(packet).encode(),
                timeout=max(0, started + 15 - time.monotonic()))
            need(process.returncode == 0 and not errors and len(output) <= exact.JSON_BYTES + 1024,
                 "wire_original_child_failed")
            header, separator, raw_response = output.partition(b"\n")
            need(separator and len(header) <= 1024, "wire_framing")
            outcome = json.loads(header)
            need(type(outcome.get("status")) is int and 100 <= outcome["status"] <= 599
                 and outcome.get("leaf_sha256") == packet["leaf_sha256"], "wire_response_binding")
            response = exact.decode(raw_response) if raw_response else {}
            if "archive_sha256" in outcome:
                response = outcome
            need(time.monotonic() < started + 15, "original_http_deadline")
            if mutation:
                recorded = True
                self.recovery.outcome(intent, status=outcome["status"], response=outcome,
                                      elapsed=time.monotonic() - started, timeout=15)
                self.report["official_chain_mutations"].append({"sequence": intent,
                    "node": node.node_id, "method": method, "path": path, "status": outcome["status"],
                    "request_body_sha256": digest(raw), "outcome": "response_received", "retried": False})
            return outcome["status"], response
        except BaseException as error:
            if mutation and not recorded:
                recorded = True
                self.recovery.outcome(intent, elapsed=time.monotonic() - started, timeout=15, error=error)
                self.report["official_chain_mutations"].append({"sequence": intent,
                    "node": node.node_id, "method": method, "path": path,
                    "status": None if outcome is None else outcome.get("status"),
                    "outcome": "unknown_effect", "retried": False})
            raise
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            waited = process is None or process.poll() is not None
            if mutation:
                for row in self.report["official_chain_mutations"]:
                    if row["sequence"] == intent:
                        row["owned_leaf_wait_completed"] = waited
            need(waited, "original_wire_child_not_reaped")
            self.checkpoint()

    def observe_history(self, node):
        class Endpoint:
            def call(_, method, path):
                return self.wire(node, method, path.replace("secret/", MOUNT + "/", 1))
        observed = exact.observations(Endpoint(), 17)
        self.report["official_history_observations"].append({"stage": self.stage,
            "node": node.node_id, "history_sha256": digest(exact.canonical(observed)),
            "versions": [{"version": int(key), "status": row["status"],
                          "data_sha256": digest(exact.canonical(row["data"]))}
                         for key, row in observed["versions"].items()]})
        return observed

    def verify_history(self, nodes, expected=None):
        expected = self.original if expected is None else expected
        for node in nodes:
            need(exact.same_json_tokens(self.observe_history(node), expected), "all_version_history_exact")

    def observe_effect(self, observation, **details):
        row = self.report["official_chain_mutations"][-1]
        need(row["outcome"] == "response_received" and "effect_observation" not in row,
             "effect_requires_single_received_mutation")
        receipt = {"schema": "heptabao.official-history-effect-observation.v1",
                   "fixture_run_id": self.run_id, "sequence": row["sequence"],
                   "observation": observation, "automatic_retry": False, **details}
        self.recovery._write(f"mutation-{row['sequence']:05d}.effect.json", receipt)
        row["effect_observation"] = observation
        self.checkpoint()

    def verify_raw_history(self, node, phase):
        destination = self.work / ("official271-" + phase + "-lossless.json")
        status, receipt = self.wire(node, "GET", EXPORT, archive_out=destination)
        raw = exact.private_read(destination, 64 * exact.MIB)
        need(status == 200 and receipt.get("archive_bytes") == len(raw)
             and receipt.get("archive_sha256") == digest(raw), "raw_export_same_response")
        observed = exact.decode(raw)
        expected = exact.decode(self.bundle)
        need(exact.same_json_tokens(observed, expected), "raw_export_all_retained_versions")
        self.report.setdefault("official_raw_history_observations", []).append({
            "phase": phase, "node": node.node_id, "body_bytes": len(raw), "body_sha256": digest(raw),
            "canonical_sha256": digest(exact.canonical(observed)),
            "versions": [{"version": int(key), "retained_record_sha256": digest(exact.canonical(value))}
                         for key, value in observed["entries"]["history"]["versions"].items()]})
        self.check("official271_" + phase + "_raw_history_exact", True, versions=19)

    def import_once(self, node):
        need(self.verify_inputs() and base.sha256_file(self.work / "ca.crt") == self.ca_sha256,
             "import_inputs_unchanged")
        client = self.migration.Client(node.api_origin, self.root_token,
            ca_file=str(self.work / "ca.crt"), end=time.monotonic() + self.migration.DEADLINE)
        intent = begin_binary(self.recovery, node, "POST", IMPORT_ROUTE, self.bundle, self.stage, 5)
        started, succeeded = time.monotonic(), False
        try:
            # admit_source already checked this exact immutable complete bundle.
            # Use the actual CLI's one-request client directly, so both the
            # durable ledger and Client measure the same original 5-second I/O.
            result = client.request("POST", IMPORT_ROUTE, self.bundle, native_import=True)
            need(result is None, "native_large_204_without_body")
            succeeded = True
        finally:
            lifecycle = client.last_request_lifecycle or {}
            status = lifecycle.get("status")
            unknown = lifecycle.get("outcome") != "response_received"
            self.recovery.outcome(intent, status=status, response={"status": status},
                elapsed=time.monotonic() - started, timeout=5,
                error=RuntimeError("unknown") if unknown else None)
            self.report["official_chain_mutations"].append({"sequence": intent, "node": node.node_id,
                "method": "POST", "path": IMPORT_ROUTE, "status": status,
                "outcome": "unknown_effect" if unknown else "response_received", "retried": False,
                "original_http_seconds": 5, "native_large_owned_leaf": lifecycle})
            self.checkpoint()
        self.check("official271_native_large_import_once", succeeded and status == 204
                   and lifecycle.get("original_wait_completed") is True)

    def finish_application(self, leader):
        # This executes the original cleanup and integrity checks before adding
        # another 34 MiB history. Their names and denominator remain untouched.
        super().finish_application(leader)
        self.stage = "official271_native_large_import"
        self.check("official271_pristine_before_import", self.wire(
            leader, "GET", MOUNT + "/metadata/history")[0] == 404)
        self.import_once(leader)
        capacity = self.capacity(leader)
        self.check("official271_capacity_full34", capacity.get("native_kv2_logical_payload_bytes", 0) >= 34 * exact.MIB
                   and capacity.get("state_storage_format") == "heptabao-state-records-v6")
        self.verify_history(self.nodes)
        self.check("official271_import_all_hosts_readindex", True, hosts=3, versions_per_host=19)
        self.verify_raw_history(leader, "import")
        self.observe_effect("all_19_api_versions_and_exact_raw_history_imported", observed_hosts=3,
                            history_sha256=digest(exact.canonical(self.original)))
        self.stage = "official271_snapshot_rollback"
        archive = self.work / "official271-native-ha.tar.gz"
        status, receipt = self.wire(leader, "GET", SNAPSHOT, archive_out=archive)
        self.check("official271_snapshot_download_once", status == 200
                   and receipt.get("archive_sha256") == base.sha256_file(archive))
        envelope = archive_contract(archive)
        self.report["official_snapshot"] = {**receipt, "contract": envelope}
        self.check("official271_snapshot_v6_ha_contract", True)
        mutation = {"after_snapshot": True}
        status, _ = self.wire(leader, "POST", MOUNT + "/data/history",
                              {"data": mutation, "options": {"cas": 19}})
        for node in self.nodes:
            read_status, changed = self.wire(node, "GET", MOUNT + "/data/history")
            need(read_status == 200 and changed["data"]["metadata"]["version"] == 20
                 and changed["data"]["data"] == mutation, "post_snapshot_effect_observed")
        self.check("official271_post_snapshot_mutation_once", status == 200)
        self.observe_effect("version_20_visible_on_all_hosts", observed_hosts=3,
                            payload_sha256=digest(exact.canonical(changed["data"]["data"])))
        before_capacity = self.capacity(leader)
        previous_generation = before_capacity["generation"]
        raft_before = base.capture_committed_frontier(self.context, leader)
        status, publication = self.wire(leader, "POST", SNAPSHOT, archive_in=archive)
        self.check("official271_snapshot_restore_once", status == 200)
        data = publication.get("data", {})
        after_capacity = self.capacity(leader)
        raft_after = base.capture_committed_frontier(self.context, leader)
        self.check("official271_restore_publication_advanced",
            all(type(data.get(key)) is int for key in ("imported_generation", "previous_local_generation",
                                                       "published_local_generation", "replay_epoch"))
            and data["imported_generation"] == envelope["generation"]
            # Mandatory Auth clock publications may advance between the read
            # and restore admission. Compare monotonic frontiers, not equality
            # between two different admitted capacity generations.
            and data["previous_local_generation"] >= previous_generation
            and data["published_local_generation"] > data["previous_local_generation"]
            and data["replay_epoch"] == before_capacity["replay_epoch"] + 1
            and after_capacity["replay_epoch"] == data["replay_epoch"]
            and after_capacity["generation"] >= data["published_local_generation"]
            and raft_after > raft_before
            and data.get("cluster_coordinated") is True and not publication.get("auth")
            and not publication.get("wrap_info"),
            publication=data, before_capacity_generation=previous_generation,
            raft_frontier_before=raft_before, raft_frontier_after=raft_after)
        self.verify_history(self.nodes)
        self.check("official271_restore_all_hosts_readindex", True, rolled_back_version=20)
        self.verify_raw_history(leader, "restore")
        self.observe_effect("version_20_rolled_back_all_19_api_and_raw_versions_restored", observed_hosts=3,
                            history_sha256=digest(exact.canonical(self.original)))
        self.stage = "official271_leader_kill_cold_rejoin"
        old = leader
        self.check("official271_leader_stopped", self.stop(old) is not None, node=old.node_id)
        survivors = [node for node in self.nodes if node != old]
        time.sleep(6)
        leader = self.leader(survivors, previous=old)
        self.check("official271_successor_elected", leader != old, node=leader.node_id)
        self.verify_history(survivors)
        self.check("official271_successor_history_exact", True)
        frontier = base.capture_committed_frontier(self.context, leader)
        self.start(old)
        self.unseal(old)
        base.wait_local_frontier(self.context, old, frontier, seconds=60, record=self.event)
        self.verify_history([old])
        self.check("official271_old_leader_cold_rejoin_readindex", True)
        self.stage = "official271_all_hosts_cold_restart"
        frontier = base.capture_committed_frontier(self.context, leader)
        for node in reversed(self.nodes):
            self.stop(node)
        for node in self.nodes[1:] + self.nodes[:1]:
            self.start(node)
            base.wait_listener(self.context, node)
        self.wait_sealed_leader(self.nodes)
        for node in self.nodes:
            self.unseal(node)
        leader = self.leader(self.nodes)
        for node in self.nodes:
            base.wait_local_frontier(self.context, node, frontier, seconds=60, record=self.event)
        self.check("official271_all_nodes_cold_restart", True)
        self.verify_history(self.nodes)
        self.check("official271_cold_all_hosts_history_exact", True)
        self.verify_raw_history(leader, "cold")
        self.stage = "official271_retirement_and_cas"
        status, _ = self.wire(leader, "POST", MOUNT + "/undelete/history", {"versions": [1]})
        read_status, restored = self.wire(leader, "GET", MOUNT + "/data/history?version=1")
        self.check("official271_soft_deleted_payload_undelete_exact", status == 204 and read_status == 200
                   and exact.same_json_tokens(restored["data"]["data"], self.api_payloads["1"])
                   and restored["data"]["metadata"]["deletion_time"] == "")
        self.observe_effect("soft_deleted_version_1_payload_restored", version=1,
                            payload_sha256=digest(exact.canonical(restored["data"]["data"])))
        status, _ = self.wire(leader, "POST", MOUNT + "/undelete/history", {"versions": [2]})
        read_status, destroyed = self.wire(leader, "GET", MOUNT + "/data/history?version=2")
        self.check("official271_destroyed_payload_remains_absent", status == 204 and read_status == 404
                   and destroyed["data"]["data"] is None and destroyed["data"]["metadata"]["destroyed"] is True)
        self.observe_effect("destroyed_version_2_retains_tombstone_and_no_payload", version=2)
        before = self.observe_history(leader)
        status, _ = self.wire(leader, "POST", MOUNT + "/data/history",
                              {"data": {"must_not_commit": True}, "options": {"cas": 0}})
        self.check("official271_data_cas_denied_without_effect", status == 400
                   and exact.same_json_tokens(self.observe_history(leader), before))
        self.observe_effect("bad_data_cas_history_unchanged", history_sha256=digest(exact.canonical(before)))
        status, _ = self.wire(leader, "POST", MOUNT + "/metadata/history",
                              {"custom_metadata": {"must_not_commit": "true"}, "metadata_cas": 0})
        self.check("official271_metadata_cas_denied_without_effect", status == 400
                   and exact.same_json_tokens(self.observe_history(leader), before))
        self.observe_effect("bad_metadata_cas_history_unchanged", history_sha256=digest(exact.canonical(before)))
        counter = before["metadata"]["current_metadata_version"]
        status, _ = self.wire(leader, "POST", MOUNT + "/metadata/history",
                              {"custom_metadata": {"revision": "physical-ha"}, "metadata_cas": counter})
        after = self.observe_history(leader)
        self.check("official271_metadata_cas_counter_exact", status == 204
                   and after["metadata"]["current_metadata_version"] == counter + 1
                   and after["metadata"]["custom_metadata"] == {"revision": "physical-ha"})
        self.verify_history(self.nodes, after)
        self.observe_effect("metadata_cas_counter_and_all_host_history_observed", observed_hosts=3,
                            current_metadata_version=counter + 1, history_sha256=digest(exact.canonical(after)))
        status, _ = self.wire(leader, "DELETE", MOUNT + "/metadata/history")
        self.check("official271_history_cleanup_once", status == 204 and all(
            self.wire(node, "GET", MOUNT + "/metadata/history")[0] == 404 for node in self.nodes))
        self.observe_effect("owned_history_metadata_absent_on_all_hosts", observed_hosts=3)
        self.check("official271_mutation_effects_observed", all(
            row["outcome"] == "response_received" and row["retried"] is False and row.get("effect_observation")
            for row in self.report["official_chain_mutations"])
            and self.recovery.public_receipt["unknown_transport_outcomes"] == 0)
        self.check("official271_inputs_and_binaries_unchanged", self.verify_inputs()
            and all(base.sha256_file(Path(path)) == value for path, value in self.source_files.items())
            and all(base.remote_binary_digest(node) == self.expected[str(node.node_id)] for node in self.nodes)
            and base.sha256_file(self.work / "ca.crt") == self.ca_sha256)
        self.check("official271_report_excludes_runtime_secrets", base.report_is_secret_safe(self.report, self.secrets()))


def parsed_arguments(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--official-full34-root", required=True, type=Path)
    parser.add_argument("--official-full34-summary-sha256", required=True)
    extra, rest = parser.parse_known_args(argv)
    need(re.fullmatch(r"[0-9a-f]{64}", extra.official_full34_summary_sha256) is not None, "receipt_sha256")
    # Source admission happens before any fixture effect or work-root creation.
    admit_source(extra.official_full34_root, extra.official_full34_summary_sha256)
    args, *others = direct.parsed_arguments(rest)
    args.official_full34_root = extra.official_full34_root
    args.official_full34_summary_sha256 = extra.official_full34_summary_sha256
    return args, *others


def main(argv=None):
    return native.execute_fixture(*parsed_arguments(argv), run_type=OfficialHistoryRun)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
