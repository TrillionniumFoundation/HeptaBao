"""Durable private custody and dispatch intents for synthetic HA fixtures.

This module never sends a request, resumes a run, or retries an operation.
An intent without an outcome is deliberately an unknown outcome. HTTP errors
and transport failures never establish that a storage mutation had no effect.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


class FixtureRecoveryLedger:
    def __init__(self, work, run_id, source_commit, source_tree, nodes,
                 expected_binaries, *, error_type=RuntimeError):
        self.error_type = error_type
        self.work = Path(work)
        self.work_identity = self._directory(self.work)
        self.root = self.work / "private-recovery"
        self.root.mkdir(mode=0o700)
        self.root_identity = self._directory(self.root)
        self.run_id = run_id
        self.nodes = {node.node_id: node for node in nodes}
        self.sequence = 0
        self.initialization_attempted = False
        self.credential_digest = None
        self.public_receipt = {
            "schema": "heptabao.synthetic-fixture-recovery-public.v1",
            "relative_root": "private-recovery", "synthetic_only": True,
            "initialization_custody_saved": False, "mutation_intents": 0,
            "mutation_responses": 0, "unknown_transport_outcomes": 0,
            "automatic_resume_or_retry": False, "secret_values_emitted": False,
        }
        self.session = {
            "schema": "heptabao.synthetic-fixture-recovery-session.v1",
            "fixture_run_id": run_id, "source_commit": source_commit,
            "source_tree": source_tree, "synthetic_only": True,
            "production_authority": False, "controller_root": str(self.work),
            "controller_device": self.work_identity[0],
            "controller_inode": self.work_identity[1],
            "expected_node_binary_sha256": expected_binaries,
            "nodes": {str(node.node_id): {"alias": node.alias, "root": node.root,
                      "api_origin": node.api_origin} for node in nodes},
        }
        self._write("session.json", self.session)
        self._sync_directory(self.work)

    def _require(self, condition, code):
        if not condition:
            raise self.error_type(code)

    def _directory(self, path):
        entry = path.lstat()
        self._require(path.resolve(strict=True) == path and stat.S_ISDIR(entry.st_mode)
                      and entry.st_uid == os.getuid() and not entry.st_mode & 0o077,
                      "fixture_recovery_directory_not_private")
        return entry.st_dev, entry.st_ino

    def _sync_directory(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _open_root(self):
        self._require(self._directory(self.work) == self.work_identity
                      and self._directory(self.root) == self.root_identity,
                      "fixture_recovery_directory_identity_changed")
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        entry = os.fstat(descriptor)
        if (entry.st_dev, entry.st_ino) != self.root_identity:
            os.close(descriptor)
            raise self.error_type("fixture_recovery_directory_identity_changed")
        return descriptor

    def _write(self, name, value):
        self._require(Path(name).name == name, "fixture_recovery_invalid_name")
        raw = canonical(value) + b"\n"
        descriptor = self._open_root()
        try:
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=descriptor)
            with os.fdopen(target, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return hashlib.sha256(raw).hexdigest()

    def _verify_custody(self):
        self._require(self.credential_digest is not None,
                      "fixture_recovery_credentials_required_before_mutation")
        descriptor = self._open_root()
        try:
            target = os.open("credentials.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=descriptor)
            with os.fdopen(target, "rb") as stream:
                before = os.fstat(stream.fileno())
                self._require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                              and before.st_nlink == 1 and not before.st_mode & 0o077
                              and before.st_size <= 65536,
                              "fixture_recovery_credentials_not_private")
                raw = stream.read(65537)
                after = os.fstat(stream.fileno())
                named = os.stat("credentials.json", dir_fd=descriptor, follow_symlinks=False)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                         item.st_mtime_ns, item.st_ctime_ns)
                self._require(identity(before) == identity(after) == identity(named)
                              and len(raw) == before.st_size
                              and hashlib.sha256(raw).hexdigest() == self.credential_digest,
                              "fixture_recovery_credentials_changed")
        finally:
            os.close(descriptor)

    def preserve_initialization(self, node, response):
        root_token = response.get("root_token") if isinstance(response, dict) else None
        keys = response.get("keys_base64") if isinstance(response, dict) else None
        self._require(isinstance(root_token, str) and 0 < len(root_token) <= 16384
                      and isinstance(keys, list) and len(keys) == 1
                      and isinstance(keys[0], str) and 0 < len(keys[0]) <= 16384,
                      "fixture_recovery_initialization_response_invalid")
        digest = self._write("credentials.json", {
            "schema": "heptabao.synthetic-fixture-recovery-credentials.v1",
            "fixture_run_id": self.run_id, "seed_node_id": node.node_id,
            "synthetic_only": True, "production_authority": False,
            "root_token": root_token, "unseal_key": keys[0],
        })
        self.credential_digest = digest
        self._verify_custody()
        self.public_receipt["initialization_custody_saved"] = True

    def begin(self, node, method, route, body, *, stage, timeout):
        self._require(self.nodes.get(node.node_id) == node,
                      "fixture_recovery_node_binding_changed")
        initialization = method == "POST" and route == "sys/init"
        if initialization:
            self._require(not self.initialization_attempted,
                          "fixture_recovery_initialization_must_not_repeat")
            self._require(not (self.root / "credentials.json").exists()
                          and not (self.root / "credentials.json").is_symlink(),
                          "fixture_recovery_credentials_output_must_be_new")
        else:
            self._verify_custody()
        sequence = self.sequence + 1
        intent = {
            "schema": "heptabao.synthetic-fixture-mutation-intent.v1",
            "fixture_run_id": self.run_id, "sequence": sequence,
            "node_id": node.node_id, "stage": stage, "method": method, "route": route,
            "recorded_before_dispatch_unix_seconds": time.time(),
            "original_http_budget_seconds": timeout,
            "request_body_sha256": hashlib.sha256(canonical(body)).hexdigest(),
            "dispatch_attempts_allowed": 1, "automatic_retry": False,
        }
        if isinstance(body, dict) and isinstance(body.get("data"), dict):
            intent["expected_data_sha256"] = hashlib.sha256(canonical(body["data"])).hexdigest()
        options = body.get("options") if isinstance(body, dict) else None
        cas = options.get("cas") if isinstance(options, dict) else None
        if type(cas) is int and cas >= 0:
            intent.update(expected_cas=cas, expected_version=cas + 1)
        self._write(f"mutation-{sequence:05d}.intent.json", intent)
        self.sequence = sequence
        self.initialization_attempted |= initialization
        self.public_receipt["mutation_intents"] += 1
        return sequence

    def outcome(self, sequence, *, status=None, response=None, elapsed, timeout, error=None):
        row = {
            "schema": "heptabao.synthetic-fixture-mutation-outcome.v1",
            "fixture_run_id": self.run_id, "sequence": sequence,
            "transport_returned": error is None, "http_status": status,
            "elapsed_ms": round(elapsed * 1000, 3),
            "original_http_budget_seconds": timeout, "within_original_budget": elapsed <= timeout,
            "storage_commit_outcome": "not_inferred_from_http_or_transport",
            "automatic_retry": False,
        }
        if error is not None:
            row["failure_type"] = type(error).__name__
            row["dispatch_outcome"] = "unknown"
        else:
            row["response_sha256"] = hashlib.sha256(canonical(response)).hexdigest()
            data = response.get("data") if isinstance(response, dict) else None
            if isinstance(data, dict) and type(data.get("version")) is int:
                row["response_data_version"] = data["version"]
        self._write(f"mutation-{sequence:05d}.outcome.json", row)
        if error is None:
            self.public_receipt["mutation_responses"] += 1
        else:
            self.public_receipt["unknown_transport_outcomes"] += 1
