"""Fault-boundary tests for auth-mount recreation."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bao_http import BaoError, Response
from migrate_auth_mount import Checkpoint, read_source_record, transfer


def record():
    return {
        "mount": "migration-approle",
        "type": "approle",
        "description": "migration boundary",
        "default_lease_ttl": 120,
        "max_lease_ttl": 300,
    }


class FaultTarget:
    namespace = ""

    def __init__(self, fault=None):
        self.fault = fault
        self.descriptor = None
        self.tune = None
        self.create_writes = 0
        self.tune_writes = 0

    def request(self, method, path, payload=None):
        if method == "GET" and path == "/v1/sys/auth/migration-approle":
            return (
                Response(200, {"data": dict(self.descriptor)})
                if self.descriptor is not None
                else Response(404, {})
            )
        if method == "GET" and path == "/v1/sys/auth/migration-approle/tune":
            return (
                Response(200, {"data": dict(self.tune)})
                if self.tune is not None
                else Response(404, {})
            )
        if method == "POST" and path == "/v1/sys/auth/migration-approle":
            self.create_writes += 1
            if self.fault == "create_before_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            self.descriptor = {
                "type": payload["type"],
                "description": payload["description"],
                "accessor": "auth_target_1",
                "revision": 1,
            }
            self.tune = {
                "description": payload["description"],
                "default_lease_ttl": 0,
                "max_lease_ttl": 0,
                "revision": 1,
            }
            if self.fault == "create_after_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            return Response(204, {})
        if (
            method == "POST"
            and path == "/v1/sys/auth/migration-approle/tune"
        ):
            self.tune_writes += 1
            if self.fault == "tune_before_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            changed = any(
                self.tune.get(key) != payload[key]
                for key in (
                    "description",
                    "default_lease_ttl",
                    "max_lease_ttl",
                )
            )
            self.tune.update(
                description=payload["description"],
                default_lease_ttl=payload["default_lease_ttl"],
                max_lease_ttl=payload["max_lease_ttl"],
            )
            if changed:
                self.descriptor["description"] = payload["description"]
                self.descriptor["revision"] += 1
                self.tune["revision"] = self.descriptor["revision"]
            if self.fault == "tune_after_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            return Response(204, {})
        return Response(404, {})


class SourceFixture:
    def __init__(self, lockout_disable):
        self.lockout_disable = lockout_disable

    def request(self, method, path, payload=None):
        if method == "GET" and path == "/v1/sys/auth/migration-approle":
            return Response(
                200,
                {
                    "data": {
                        "type": "approle",
                        "description": "migration boundary",
                        "local": False,
                        "seal_wrap": False,
                        "options": {},
                        "accessor": "auth_source",
                    }
                },
            )
        if method == "GET" and path == "/v1/sys/auth/migration-approle/tune":
            return Response(
                200,
                {
                    "data": {
                        "description": "migration boundary",
                        "default_lease_ttl": 120,
                        "max_lease_ttl": 300,
                        "force_no_cache": False,
                        "token_type": "default-service",
                        "user_lockout_config": {
                            "lockout_disable": self.lockout_disable,
                            "lockout_threshold": "5",
                            "lockout_duration": "15m",
                            "lockout_counter_reset": "15m",
                        },
                    }
                },
            )
        return Response(404, {})


class AuthMountMigrationTests(unittest.TestCase):
    def checkpoint(self, directory, binding=None):
        return Checkpoint(
            Path(directory) / "checkpoint.json",
            {"binding": "one"} if binding is None else binding,
        )

    def test_committed_create_with_lost_ack_reconciles_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget("create_after_effect")
            checkpoint = self.checkpoint(directory)
            with self.assertRaisesRegex(
                BaoError, "transport_outcome_unknown"
            ):
                transfer(target, record(), checkpoint)
            self.assertEqual(target.create_writes, 1)
            self.assertEqual(
                transfer(target, record(), self.checkpoint(directory)),
                "copied_and_verified",
            )
            self.assertEqual(target.create_writes, 1)
            self.assertEqual(target.tune_writes, 1)
            self.assertEqual(
                transfer(target, record(), self.checkpoint(directory)),
                "already_verified",
            )
            self.assertEqual(target.create_writes, 1)
            self.assertEqual(target.tune_writes, 1)

    def test_committed_tune_with_lost_ack_reconciles_without_second_tune(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget("tune_after_effect")
            with self.assertRaisesRegex(
                BaoError, "transport_outcome_unknown"
            ):
                transfer(target, record(), self.checkpoint(directory))
            self.assertEqual(target.create_writes, 1)
            self.assertEqual(target.tune_writes, 1)
            self.assertEqual(
                transfer(target, record(), self.checkpoint(directory)),
                "copied_and_verified",
            )
            self.assertEqual(target.tune_writes, 1)
            self.assertEqual(target.tune["default_lease_ttl"], 120)
            self.assertEqual(target.tune["max_lease_ttl"], 300)

    def test_unknown_create_with_no_effect_is_never_blindly_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget("create_before_effect")
            with self.assertRaisesRegex(
                BaoError, "transport_outcome_unknown"
            ):
                transfer(target, record(), self.checkpoint(directory))
            with self.assertRaisesRegex(
                BaoError, "authoritative_reconciliation"
            ):
                transfer(target, record(), self.checkpoint(directory))
            self.assertEqual(target.create_writes, 1)
            self.assertIsNone(target.descriptor)

    def test_unknown_tune_with_no_effect_requires_manual_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget("tune_before_effect")
            with self.assertRaisesRegex(
                BaoError, "transport_outcome_unknown"
            ):
                transfer(target, record(), self.checkpoint(directory))
            self.assertEqual(target.create_writes, 1)
            self.assertEqual(target.tune_writes, 1)
            with self.assertRaisesRegex(
                BaoError, "target_auth_mount_tune_mismatch"
            ):
                transfer(target, record(), self.checkpoint(directory))
            self.assertEqual(target.tune_writes, 1)

    def test_existing_unowned_target_mount_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget()
            target.descriptor = {
                "type": "approle",
                "description": "migration boundary",
                "accessor": "auth_preexisting",
                "revision": 1,
            }
            target.tune = {
                "description": "migration boundary",
                "default_lease_ttl": 120,
                "max_lease_ttl": 300,
                "revision": 1,
            }
            with self.assertRaisesRegex(
                BaoError, "exists_without_owned_checkpoint"
            ):
                transfer(target, record(), self.checkpoint(directory))
            self.assertEqual(target.create_writes, 0)

    def test_source_lockout_must_be_explicitly_disabled(self):
        with self.assertRaisesRegex(
            BaoError, "lockout_must_be_explicitly_disabled"
        ):
            read_source_record(SourceFixture(False), "migration-approle")
        accepted = read_source_record(
            SourceFixture(True), "migration-approle"
        )
        self.assertTrue(accepted["source_user_lockout_disabled"])

    def test_checkpoint_binding_cannot_change(self):
        with tempfile.TemporaryDirectory() as directory:
            self.checkpoint(directory, {"target": "one"})
            with self.assertRaisesRegex(
                BaoError, "context_mismatch"
            ):
                self.checkpoint(directory, {"target": "two"})


if __name__ == "__main__":
    unittest.main()
