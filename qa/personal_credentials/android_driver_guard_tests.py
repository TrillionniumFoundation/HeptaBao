#!/usr/bin/env python3
"""Local fault regressions for the device driver's restore guards, never device QA.

No ADB command runs. These tests check unknown-query and malformed-journal paths
that otherwise could produce false cleanup evidence or authorize a wrong removal.
"""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


parser = argparse.ArgumentParser()
parser.add_argument("--driver", type=Path, default=Path(__file__).with_name("android_live.py"))
args, unittest_args = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("android_live_under_test", args.driver)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def journal():
    return {"schema": 2, "device_serial_sha256": driver.DEVICE_SHA256,
            "service_written": driver.SERVICE, "previous_autofill_service": "null",
            "setting_write_attempted": False, "initial_absent": {driver.GOOD: True},
            "owned_packages": {driver.GOOD: ["a" * 64]}, "created_unix_ns": 1}


class FakeDevice:
    def __init__(self, current="a" * 64):
        self.current = current
        self.calls = []

    def package_hash(self, package):
        self.calls.append(("package_hash", package))
        return self.current

    def adb_command(self, *args, **kwargs):
        self.calls.append(args)
        if args == ("uninstall", driver.GOOD): self.current = None
        else: raise AssertionError("unexpected_device_operation")


class RestoreGuardTests(unittest.TestCase):
    def device_for_query(self):
        device = driver.Device.__new__(driver.Device)
        device.adb = "no-real-adb"
        device.serial = "synthetic-stub-serial"
        return device

    def test_nonzero_empty_query_is_unknown(self):
        result = subprocess.CompletedProcess([], 1, b"", b"synthetic query failure")
        with patch.object(driver.subprocess, "run", return_value=result):
            with self.assertRaises(driver.Failed): self.device_for_query().package_hash(driver.GOOD)

    def test_zero_error_text_query_is_unknown(self):
        result = subprocess.CompletedProcess([], 0, b"Error: service unavailable\n", b"")
        with patch.object(driver.subprocess, "run", return_value=result):
            with self.assertRaises(driver.Failed): self.device_for_query().package_hash(driver.GOOD)

    def test_successful_exact_absence(self):
        # A similarly named package is not the requested fixed package.
        result = subprocess.CompletedProcess([], 0, ("package:" + driver.GOOD + ".other\n").encode(), b"")
        with patch.object(driver.subprocess, "run", return_value=result):
            self.assertIsNone(self.device_for_query().package_hash(driver.GOOD))

    def test_malformed_digest_string_never_authorizes_removal(self):
        value = journal(); value["owned_packages"][driver.GOOD] = "prefix" + "a" * 64 + "suffix"
        device = FakeDevice()
        with patch.object(driver, "atomic_json"):
            with self.assertRaises(driver.Failed): driver.restore(device, value, Path("unused"))
        self.assertEqual(device.calls, [])

    def test_missing_initial_absence_never_authorizes_removal(self):
        value = journal(); value["initial_absent"] = {}
        device = FakeDevice()
        with patch.object(driver, "atomic_json"):
            with self.assertRaises(driver.Failed): driver.restore(device, value, Path("unused"))
        self.assertEqual(device.calls, [])

    def test_non_boolean_setting_intent_rejected(self):
        value = journal(); value["setting_write_attempted"] = "false"
        with self.assertRaises(driver.Failed): driver.validate_journal(value)

    def test_unknown_current_artifact_preserved(self):
        device = FakeDevice("b" * 64)
        with patch.object(driver, "atomic_json"):
            _, cleanup = driver.restore(device, journal(), Path("unused"))
        self.assertEqual(cleanup[driver.GOOD], "unknown_artifact_preserved")
        self.assertFalse(any(call[0] == "uninstall" for call in device.calls))

    def test_owned_attempt_current_hash_can_be_cleaned(self):
        device = FakeDevice()
        with patch.object(driver, "atomic_json"):
            _, cleanup = driver.restore(device, journal(), Path("unused"))
        self.assertEqual(cleanup[driver.GOOD], "removed_owned_package")
        self.assertIn(("uninstall", driver.GOOD), device.calls)


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__)), *unittest_args])
