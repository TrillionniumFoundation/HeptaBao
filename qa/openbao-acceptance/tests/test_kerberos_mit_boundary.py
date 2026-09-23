"""Harness resource/coverage guards; fake FFI here is not native KDC evidence."""
import base64
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kerberos_mit_live as fixture


class FakeGss:
    def __init__(self, payload=b"synthetic AP-REQ", major=0, import_status=0):
        self.storage = ctypes.create_string_buffer(payload)
        self.payload = payload
        self.major, self.import_status = major, import_status
        self.gss_import_name = Mock(side_effect=self.import_name)
        self.gss_init_sec_context = Mock(side_effect=self.init_context)
        self.gss_release_buffer = Mock(return_value=0)
        self.gss_release_name = Mock(return_value=0)
        self.gss_delete_sec_context = Mock(return_value=0)

    def import_name(self, *_args):
        ctypes.cast(_args[3], ctypes.POINTER(ctypes.c_void_p))[0] = 1
        return self.import_status

    def init_context(self, *args):
        ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p))[0] = 2
        output = ctypes.cast(args[10], ctypes.POINTER(fixture.GssBuffer)).contents
        output.length = len(self.payload)
        output.value = ctypes.cast(self.storage, ctypes.c_void_p)
        return self.major


class KerberosBoundaryTests(unittest.TestCase):
    def invoke(self, library):
        with patch("kerberos_mit_live.ctypes.util.find_library", return_value="fixture"), \
             patch("kerberos_mit_live.ctypes.CDLL", return_value=library):
            return fixture.negotiate_header(None, {"KRB5CCNAME":"FILE:fixture-only"})

    def test_native_objects_and_cache_selector_are_released_after_success(self):
        library = FakeGss()
        with patch.dict(os.environ, {"KRB5CCNAME":"FILE:original"}):
            result = self.invoke(library)
            self.assertEqual(os.environ["KRB5CCNAME"], "FILE:original")
        self.assertEqual(result, "Negotiate " + base64.b64encode(library.payload).decode())
        library.gss_release_buffer.assert_called_once()
        library.gss_release_name.assert_called_once()
        library.gss_delete_sec_context.assert_called_once()

    def test_partial_failure_and_oversized_output_release_native_objects(self):
        for library in (FakeGss(major=1), FakeGss(payload=b"x" * (128 * 1024 + 1))):
            with self.subTest(length=len(library.payload), major=library.major):
                with self.assertRaisesRegex(fixture.FixtureFailure, "^gss_ap_req_creation$"):
                    self.invoke(library)
                library.gss_release_buffer.assert_called_once()
                library.gss_release_name.assert_called_once()
                library.gss_delete_sec_context.assert_called_once()

    def test_failed_name_import_is_freed_without_creating_a_context(self):
        library = FakeGss(import_status=1)
        with self.assertRaisesRegex(fixture.FixtureFailure, "^gss_target_import$"):
            self.invoke(library)
        library.gss_release_name.assert_called_once()
        library.gss_init_sec_context.assert_not_called()
        library.gss_delete_sec_context.assert_not_called()

    def test_kdc_configuration_binds_both_transports_to_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            _, config, _, _ = fixture.kerberos_files(Path(directory), 12345)
            text = config.read_text()
            self.assertIn("kdc_listen = 127.0.0.1:12345", text)
            self.assertIn("kdc_tcp_listen = 127.0.0.1:12345", text)
            self.assertNotIn("kdc_ports =", text)
            self.assertNotIn("kdc_tcp_ports =", text)

    def test_failure_stage_cannot_reflect_arbitrary_provider_text(self):
        error = fixture.FixtureFailure("provider stderr: secret credential")
        self.assertEqual(error.stage, "unclassified_failure")
        self.assertNotIn("secret", json.dumps({"stage":error.stage}))

    def test_case_identifiers_are_unique_and_match_the_registry(self):
        registry = json.loads((fixture.ROOT / "qa/openbao-acceptance/external_fixture_case_registry_v1.json").read_text())
        def find(value):
            if isinstance(value, dict):
                if value.get("script") == "qa/openbao-acceptance/kerberos_mit_live.py":
                    return value["case_ids"]
                for child in value.values():
                    result = find(child)
                    if result is not None:
                        return result
            return None
        self.assertEqual(list(fixture.CORPUS_CASE_IDS), find(registry))
        self.assertEqual(len(fixture.CORPUS_CASE_IDS), len(set(fixture.CORPUS_CASE_IDS)))
