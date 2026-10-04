"""Bounded public PEM syntax allowances never skip a source file or new marker."""
from __future__ import annotations

import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("plan_secret_hygiene", ROOT / "scripts/validate_plan_v2.py")
assert SPEC and SPEC.loader
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)
HEADER = "-----BEGIN " + "PRIVATE KEY-----"
FOOTER = "-----END " + "PRIVATE KEY-----"
SITES = {
    "crates/heptabao-server/src/service_local_pki_tests.rs": 1,
    "crates/heptabao-server/src/engines/pki_local_key_tests.rs": 2,
    "crates/heptabao-server/src/engines/pki_local_key.rs": 1,
    "crates/heptabao-server/src/service_external_key_native_tests.rs": 1,
    "crates/heptabao-server/src/outbound_ldap_transport.rs": 1,
}


class PlanSecretHygieneTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sources = {name: (ROOT / name).read_text() for name in SITES}
        self.synthetic_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def scan(self):
        with patch.object(plan, "ROOT", self.root):
            plan.scan_secret_hygiene()

    def test_current_six_reviewed_public_uses_are_recognized(self):
        self.assertEqual(sum(SITES.values()), 6)
        for name, text in self.sources.items():
            self.assertEqual(text.count(HEADER), SITES[name])
            self.assertEqual(len(plan.reviewed_public_pem_spans(name, text)), SITES[name])
            self.write(name, text)
        self.scan()

    def test_unrelated_comments_and_whitespace_outside_spans_stay_allowed(self):
        for name, text in self.sources.items():
            self.write(name, "// unrelated formatting/comment change\n\n" + text + "\n  \n// unrelated end comment\n")
        self.scan()

    def test_real_private_key_added_adjacent_to_each_site_is_rejected(self):
        for name, text in self.sources.items():
            with self.subTest(name=name):
                self.write(name, text + "\n" + self.synthetic_key)
                with self.assertRaises(plan.ValidationFailure):
                    self.scan()
                (self.root / name).unlink()

    def test_real_private_key_inserted_inside_each_allowed_literal_is_rejected(self):
        escaped = self.synthetic_key.replace("\n", "\\n")
        for name, text in self.sources.items():
            with self.subTest(name=name):
                self.write(name, text.replace(HEADER, escaped, 1))
                with self.assertRaises(plan.ValidationFailure):
                    self.scan()
                (self.root / name).unlink()

    def test_unknown_marker_in_reviewed_file_is_not_a_path_exemption(self):
        for name, text in self.sources.items():
            with self.subTest(name=name):
                self.write(name, text + '\nlet unexpected = "' + HEADER + '";\n')
                with self.assertRaises(plan.ValidationFailure):
                    self.scan()
                (self.root / name).unlink()

    def test_same_public_expression_at_unknown_path_is_rejected(self):
        self.write("unexpected.rs", f'text.starts_with("{HEADER}\\n")')
        with self.assertRaises(plan.ValidationFailure):
            self.scan()

    def test_duplicate_allowed_expression_is_rejected(self):
        name = "crates/heptabao-server/src/service_local_pki_tests.rs"
        self.write(name, self.sources[name] + f'\ntext.starts_with("{HEADER}\\n");\n')
        with self.assertRaises(plan.ValidationFailure):
            self.scan()

    def test_altered_public_expression_is_rejected(self):
        name = "crates/heptabao-server/src/service_local_pki_tests.rs"
        self.write(name, self.sources[name].replace("text.starts_with(", "other_call(", 1))
        with self.assertRaises(plan.ValidationFailure):
            self.scan()

    def test_allowed_expression_cannot_be_suffix_of_another_identifier(self):
        name = "crates/heptabao-server/src/service_local_pki_tests.rs"
        self.write(name, self.sources[name].replace("text.starts_with(", "other_text.starts_with(", 1))
        with self.assertRaises(plan.ValidationFailure):
            self.scan()

    def test_negative_fixture_cannot_change_into_a_raw_string_context(self):
        name = "crates/heptabao-server/src/service_external_key_native_tests.rs"
        literal = f'"{{}}\\n{HEADER}\\nMAA=\\n{FOOTER}"'
        self.assertIn(literal, self.sources[name])
        self.write(name, self.sources[name].replace(literal, "r#" + literal + "#", 1))
        with self.assertRaises(plan.ValidationFailure):
            self.scan()

    def test_changed_negative_fixture_body_is_rejected(self):
        for name, body in [("crates/heptabao-server/src/service_external_key_native_tests.rs", "MAA="),
                           ("crates/heptabao-server/src/outbound_ldap_transport.rs", "AAAA")]:
            with self.subTest(name=name):
                self.write(name, self.sources[name].replace(body, "MAMCAQA=", 1))
                with self.assertRaises(plan.ValidationFailure):
                    self.scan()
                (self.root / name).unlink()

    def test_two_allowed_fixture_payloads_are_not_private_keys(self):
        for payload in ("MAA=", "AAAA"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                serialization.load_der_private_key(base64.b64decode(payload), password=None)

    def test_other_secret_markers_are_still_rejected_in_allowed_files(self):
        name = "crates/heptabao-server/src/service_local_pki_tests.rs"
        for marker in ("-----BEGIN OPENSSH " + "PRIVATE KEY-----", "gh" + "p_", "xox" + "b-", "AK" + "IAIOSFODNN7EXAMPLE"):
            with self.subTest(marker=marker):
                self.write(name, self.sources[name] + "\n" + marker)
                with self.assertRaises(plan.ValidationFailure):
                    self.scan()

    def test_actual_private_key_at_unknown_path_is_rejected(self):
        self.write("unreviewed.txt", self.synthetic_key)
        with self.assertRaises(plan.ValidationFailure):
            self.scan()


if __name__ == "__main__":
    unittest.main()
