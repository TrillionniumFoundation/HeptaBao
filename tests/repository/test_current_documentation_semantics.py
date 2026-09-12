"""Regressions for source/doc mismatch that a fresh digest alone cannot detect."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("documentation_semantics", ROOT / "scripts/validate_current_documentation_semantics.py")
assert SPEC and SPEC.loader
SEM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEM)


class DocumentationSemanticsTests(unittest.TestCase):
    def test_current_repository_semantics(self) -> None:
        self.assertEqual([], SEM.validate(ROOT))

    def test_historical_api_table_cannot_supply_current_semantics(self) -> None:
        text = "## Public API and ownership\n\n<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->\nA formerly public AuthState and authorize method.\n<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->\n"
        self.assertNotIn("AuthState", SEM.human_text(text))
        self.assertIn("Public API and ownership", SEM.human_text(text))

    def test_removing_live_time_or_widening_visibility_rejects_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "auth.rs"
            declaration = "pub(super) fn authorize_request(&self, principal: &Principal, now: u64) -> Result<(), AuthError>"
            document = "<!-- CURRENT API: auth.rs#authorize_request -->\n```text\n" + declaration + "\n```"
            source.write_text(declaration + " { Ok(()) }\n")
            self.assertEqual([], SEM.validate_api_contracts(root, document, "auth guide"))
            for changed in [declaration.replace(", now: u64", ""), declaration.replace("pub(super)", "pub")]:
                source.write_text(changed + " { Ok(()) }\n")
                self.assertTrue(SEM.validate_api_contracts(root, document, "auth guide"))

    def test_runtime_closure_excludes_dev_and_includes_target_normal_edges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packages = {}
            for name in ["server", "normal", "target", "test-only"]:
                package = "heptabao-" + name
                path = root / package
                path.mkdir()
                packages[package] = {"root": package}
                (path / "Cargo.toml").write_text(f'[package]\nname="{package}"\n')
            (root / "heptabao-server/Cargo.toml").write_text('''[dependencies]
heptabao-normal={path="../heptabao-normal"}
[dev-dependencies]
heptabao-test-only={path="../heptabao-test-only"}
[target.'cfg(target_os = "linux")'.dependencies]
heptabao-target={path="../heptabao-target"}
''')
            self.assertEqual({"heptabao-server", "heptabao-normal", "heptabao-target"}, SEM.runtime_closure(root, packages))


if __name__ == "__main__":
    unittest.main()
