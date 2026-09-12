"""Current-source binding rejects drift without rewriting frozen history."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("inventory_under_test", ROOT / "scripts/current_source_inventory.py")
assert SPEC and SPEC.loader
INV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INV)


class CurrentSourceInventoryTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        files = {
            "Cargo.toml": '[workspace]\nmembers=["crates/*"]\n',
            "Cargo.lock": 'version=4\n',
            "crates/heptabao-probe/Cargo.toml": '[package]\nname="heptabao-probe"\nversion="0.1.0"\n',
            "crates/heptabao-probe/src/lib.rs": 'pub const fn limit() -> usize { 4 }\n#[tokio::test(flavor = "multi_thread")]\nasync fn bounded() {}\n',
            "docs/modules/heptabao-probe.md": '# Probe\nConcrete current guide\n',
        }
        for path, text in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        historical = root / INV.HISTORICAL
        historical.parent.mkdir(parents=True, exist_ok=True)
        historical.write_bytes((ROOT / INV.HISTORICAL).read_bytes())
        self.save(root)

    def save(self, root: Path) -> None:
        value, _ = INV.inventory(root)
        (root / INV.SNAPSHOT).write_bytes(INV.canonical(value))

    def test_current_repository_inventory_matches(self) -> None:
        self.assertEqual([], INV.validate())
        snapshot, details = INV.inventory()
        self.assertEqual(len(details), snapshot["package_count"])
        self.assertIn("heptabao-ha-service", details)
        self.assertFalse(snapshot["qualification"])
        self.assertFalse(snapshot["compatibility_claim"])

    def test_public_const_fn_and_parameterized_async_test_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            _, details = INV.inventory(root)
            detail = details["heptabao-probe"]
            self.assertEqual(["fn", "limit"], detail["public_lexical_declarations"][0][2:4])
            self.assertEqual("bounded", detail["discovered_test_functions"][0][2])

    def test_source_guide_manifest_and_lock_drift_are_each_rejected(self) -> None:
        for path in ["crates/heptabao-probe/src/lib.rs", "docs/modules/heptabao-probe.md", "crates/heptabao-probe/Cargo.toml", "Cargo.lock"]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                original = (root / path).read_text()
                (root / path).write_text(original + "\n")
                self.assertTrue(INV.validate(root))
                self.save(root)
                self.assertEqual([], INV.validate(root))

    def test_frozen_history_cannot_be_rebased_by_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / INV.HISTORICAL).write_text("rewritten historical record")
            with self.assertRaisesRegex(ValueError, "frozen V1.4.7"):
                self.save(root)

    def test_unknown_or_missing_guide_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            extra = root / "docs/modules/heptabao-unknown.md"
            extra.write_text("orphan")
            self.assertTrue(INV.validate(root))
            extra.unlink()
            (root / "docs/modules/heptabao-probe.md").unlink()
            self.assertTrue(INV.validate(root))

    def test_symlinked_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            source = root / "crates/heptabao-probe/src/lib.rs"
            saved = root / "saved.rs"
            source.rename(saved)
            try:
                source.symlink_to(saved)
            except OSError:
                self.skipTest("symlink creation unavailable on this test platform")
            self.assertTrue(INV.validate(root))

    def test_readonly_validation_does_not_repair_a_bad_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = root / INV.SNAPSHOT
            path.write_text("{}\n")
            self.assertTrue(INV.validate(root))
            self.assertEqual("{}\n", path.read_text())

    def test_workspace_escape_and_duplicate_patterns_are_rejected(self) -> None:
        for patterns in ['["../other"]', '["crates/*", "crates/*"]']:
            with self.subTest(patterns=patterns), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                (root / "Cargo.toml").write_text(f'[workspace]\nmembers={patterns}\n')
                self.assertTrue(INV.validate(root))


if __name__ == "__main__":
    unittest.main()
