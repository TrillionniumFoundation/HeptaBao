"""Fresh provider DDL is the effective forward-upgrade contract, without shadows."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
from postgres_provider_contract import (
    UPGRADES, current_provider_contract_matches, provider_function,
)


class PostgresProviderContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        paths = ["bootstrap/postgresql/provider.sql",
                 "qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql"]
        paths += ["bootstrap/postgresql/" + name for name in UPGRADES]
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.provider = self.root / "bootstrap/postgresql/provider.sql"
        self.assertTrue(current_provider_contract_matches(self.root))

    def reject(self, old: str, new: str, path: Path | None = None):
        path = path or self.provider
        source = path.read_text()
        self.assertIn(old, source)
        path.write_text(source.replace(old, new, 1))
        self.assertFalse(current_provider_contract_matches(self.root))

    def test_current_fresh_install_matches_complete_upgrade_chain(self):
        self.assertTrue(current_provider_contract_matches(ROOT))

    def test_shadowed_function_definition_is_rejected(self):
        source = self.provider.read_text()
        self.provider.write_text(source + "\n" + provider_function(source, "protocol"))
        self.assertFalse(current_provider_contract_matches(self.root))

    def test_changed_current_function_guard_is_rejected(self):
        self.reject("p_seq<1", "p_seq<0")

    def test_missing_current_function_is_rejected(self):
        self.reject(provider_function(self.provider.read_text(), "protocol"), "")

    def test_missing_public_function_revocation_is_rejected(self):
        self.reject("REVOKE ALL ON FUNCTION heptabao_provider.protocol() FROM PUBLIC;", "")

    def test_added_public_execute_grant_is_rejected(self):
        self.provider.write_text(self.provider.read_text() +
            "\nGRANT EXECUTE ON FUNCTION heptabao_provider.protocol() TO PUBLIC;\n")
        self.assertFalse(current_provider_contract_matches(self.root))

    def test_changed_provider_table_constraint_is_rejected(self):
        self.reject("last_seq bigint NOT NULL", "last_seq bigint")

    def test_changed_effective_upgrade_function_is_rejected(self):
        self.reject("p_seq<1", "p_seq<0", self.root /
            "bootstrap/postgresql/upgrade_v6_root_rotation_statements.sql")


if __name__ == "__main__":
    unittest.main()
