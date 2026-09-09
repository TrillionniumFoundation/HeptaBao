from pathlib import Path
import unittest


class MigrationInventoryV24Tests(unittest.TestCase):
    def test_all_object_kinds_and_dependency_cycle_rejection_exist(self):
        source=Path("crates/heptabao-migration-journal/src/lib.rs").read_text(encoding="utf-8")
        for marker in ("MigrationObjectKindV24", "all_required_for_complete_profile", "MissingRequiredKind", "MissingDependency", "DependencyCycle", "migration_topological_order_v2_4"):
            self.assertIn(marker,source)

    def test_adapter_and_cutover_boundary_is_explicit(self):
        guide=Path("docs/modules/heptabao-migration-journal.md").read_text(encoding="utf-8")
        self.assertIn("not semantic correctness of each object adapter",guide)
        self.assertIn("cutover evidence remain required",guide)


if __name__ == "__main__":
    unittest.main()
