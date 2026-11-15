"""Keep both Android product adapters covered by the synthetic CI trigger."""
from fnmatch import fnmatchcase
from pathlib import Path
import unittest


class SyntheticWorkflowPaths(unittest.TestCase):
    def test_android_only_changes_select_the_synthetic_workflow(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / ".github/workflows/personal-credentials-synthetic.yml").read_text()
        # This workflow's path list is an unquoted, single-line block. Keep the
        # guard independent of YAML 1.1's surprising coercion of the `on` key.
        paths = source.split("    paths:\n", 1)[1].split("  workflow_dispatch:", 1)[0]
        patterns = [line.strip()[2:] for line in paths.splitlines()
                    if line.strip().startswith("- ")]
        for directory in ("clients/android", "clients/android-passkey"):
            files = sorted(path for path in (root / directory).rglob("*") if path.is_file())
            self.assertTrue(files, directory)
            for path in files:
                relative = path.relative_to(root).as_posix()
                with self.subTest(path=relative):
                    self.assertTrue(any(fnmatchcase(relative, pattern) for pattern in patterns))


if __name__ == "__main__":
    unittest.main()
