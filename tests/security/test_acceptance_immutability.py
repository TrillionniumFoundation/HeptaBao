from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
import validate_acceptance_immutability as policy


class AcceptanceImmutabilityTests(unittest.TestCase):
    def test_current_workflows_cannot_publish_source_or_refs(self):
        self.assertEqual([], policy.validate_directory(ROOT / ".github/workflows"))

    def test_source_materializer_patterns_fail_closed(self):
        commands = [
            "git add -A && git commit -m generated",
            "git push origin HEAD:candidate/generated",
            "git tag candidate && git push origin candidate",
            "gh pr create --head generated --base main",
            "curl https://api.github.com/repos/example/repo/git/refs",
        ]
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "materializer.yml"
                path.write_text(f"name: materializer\njobs:\n  x:\n    steps:\n      - run: {command}\n")
                self.assertTrue(policy.validate_directory(Path(temp)))


if __name__ == "__main__":
    unittest.main()
