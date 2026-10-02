"""Static regression guards complement, not replace, executed platform tests."""
import re
import tomllib
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


class TargetFileFlagsTests(unittest.TestCase):
    def test_all_custom_file_flags_use_target_constants(self):
        calls=[]
        for path in (ROOT/"crates/heptabao-server/src").rglob("*.rs"):
            for match in re.finditer(r"\.custom_flags\((.*?)\)",path.read_text(),re.S):
                value=match.group(1)
                calls.append((path,value))
                self.assertNotRegex(value,r"\b(?:0o[0-7]+|0x[0-9A-Fa-f]+|[0-9]+)\b",str(path))
                self.assertIn("libc::O_NOFOLLOW",value,str(path))
                self.assertIn("libc::O_CLOEXEC",value,str(path))
        self.assertGreaterEqual(len(calls),13)

    def test_dependency_matches_all_unix_consumers(self):
        manifest=tomllib.loads((ROOT/"crates/heptabao-server/Cargo.toml").read_text())
        self.assertEqual(manifest["target"]["cfg(unix)"]["dependencies"]["libc"],"=0.2.189")

    def test_read_only_workflow_runs_client_and_runtime_profiles(self):
        source=(ROOT/".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        for command in ("clients/python/tests","qa/openbao-acceptance/client_live.py", "qa/openbao-acceptance/ssh_otp_ha.py"):
            self.assertIn(command,source)
        self.assertIn("contents: read",source)
        self.assertNotIn("contents: write",source)
        self.assertNotIn("continue-on-error: true",source)
        self.assertIn('"$(git rev-parse HEAD)" = "$EXPECTED_SOURCE"',source)


if __name__=="__main__":unittest.main()
