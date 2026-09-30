from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError


@unittest.skipUnless(sys.platform == "darwin", "macOS system alias contract")
class DarwinPrivateStateTests(unittest.TestCase):
    def test_root_owned_var_alias_is_normalized_before_descriptor_walk(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            root = Path(directory)
            root.chmod(0o700)
            with StateDirectory(root, writer=True) as state:
                state.write("value", b"descriptor-bound")
                self.assertEqual(state.read("value"), b"descriptor-bound")

    def test_non_system_symlink_component_remains_rejected(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            target = parent / "target"
            target.mkdir(mode=0o700)
            alias = parent / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(BaoError, "private_state_directory_open_failed"):
                StateDirectory(alias)


if __name__ == "__main__":
    unittest.main()
