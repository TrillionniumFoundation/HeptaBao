"""Unknown source versions must stop before migration reads or effects."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import migrate_policies as policies
import migrate_identity as identity
import migrate_auth_mount as auth_mount
import migrate_ssh_roles as ssh_roles
import migration_preflight as preflight
from bao_http import BaoError


def endpoint(version, name):
    return SimpleNamespace(
        address="https://" + name + ".example", namespace="",
        health=lambda: {"version": version, "cluster_id": name},
        request=Mock(side_effect=AssertionError("no migration request permitted")),
    )


class SourceVersionTests(unittest.TestCase):
    def test_unknown_or_product_like_source_stops_before_inventory_or_write(self):
        for version in ("2.8.0", "2.7.0-dev", "HeptaBao-2.7.0", ""):
            for module, args in (
                (policies, []), (identity, []), (ssh_roles, []),
                (auth_mount, ["--mount", "migration-approle"]),
            ):
                with self.subTest(module=module.__name__, version=version):
                    source, target = endpoint(version, "source"), endpoint("HeptaBao-test", "target")
                    output = io.StringIO()
                    with patch.object(module.Client, "from_env", side_effect=[source, target]), redirect_stdout(output):
                        self.assertEqual(module.main(args), 2)
                    import json
                    self.assertEqual(json.loads(output.getvalue())["reason"], "unsupported_source_version")
                    source.request.assert_not_called()
                    target.request.assert_not_called()

    def test_preflight_unknown_source_stops_before_catalogs_or_capacity(self):
        source, target = endpoint("2.8.0", "source"), endpoint("HeptaBao-test", "target")
        with self.assertRaisesRegex(BaoError, "migration_product_version_mismatch"):
            preflight.collect(source, target)
        source.request.assert_not_called()
        target.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
