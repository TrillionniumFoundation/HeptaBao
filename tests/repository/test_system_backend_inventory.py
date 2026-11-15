import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

class SystemBackendInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads((ROOT / 'planning/HEPTABAO_SYSTEM_BACKEND_ENDPOINT_INVENTORY_V1.json').read_text())
        self.service = (ROOT / 'crates/heptabao-server/src/service.rs').read_text()
        self.tests = (ROOT / 'crates/heptabao-server/src/service_tests.rs').read_text()

    def test_inventory_is_closed_and_source_bound(self):
        self.assertEqual(self.inventory['schema'], 'heptabao.system-backend-endpoints.v1')
        expected = {
            'sys/health','sys/init','sys/unseal','sys/seal-status','sys/seal',
            'sys/rekey/init','sys/rekey/update'
        }
        routes = self.inventory['routes']
        self.assertEqual({row['path'] for row in routes}, expected)
        self.assertEqual(len(routes), len(expected))
        for row in routes:
            self.assertIn(f'"{row["path"]}"', self.service)
            self.assertEqual(row['methods'], list(dict.fromkeys(row['methods'])))
            self.assertEqual(row['fields'], list(dict.fromkeys(row['fields'])))

    def test_behavior_anchors_are_real(self):
        anchors = self.inventory['behavior_anchors']
        self.assertGreaterEqual(len(anchors), 4)
        self.assertEqual(len(anchors), len(set(anchors)))
        for name in anchors:
            self.assertIn(f'fn {name}', self.tests)

    def test_required_field_and_precedence_markers_exist(self):
        for marker in [
            'initialization requires the root namespace',
            'server is sealed',
            'permission denied',
            'rekey nonce is required',
            'unseal share is required',
            'unsupported rekey update fields',
        ]:
            self.assertIn(marker, self.service)

if __name__ == '__main__':
    unittest.main()
