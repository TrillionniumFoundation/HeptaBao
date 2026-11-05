import unittest


import sys_leader_live as fixture
guard = fixture.capacity_observer_effect

def observations(delta=2):
    return [{'generation': 8 + i * delta, 'retained_operations': 8 + i * delta,
             'journal_bytes': 34000 + i * 11000, 'durable_payload_bytes': 13000 + i * 5300,
             'state_bytes': 3552, 'state_limit_bytes': 83886080,
             'state_remaining_bytes': 83886080-3552, 'state_schema': 86, 'kv_read_only_dispatches': 0,
             'state_size_basis': 'opaque-owner-json-plus-kv1-canonical-values',
             'state_storage_format': 'heptabao-state-records-v5'} for i in range(5)]


class ObserverGuard(unittest.TestCase):
    def test_current_execution_measures_observer_instead_of_assuming_two(self):
        for delta in [0, 2, 4]:
            with self.subTest(delta=delta):
                result = guard(observations(delta))
                self.assertTrue(result['passed'])
                self.assertEqual(result['net_extra_operations'],
                                 {'generation': 0, 'retained_operations': 0})

    def test_extra_effect_adjacent_to_leader_is_rejected(self):
        rows = observations()
        for row in rows[3:]:
            row['generation'] += 1
            row['retained_operations'] += 1
        result = guard(rows)
        self.assertTrue(result['baseline_stable'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['net_extra_operations']['generation'], 1)

    def test_concurrent_writer_in_control_interval_is_rejected(self):
        rows = observations()
        rows[1]['generation'] += 1
        self.assertFalse(guard(rows)['baseline_stable'])
        self.assertFalse(guard(rows)['passed'])

    def test_kv_dispatch_and_schema_changes_are_rejected(self):
        for field in ['kv_read_only_dispatches', 'state_schema']:
            with self.subTest(field=field):
                rows = observations()
                rows[3][field] += 1
                self.assertFalse(guard(rows)['passed'])

    def test_observed_owner_byte_variation_requires_exact_capacity_arithmetic(self):
        rows = observations()
        rows[3]['state_bytes'] -= 1
        self.assertFalse(guard(rows)['passed'])
        rows[3]['state_remaining_bytes'] += 1
        result = guard(rows)
        self.assertTrue(result['passed'])
        self.assertEqual(result['observed_state_bytes'], [3552,3552,3552,3551,3552])
        rows[3]['state_bytes'] = rows[3]['state_limit_bytes'] + 1
        rows[3]['state_remaining_bytes'] = 0
        self.assertFalse(guard(rows)['passed'])

    def test_unknown_or_non_numeric_capacity_is_rejected(self):
        for field, value in [('generation', True), ('retained_operations', None),
                             ('state_storage_format', None), ('state_bytes', -1)]:
            with self.subTest(field=field):
                rows = observations()
                rows[0][field] = value
                self.assertIsNone(guard(rows))

    def test_clock_metadata_byte_lengths_are_observed_without_fixed_size(self):
        rows = observations()
        rows[2]['journal_bytes'] += 8
        rows[2]['durable_payload_bytes'] += 3
        self.assertTrue(guard(rows)['passed'])
        rows[2]['journal_bytes'] = rows[1]['journal_bytes'] - 1
        self.assertFalse(guard(rows)['passed'])


if __name__ == '__main__':
    unittest.main()
