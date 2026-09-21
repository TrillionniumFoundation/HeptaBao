import unittest
from unittest.mock import patch
import kv1_record_scale_live as scale


class Kv1RecordScaleGuards(unittest.TestCase):
    def test_growth_evidence_must_really_cross_sixteen_mib_and_cover_restart_and_delete(self):
        checks = [{'case':name, 'passed':True} for name in sorted(scale.REQUIRED-{'complete'})]
        checks.append({'case':'complete', 'passed':True})
        points = [{'target_mib':mib, 'logical_payload_bytes':mib*scale.MIB, 'small_writes':3}
                  for mib in (4,24,32)]
        self.assertTrue(scale.complete(checks,32,points))
        self.assertTrue(scale.complete(checks[:-1]+[{'case':'extra','passed':True}]+checks[-1:],32,points))
        for i in range(len(checks)):
            self.assertFalse(scale.complete(checks[:i]+checks[i+1:],32,points))
        self.assertFalse(scale.complete(checks+[checks[0]],32,points))
        self.assertFalse(scale.complete(checks,32,points[:-1]))
        for damaged in (points[:-1]+[dict(points[-1], logical_payload_bytes=16*scale.MIB)],
                        points[:-1]+[dict(points[-1], small_writes=0)], points[:-1]+[None]):
            self.assertFalse(scale.complete(checks,32,damaged))
        self.assertFalse(scale.complete(checks[:-1]+[{'case':'complete','passed':1}],32,points))

    def test_full_record_hash_checks_data_not_just_status_or_size(self):
        data=scale.Dataset()
        value={'payload':'synthetic-sensitive', 'ordinal':7}
        data.remember('bulk/0007',value)
        self.assertTrue(data.matches('bulk/0007',200,{'data':value}))
        self.assertFalse(data.matches('bulk/0007',200,{'data':dict(value,ordinal=8)}))
        self.assertFalse(data.matches('bulk/0007',204,{'data':value}))
        self.assertFalse(data.matches('bulk/0007',200,{'data':{'data':value}}))
        self.assertNotIn('synthetic-sensitive', str(data.hashes))

    def test_replacement_and_delete_change_expected_live_bytes_without_retaining_payload(self):
        data=scale.Dataset()
        data.remember('a',{'v':'short'})
        data.remember('b',{'v':'longer'})
        before=data.logical_bytes
        data.remember('a',{'v':'larger-value'})
        self.assertGreater(data.logical_bytes,before)
        data.forget('b')
        self.assertEqual(data.logical_bytes,len(scale.canonical({'v':'larger-value'})))
        self.assertEqual(set(data.hashes),{'a'})

    def test_generated_values_stay_under_http_bound_and_use_distinct_random_payloads(self):
        data=scale.Dataset()
        left,right=data.make_value(0),data.make_value(1)
        self.assertNotEqual(left['payload'],right['payload'])
        self.assertEqual(len(left['payload']),scale.PAYLOAD_BYTES)
        self.assertLess(len(scale.canonical(left)),256*1024)
        self.assertEqual(len(data.sample_prefixes),2)

    def test_process_counter_missing_or_backwards_is_not_silently_zero(self):
        before={'cpu_ticks':10,'write_bytes':4096,'wchar':100,'rss_kib':10,'peak_rss_kib':20}
        after=dict(before,cpu_ticks=11,write_bytes=8192,wchar=200)
        with patch.object(scale.os,'sysconf',return_value=100):
            result=scale.measurement_delta(before,after)
        self.assertEqual(result['server_cpu_seconds'],.01)
        self.assertEqual(result['process_write_bytes'],4096)
        for broken in ({},dict(after,write_bytes=0),dict(after,cpu_ticks=True)):
            with self.assertRaises(scale.ScenarioFailure):
                scale.measurement_delta(before,broken)


if __name__=='__main__':unittest.main()
