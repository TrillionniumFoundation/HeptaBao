from pathlib import Path
from types import SimpleNamespace
import raft_record_snapshot_observation as observer
import unittest
from unittest.mock import patch
import kv1_record_ha_live as fixture
from kv1_record_scale_live import Dataset


class Kv1RecordHaGuards(unittest.TestCase):
    def test_successful_wrong_value_fails_immediately_and_is_not_hidden_by_retry(self):
        dataset=Dataset();dataset.remember('bulk/0000',{'value':'correct'})
        calls=[]
        def call(*args,**kwargs):
            calls.append(args)
            return (200,{'data':{'value':'wrong' if len(calls)==1 else 'correct'}})
        with self.assertRaises(fixture.FixtureError):
            fixture.read_exact(SimpleNamespace(call=call),'synthetic',dataset,'bulk/0000',recover=True)
        self.assertEqual(len(calls),1)

    def test_recovery_only_polls_transient_unavailability_and_validates_final_hash(self):
        dataset=Dataset();dataset.remember('bulk/0000',{'value':'correct'})
        replies=iter([(503,{}),(200,{'data':{'value':'correct'}})])
        with patch.object(fixture.time,'sleep',return_value=None):
            fixture.read_exact(SimpleNamespace(call=lambda *a,**k:next(replies)),
                               'synthetic',dataset,'bulk/0000',recover=True)
        for status in (200,400,403,404):
            with self.assertRaises(fixture.FixtureError):
                fixture.read_exact(SimpleNamespace(call=lambda *a,**k:(status,{})),
                                   'synthetic',dataset,'bulk/0000',recover=True)

    def test_purge_frontier_must_be_real_ordered_integer_indices(self):
        good={'applied_index':120,'snapshot_index':119,'purged_index':119}
        self.assertTrue(fixture.snapshot_frontier(good))
        for broken in ({},dict(good,purged_index=None),dict(good,purged_index=True),
                       dict(good,purged_index=121),dict(good,snapshot_index=121),dict(good,purged_index=-1)):
            self.assertFalse(fixture.snapshot_frontier(broken))

    def test_snapshot_trigger_uses_small_maintenance_response_not_backup_export(self):
        calls=[]
        def call(method,path,body,**kwargs):
            calls.append((method,path,body,kwargs))
            return 200,{'data':{'generation':99,'journal_bytes_after':0}}
        self.assertEqual(fixture.compact_for_snapshot(SimpleNamespace(call=call),'synthetic')[0],200)
        self.assertEqual(calls,[('POST','sys/storage/raft/compact',{}, {'token':'synthetic','timeout':60})])

    def test_snapshot_polling_never_hides_corrupt_graph_or_metadata(self):
        node=SimpleNamespace(root=Path('synthetic'))
        with patch.object(observer,'inspect_record_bundle',side_effect=ValueError('invalid_graph')) as inspect:
            with self.assertRaises(ValueError): fixture.wait_record_snapshot(node,99)
            self.assertEqual(inspect.call_count,1)
        with patch.object(observer,'inspect_record_bundle',side_effect=[observer.SnapshotPending(), {'snapshot_index':99}]), \
             patch.object(fixture.time,'sleep',return_value=None):
            self.assertEqual(fixture.wait_record_snapshot(node,99),{'snapshot_index':99})

    def test_graph_catchup_new_leader_and_quorum_phases_cannot_be_omitted(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]),rows[i])
        for invalid in ([],rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],
                        rows[:-1]+[dict(rows[-1],raw='sensitive')]):
            self.assertFalse(fixture.complete(invalid))


if __name__=='__main__':unittest.main()
