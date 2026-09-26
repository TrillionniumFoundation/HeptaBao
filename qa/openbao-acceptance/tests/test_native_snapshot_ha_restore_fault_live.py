import signal
from types import SimpleNamespace
import unittest
from unittest import mock
import native_snapshot_ha_restore_fault_live as f


class FaultScenarioGuards(unittest.TestCase):
    def test_required_phases_cannot_be_replaced_with_check_count(self):
        rows=[{'case':n,'passed':True} for n in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for index in range(len(rows)):self.assertFalse(f.complete(rows[:index]+rows[index+1:]))
        self.assertFalse(f.complete(rows+[rows[0]]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'fixture_exception','passed':True}]))

    def test_kill_rejects_foreign_or_dead_process_and_requires_sigkill(self):
        process=SimpleNamespace(poll=lambda:None,returncode=None)
        node=SimpleNamespace(process=process)
        def stop():process.returncode=-signal.SIGKILL;node.process=None
        node.stop=mock.Mock(side_effect=stop)
        with self.assertRaises(f.FixtureError):f.owned_kill(SimpleNamespace(nodes=[]),node)
        node.stop.assert_not_called()
        self.assertTrue(f.owned_kill(SimpleNamespace(nodes=[node]),node))
        node.stop.assert_called_once()
        with self.assertRaises(f.FixtureError):f.owned_kill(SimpleNamespace(nodes=[node]),node)

    def test_observation_requires_all_values_later_absence_and_other_owner(self):
        values={'a':{'v':'archived'},'b':{'v':'different'}};owner={'name':'policy','policy':'synthetic'}
        def response(method,path,**kwargs):
            self.assertEqual(method,'GET');self.assertLessEqual(kwargs['timeout'],5)
            if path.endswith('/later'):return 404,{}
            if path.startswith('sys/policies/'):return 200,{'data':owner}
            return 200,{'data':values[path.rsplit('/',1)[1]]}
        node=SimpleNamespace(call=mock.Mock(side_effect=response))
        hashes={k:f.digest(v) for k,v in values.items()}
        self.assertTrue(f.observe(node,'token',hashes,f.digest(owner),later_present=False))
        self.assertEqual(node.call.call_count,4)
        self.assertFalse(f.observe(node,'token',hashes,'0'*64,later_present=False))
        self.assertFalse(f.observe(node,'token',hashes,f.digest(owner),later_present=True))
        self.assertFalse(f.observe(node,'token',{'a':'0'*64},f.digest(owner),later_present=False))

    def test_no_completed_observation_cannot_authorize_kill(self):
        node=SimpleNamespace(node_id=2)
        # Bounded time advances through calls; old state is never accepted as publication.
        with mock.patch.object(f.time,'monotonic',side_effect=range(100)),mock.patch.object(f.time,'sleep'),mock.patch.object(f,'observe',return_value=False):
            with self.assertRaisesRegex(f.FixtureError,'restored_publication_not_observed'):
                f.wait_survivor_observation([node],'token',{},'owner',later_present=False)

    def test_survivor_poll_returns_only_after_matching_application(self):
        nodes=[SimpleNamespace(node_id=2),SimpleNamespace(node_id=3)]
        with mock.patch.object(f,'observe',side_effect=[False,True]) as observe:
            self.assertEqual(f.wait_survivor_observation(nodes,'token',{'a':'digest'},'owner',later_present=False),3)
        self.assertEqual(observe.call_count,2)
        self.assertTrue(all(c.kwargs['deadline']>0 for c in observe.call_args_list))
