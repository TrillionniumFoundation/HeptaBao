#!/usr/bin/env python3
"""Safety gates only: no subprocess, launchctl, filesystem mutation, or signal."""
import copy
import json
import types
import unittest
from unittest import mock
import fresh_synthetic_controller_r1 as c

IDENTITY={'pid':32528,'ppid':1,'pgid':32528,'uid':501,'birthSec':1793973000,
          'birthUsec':123456,'executable':'/exact/Python'}
KNOWN={'attempted':True,'complete':True,'exitCode':0,
       'command':{'outcomeUnknown':False,'completeBeforeDeadline':True}}

class DummyBase:
    def _query(self,label,entry,**kwargs):return copy.deepcopy(self.state)
    def public(self):return {'ok':False,'ownedCommands':{'commands':[]}}

def entry():
    return {'generation':'server-initial','label':'fixture','target':c.TARGET,
            'wrapperIdentity':None,'execIdentity':None,'groups':set(),
            'attempts':{'bootstrap':copy.deepcopy(KNOWN)},'arguments':['python','wrapper'],
            'plistSha256':'a'*64,'planSha256':'b'*64,'registrationClosed':False}

class SafetyGates(unittest.TestCase):
    def setUp(self):
        base=types.SimpleNamespace(OwnedLaunchd=DummyBase,PYTHON_KERNEL_IMAGE='/exact/Python',ManagerRefused=RuntimeError)
        self.cls=c.install_controller(base,types.SimpleNamespace())
        self.manager=object.__new__(self.cls)
        self.manager.state={'pid':IDENTITY['pid'],'runs':1,'last exit code':None}
        self.manager.reader=types.SimpleNamespace(read=mock.Mock(return_value=copy.deepcopy(IDENTITY)),children=mock.Mock(return_value=[]))
        self.manager.journal=types.SimpleNamespace(append=mock.Mock())
        self.manager.commands=types.SimpleNamespace(public=mock.Mock(return_value={
            'unknownCommandCount':0,'allOwnedCommandsStopped':True}))
        self.entry=entry()
    def test_bootstrap_capture_never_grants_business_admission(self):
        self.manager._query('fixture',self.entry)
        self.assertEqual(self.entry['bootstrapIdentity'],IDENTITY)
        self.assertIsNone(self.entry['wrapperIdentity']);self.assertIsNone(self.entry['execIdentity'])
        value=self.manager.journal.append.call_args.args[1]
        self.assertFalse(value['businessAdmissionGranted'])
    def test_cleanup_query_never_creates_new_custody(self):
        self.manager._query('fixture',self.entry,cleanup=True)
        self.assertNotIn('bootstrapIdentity',self.entry)
        self.manager.reader.read.assert_not_called()
    def test_unknown_bootstrap_cannot_capture_identity(self):
        self.entry['attempts']['bootstrap']['command']['outcomeUnknown']=True
        with self.assertRaisesRegex(RuntimeError,'known_bootstrap'):self.manager._query('fixture',self.entry)
        self.manager.journal.append.assert_not_called()
    def test_incomplete_bootstrap_cannot_capture_identity(self):
        self.entry['attempts']['bootstrap']['complete']=False
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_nonzero_bootstrap_cannot_capture_identity(self):
        self.entry['attempts']['bootstrap']['exitCode']=5
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_foreign_uid_cannot_capture_identity(self):
        self.manager.reader.read.return_value={**IDENTITY,'uid':0}
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_foreign_parent_cannot_capture_identity(self):
        self.manager.reader.read.return_value={**IDENTITY,'ppid':12}
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_nonleader_cannot_capture_identity(self):
        self.manager.reader.read.return_value={**IDENTITY,'pgid':32529}
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_foreign_executable_cannot_capture_identity(self):
        self.manager.reader.read.return_value={**IDENTITY,'executable':'/unrelated/Python'}
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_birth_change_cannot_capture_identity(self):
        self.manager.reader.read.side_effect=[copy.deepcopy(IDENTITY),{**IDENTITY,'birthUsec':123457}]
        with self.assertRaisesRegex(RuntimeError,'repeat_bootstrap'):self.manager._query('fixture',self.entry)
        self.assertNotIn('bootstrapIdentity',self.entry)
    def test_no_pid_does_not_invent_identity(self):
        self.manager.state={'runs':0}
        self.manager._query('fixture',self.entry)
        self.assertNotIn('bootstrapIdentity',self.entry)
    def test_preexisting_ready_identity_is_not_replaced(self):
        self.entry['wrapperIdentity']=copy.deepcopy(IDENTITY)
        self.manager._query('fixture',self.entry)
        self.manager.reader.read.assert_not_called()
    def test_multiple_runs_are_rejected(self):
        self.manager.state['runs']=2
        with self.assertRaises(RuntimeError):self.manager._query('fixture',self.entry)
    def test_unrelated_uid_minus_two_and_stat_do_not_grant_or_block_ownership(self):
        raw=b'97472 1 97472 -2 UNKNOWN!\n32528 1 32528 501 S\n'
        self.assertEqual([r['pid'] for r in c.select_related_rows(raw,{32528})],[32528])
    def test_related_uid_minus_two_is_rejected_and_retained(self):
        with self.assertRaises(c.ProcessRowRefused) as caught:c.select_related_rows(b'32528 1 32528 -2 S\n',{32528})
        self.assertEqual(caught.exception.safe_row['fields'][3],'-2')
    def test_related_child_outside_group_is_visible(self):
        rows=c.select_related_rows(b'32529 32528 32529 501 S\n',{32528})
        self.assertEqual(rows[0]['pid'],32529)
    def test_ambiguous_global_selector_is_rejected_and_retained(self):
        with self.assertRaises(c.ProcessRowRefused) as caught:c.select_related_rows(b'bad 1 99 0 S\n',{32528})
        self.assertEqual(caught.exception.safe_row['fields'][0],'bad')
    def test_related_unknown_stat_is_rejected(self):
        with self.assertRaises(c.ProcessRowRefused):c.select_related_rows(b'32528 1 32528 501 unknown!\n',{32528})
    def test_related_extra_fields_are_rejected(self):
        with self.assertRaises(c.ProcessRowRefused):c.select_related_rows(b'32528 1 32528 501 S extra\n',{32528})
    def test_unknown_prior_signal_prevents_every_new_mutation(self):
        self.entry['attempts']['term']={**copy.deepcopy(KNOWN),'complete':False}
        with self.assertRaisesRegex(RuntimeError,'no_mutation_after_unknown'):
            self.manager._dispatch_once(self.entry,'kill',['/bin/launchctl','kill','SIGKILL',c.TARGET],cleanup=True)
        self.manager.journal.append.assert_not_called()
    def test_unknown_readonly_helper_prevents_new_mutation(self):
        self.manager.commands.public.return_value['unknownCommandCount']=1
        with self.assertRaisesRegex(RuntimeError,'all_previous_command_outcomes_known'):
            self.manager._dispatch_once(self.entry,'term',['/bin/launchctl','kill','SIGTERM',c.TARGET],cleanup=True)
        self.manager.journal.append.assert_not_called()
    def test_unclosed_readonly_helper_prevents_new_mutation(self):
        self.manager.commands.public.return_value['allOwnedCommandsStopped']=False
        with self.assertRaisesRegex(RuntimeError,'all_previous_command_outcomes_known'):
            self.manager._dispatch_once(self.entry,'term',['/bin/launchctl','kill','SIGTERM',c.TARGET],cleanup=True)
        self.manager.journal.append.assert_not_called()
    def test_known_prior_signal_is_not_replayed(self):
        self.entry['attempts']['term']=copy.deepcopy(KNOWN)
        with self.assertRaisesRegex(RuntimeError,'one_mutation_attempt'):
            self.manager._dispatch_once(self.entry,'term',['/bin/launchctl','kill','SIGTERM',c.TARGET],cleanup=True)
        self.manager.journal.append.assert_not_called()
    def test_other_target_cannot_receive_signal(self):
        self.entry['target']='gui/501/unrelated'
        with self.assertRaisesRegex(RuntimeError,'only_fixed_fresh'):
            self.manager._dispatch_once(self.entry,'term',['/bin/launchctl','kill','SIGTERM',self.entry['target']],cleanup=True)
    def prepare_retired(self):
        self.manager._check_registration_files=mock.Mock()
        self.manager._query=mock.Mock(return_value={'pid':None,'runs':1,'last exit code':None,'last terminating signal':None})
        self.manager._native_absent=mock.Mock(return_value={'pid':IDENTITY['pid'],'bytes':0,'errno':3})
        self.manager._rows=mock.Mock(return_value=[])
        self.entry['groups']={IDENTITY['pgid']}
    def test_unknown_terminal_never_proves_retirement(self):
        self.prepare_retired()
        with self.assertRaisesRegex(RuntimeError,'known_retired_terminal'):self.manager._retired(self.entry,IDENTITY)
        self.manager._native_absent.assert_not_called()
    def test_kill_requires_exact_known_signal_terminal(self):
        self.prepare_retired();self.entry['attempts']['kill']=copy.deepcopy(KNOWN)
        self.manager._query.return_value['last exit code']=0
        with self.assertRaisesRegex(RuntimeError,'exact_sigkill_terminal'):self.manager._retired(self.entry,IDENTITY)
    def test_sigkill_retirement_requires_absent_pid_and_related_group(self):
        self.prepare_retired();self.entry['attempts']['kill']=copy.deepcopy(KNOWN)
        self.manager._query.return_value['last terminating signal']='Killed: 9'
        result=self.manager._retired(self.entry,IDENTITY)
        self.assertEqual(result['relatedRows'],[])
        self.assertEqual(self.manager._native_absent.call_count,2)
    def test_retired_child_blocks_bootout(self):
        self.prepare_retired();self.manager._query.return_value['last exit code']=1
        self.manager.reader.children.return_value=[32529]
        with self.assertRaisesRegex(RuntimeError,'retired_no_group_or_children'):self.manager._retired(self.entry,IDENTITY)
    def test_live_child_blocks_signal_authority(self):
        self.manager._check_registration_files=mock.Mock()
        self.manager._query=mock.Mock(return_value={'pid':IDENTITY['pid'],'runs':1})
        self.manager._rows=mock.Mock(return_value=[{'pid':IDENTITY['pid'],'ppid':1,'pgid':IDENTITY['pgid'],'uid':501,'state':'S'}])
        self.manager.reader.children.return_value=[32529]
        with self.assertRaisesRegex(RuntimeError,'repeat_birth_and_no_native_children'):
            self.manager._owned_live(self.entry,IDENTITY)
    def test_changed_birth_blocks_signal_authority(self):
        self.manager._check_registration_files=mock.Mock()
        self.manager._query=mock.Mock(return_value={'pid':IDENTITY['pid'],'runs':1})
        self.manager.reader.read.return_value={**IDENTITY,'birthSec':IDENTITY['birthSec']+1}
        with self.assertRaisesRegex(RuntimeError,'same_current_complete_birth'):
            self.manager._owned_live(self.entry,IDENTITY)

def run():
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SafetyGates)
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    print(json.dumps({'schema':'heptabao.mac-fresh-synthetic-safety-gates.r1','testsRun':result.testsRun,
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'ok':result.wasSuccessful(),'serviceMutationExecuted':False,'signalDispatched':False},sort_keys=True))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(run())
