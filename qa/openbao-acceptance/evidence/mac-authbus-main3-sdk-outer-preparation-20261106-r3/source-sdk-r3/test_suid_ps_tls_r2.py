#!/usr/bin/env python3
"""Negative and deadline gates for the fixed Mac PS exception and TLS readiness.

Mocks perform no subprocess, filesystem mutation, signal or network action.
Actual fixed system-PS lifecycle qualification is a separate source-bound job.
"""
import copy
import errno
import hashlib
import json
import types
import unittest
from contextlib import ExitStack
from unittest import mock
import mac_owned_unreaped_r1 as u
import mac_owned_commands_r1 as commands
import tls_complete_http_probe as tls

class FixedPsGates(unittest.TestCase):
    def setUp(self):
        self.child=types.SimpleNamespace(pid=2345,args=list(u.FIXED_PS_ARGV),returncode=None,wait=mock.Mock())
        self.row={'pid':2345,'ppid':1234,'pgid':2345,'uid':0,'state':'R','start':'Fri Nov  6 22:00:00 2026'}
        self.pin={'identity':list(u.FIXED_PS_IDENTITY),'sha256':u.FIXED_PS_SHA256}
        self.contract={'schema':'heptabao.fixed-system-ps-child.r1','argv':list(u.FIXED_PS_ARGV),
            'launcherPid':1234,'callerUid':501,'pin':self.pin}
        self.owner={'ps':u.stable(self.row),'sid_observed_while_live':2345,'captured_exit':None,
            'fixedPsContract':self.contract}
    def base(self,rows=None):
        st=ExitStack()
        for target,value in ((u.os,'getpid'),(u.os,'geteuid')):
            st.enter_context(mock.patch.object(target,value,return_value=1234 if value=='getpid' else 501))
        st.enter_context(mock.patch.object(u,'require_waitid'))
        st.enter_context(mock.patch.object(u,'ps_rows',return_value=[self.row] if rows is None else rows))
        st.enter_context(mock.patch.object(u,'fixed_ps_pin',return_value=self.pin))
        st.enter_context(mock.patch.object(u,'exit_observation',return_value=None))
        st.enter_context(mock.patch.object(u.os,'getpgid',return_value=2345))
        st.enter_context(mock.patch.object(u.os,'getsid',return_value=2345))
        st.enter_context(mock.patch.object(u.time,'monotonic',return_value=1.0))
        return st
    def pin_context(self,*,bad=None,wrong_hash=False,changed=False,caller=501,expired=False):
        st=ExitStack()
        names=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        info=dict(zip(names,u.FIXED_PS_IDENTITY))
        if bad:info.update(bad)
        state=types.SimpleNamespace(**info)
        later=types.SimpleNamespace(**{**info,'st_ino':info['st_ino']+1})
        raw=b'x'*u.FIXED_PS_BYTES
        st.enter_context(mock.patch.object(u.os,'getuid',return_value=caller))
        st.enter_context(mock.patch.object(u.os,'geteuid',return_value=caller))
        st.enter_context(mock.patch.object(u.time,'monotonic',return_value=2.0 if expired else 0.0))
        st.enter_context(mock.patch.object(u.os,'lstat',return_value=state))
        st.enter_context(mock.patch.object(u.os,'fstat',side_effect=[state,later] if changed else None,return_value=state))
        self.open=st.enter_context(mock.patch.object(u.os,'open',return_value=99))
        self.close=st.enter_context(mock.patch.object(u.os,'close'))
        parts=[raw[i:i+65536] for i in range(0,len(raw),65536)]+[b'']
        st.enter_context(mock.patch.object(u.os,'read',side_effect=parts))
        if not wrong_hash:st.enter_context(mock.patch.object(u,'FIXED_PS_SHA256',hashlib.sha256(raw).hexdigest()))
        return st
    def test_unrelated_command_has_no_privilege_contract(self):
        with mock.patch.object(u,'fixed_ps_pin') as pin:
            self.assertIsNone(u.prepare_fixed_ps_contract(['/usr/bin/true'],until=2))
            pin.assert_not_called()
    def test_wrong_ps_argv_rejected_before_any_child(self):
        with mock.patch.object(commands,'require_waitid'),mock.patch.object(commands.subprocess,'Popen') as popen:
            with self.assertRaisesRegex(u.Refusal,'fixed_ps_exact_argv_before_launch'):
                commands.Commands(commands.Signals()).run('forbidden-ps',['/bin/ps','-ef'],until=u.time.monotonic()+4)
            popen.assert_not_called()
    def test_fixed_ps_requires_exact_caller_501(self):
        with self.pin_context(caller=0):
            with self.assertRaisesRegex(u.Refusal,'exact_caller'):u.fixed_ps_pin(until=1)
            self.open.assert_not_called()
    def test_fixed_ps_rejects_mode_change(self):
        with self.pin_context(bad={'st_mode':0o100755}):
            with self.assertRaisesRegex(u.Refusal,'file_identity'):u.fixed_ps_pin(until=1)
            self.open.assert_not_called()
    def test_fixed_ps_rejects_owner_change(self):
        with self.pin_context(bad={'st_uid':501}):
            with self.assertRaises(u.Refusal):u.fixed_ps_pin(until=1)
            self.open.assert_not_called()
    def test_fixed_ps_rejects_hash_change_and_closes(self):
        with self.pin_context(wrong_hash=True):
            with self.assertRaisesRegex(u.Refusal,'whole_file_hash'):u.fixed_ps_pin(until=1)
            self.close.assert_called_once_with(99)
    def test_fixed_ps_rejects_changed_file_and_closes(self):
        with self.pin_context(changed=True):
            with self.assertRaisesRegex(u.Refusal,'named_file_unchanged'):u.fixed_ps_pin(until=1)
            self.close.assert_called_once_with(99)
    def test_fixed_ps_deadline_is_existing_and_prelaunch(self):
        with self.pin_context(expired=True):
            with self.assertRaisesRegex(u.Refusal,'deadline_exhausted'):u.fixed_ps_pin(until=1)
            self.open.assert_not_called()
    def test_fixed_ps_pin_uses_nofollow_and_complete_hash(self):
        with self.pin_context():
            self.assertEqual(u.fixed_ps_pin(until=1)['identity'],list(u.FIXED_PS_IDENTITY))
            self.assertTrue(self.open.call_args.args[1]&u.os.O_NOFOLLOW)
            self.close.assert_called_once_with(99)
    def test_contract_rejects_changed_child_argv(self):
        self.child.args=['/bin/ps','-ef']
        with self.base():
            with self.assertRaisesRegex(u.Refusal,'direct_child_contract'):
                u.verify_fixed_ps_contract(self.child,self.contract,until=2)
    def test_contract_rejects_changed_launcher(self):
        self.contract['launcherPid']=1111
        with self.base():
            with self.assertRaisesRegex(u.Refusal,'direct_child_contract'):
                u.verify_fixed_ps_contract(self.child,self.contract,until=2)
    def test_contract_rejects_changed_prelaunch_pin(self):
        self.contract['pin']={'identity':[],'sha256':'0'*64}
        with self.base():
            with self.assertRaisesRegex(u.Refusal,'binding_changed'):
                u.verify_fixed_ps_contract(self.child,self.contract,until=2)
    def test_arbitrary_root_child_remains_forbidden(self):
        with self.base():
            with self.assertRaisesRegex(u.Refusal,'owned_child_scope_mismatch'):
                u.capture_child(self.child,until=2)
            self.child.wait.assert_not_called()
    def test_fixed_ps_root_leader_accepts_without_libproc_or_reap(self):
        with self.base():
            owner=u.capture_child(self.child,until=2,fixed_ps_contract=self.contract)
            self.assertEqual(owner['ps']['uid'],0);self.assertEqual(owner['sid_observed_while_live'],2345)
            self.assertEqual(owner['fixedPsContract'],self.contract)
            self.child.wait.assert_not_called()
    def test_foreign_parent_or_group_still_forbidden(self):
        for field in ('ppid','pgid'):
            with self.subTest(field=field),self.base(rows=[{**self.row,field:7777}]):
                with self.assertRaisesRegex(u.Refusal,'owned_child_scope_mismatch'):
                    u.capture_child(self.child,until=2,fixed_ps_contract=self.contract)
    def test_retained_exit_never_reaps_during_capture(self):
        event={'pid':2345,'signo':20,'code':1,'status':0}
        with self.base(rows=[{**self.row,'state':'Z'}]),mock.patch.object(u,'exit_observation',return_value=event):
            owner=u.capture_child(self.child,until=2,fixed_ps_contract=self.contract)
            self.assertEqual(owner['captured_exit'],event);self.child.wait.assert_not_called()
    def test_changed_start_identity_blocks_verification(self):
        with self.base(rows=[{**self.row,'start':'another lifetime'}]):
            with self.assertRaisesRegex(u.Refusal,'identity_changed_no_signal'):
                u.verify_unreaped(self.child,self.owner,until=2)
    def test_changed_effective_uid_blocks_verification(self):
        with self.base(rows=[{**self.row,'uid':501}]):
            with self.assertRaisesRegex(u.Refusal,'identity_changed_no_signal'):
                u.verify_unreaped(self.child,self.owner,until=2)
    def test_no_other_uid501_group_member_allowed_for_system_ps(self):
        other={**self.row,'pid':2346,'ppid':2345,'uid':501}
        with self.base(),mock.patch.object(u,'verify_unreaped'),mock.patch.object(u,'ps_rows',return_value=[self.row,other]):
            with self.assertRaisesRegex(u.Refusal,'no_other_group_or_direct_child'):
                u.live_group(self.child,self.owner,until=2)
    def test_no_other_uid0_group_member_allowed_for_system_ps(self):
        other={**self.row,'pid':2346,'ppid':2345}
        with self.base(),mock.patch.object(u,'verify_unreaped'),mock.patch.object(u,'ps_rows',return_value=[self.row,other]):
            with self.assertRaisesRegex(u.Refusal,'no_other_group_or_direct_child'):
                u.live_group(self.child,self.owner,until=2)
    def test_escaped_direct_child_blocks_system_ps_custody(self):
        other={**self.row,'pid':2346,'ppid':2345,'pgid':9876,'uid':501}
        with self.base(),mock.patch.object(u,'verify_unreaped'),mock.patch.object(u,'ps_rows',return_value=[self.row,other]):
            with self.assertRaisesRegex(u.Refusal,'no_other_group_or_direct_child'):
                u.live_group(self.child,self.owner,until=2)
    def test_standard_uid501_group_remains_standard(self):
        owner={**self.owner,'fixedPsContract':None}
        with self.base():
            self.assertTrue(u.fixed_ps_group_uid({**self.row,'uid':501},self.child,owner))
            self.assertFalse(u.fixed_ps_group_uid(self.row,self.child,owner))
    def test_already_reaped_child_never_signalled(self):
        self.child.returncode=0
        with self.base(),mock.patch.object(u.os,'killpg') as kill:
            result=u.stop_once_unreaped(self.child,self.owner)
            self.assertFalse(result['ok']);self.assertTrue(result['outcomeUnknown'])
            self.assertEqual(result['cleanupCaps'],{'term':1,'wait':5,'group':3,'psMax':4})
            kill.assert_not_called()

class TlsReadinessGates(unittest.TestCase):
    def run_probe(self,*,failures=(),advance=0.1,handshake_error=None,wrong_pin=False,
                  incomplete=False,non_refused=None,body_delay=0,always_refused=False):
        clock=[0.0]
        def sleep(value):clock[0]+=value if advance is None else advance
        self.raw=mock.Mock();self.socket=mock.Mock();self.socket.version.return_value='TLSv1.3'
        certificate=b'synthetic-public-certificate';self.socket.getpeercert.return_value=certificate
        context=mock.Mock();context.wrap_socket.return_value=self.socket
        if handshake_error:context.wrap_socket.side_effect=handshake_error
        value={'initialized':False,'sealed':True};body=json.dumps(value).encode()
        response=mock.Mock(status=501,reason='Not Implemented',version=11)
        response.getheader.side_effect=lambda name:str(len(body)) if name=='Content-Length' else None
        def read(_):
            clock[0]+=body_delay
            return body[:-1] if incomplete else body
        response.read.side_effect=read
        refused=ConnectionRefusedError(errno.ECONNREFUSED,'refused')
        pending=list(failures)
        def connect(*args,**kwargs):
            if non_refused:raise non_refused
            if always_refused:raise refused
            if pending:raise pending.pop(0)
            return self.raw
        with mock.patch.object(tls.time,'monotonic',side_effect=lambda:clock[0]), \
             mock.patch.object(tls.time,'sleep',side_effect=sleep), \
             mock.patch.object(tls.ssl,'create_default_context',return_value=context), \
             mock.patch.object(tls.socket,'create_connection',side_effect=connect) as call, \
             mock.patch.object(tls.http.client,'HTTPResponse',return_value=response) as http:
            record=tls.probe('127.0.0.1',61620,'localhost','synthetic-ca',
                '0'*64 if wrong_pin else hashlib.sha256(certificate).hexdigest(),'mock')
            self.connect_count=call.call_count;self.http_count=http.call_count
        self.context=context;return record
    def test_immediate_ready_one_tls_one_http(self):
        r=self.run_probe();self.assertTrue(r['passed'])
        self.assertEqual((r['connection_attempts'],r['connection_refusals'],r['request_count']),(1,0,1))
        self.socket.sendall.assert_called_once();self.context.wrap_socket.assert_called_once()
    def test_two_refusals_then_ready_sends_one_request(self):
        refused=ConnectionRefusedError(errno.ECONNREFUSED,'refused')
        r=self.run_probe(failures=[refused,refused]);self.assertTrue(r['passed'])
        self.assertEqual((r['connection_attempts'],r['connection_refusals'],r['request_count']),(3,2,1))
        self.socket.sendall.assert_called_once();self.assertEqual(r['timeout_seconds'],15)
    def test_original_fifteen_seconds_expires_before_any_http(self):
        r=self.run_probe(always_refused=True,advance=None)
        self.assertFalse(r['passed']);self.assertEqual(r['error_type'],'TimeoutError')
        self.assertLessEqual(r['elapsed_seconds'],15.001);self.assertEqual(r['request_count'],0)
        self.context.wrap_socket.assert_not_called();self.socket.sendall.assert_not_called()
    def test_other_connect_error_never_retries(self):
        r=self.run_probe(non_refused=OSError(errno.EHOSTUNREACH,'unreachable'))
        self.assertFalse(r['passed']);self.assertEqual(self.connect_count,1);self.assertEqual(r['request_count'],0)
    def test_socket_timeout_never_retries(self):
        r=self.run_probe(non_refused=TimeoutError('connect timeout'))
        self.assertFalse(r['passed']);self.assertEqual(self.connect_count,1);self.assertEqual(r['request_count'],0)
    def test_tls_verification_failure_never_retries_or_sends(self):
        r=self.run_probe(handshake_error=tls.ssl.SSLCertVerificationError('verify failure'))
        self.assertFalse(r['passed']);self.assertEqual(self.connect_count,1)
        self.assertEqual(r['request_count'],0);self.raw.close.assert_called_once()
    def test_wrong_leaf_never_retries_or_sends(self):
        r=self.run_probe(wrong_pin=True);self.assertFalse(r['passed'])
        self.assertEqual(self.connect_count,1);self.assertEqual(r['request_count'],0)
        self.socket.close.assert_called_once()
    def test_incomplete_http_never_retries(self):
        r=self.run_probe(incomplete=True);self.assertFalse(r['passed'])
        self.assertEqual(self.connect_count,1);self.assertEqual(r['request_count'],1)
        self.assertEqual(self.http_count,1);self.socket.close.assert_called_once()
    def test_late_complete_http_cannot_pass_deadline(self):
        r=self.run_probe(body_delay=16);self.assertFalse(r['passed'])
        self.assertEqual(r['error_type'],'TimeoutError');self.assertEqual(r['request_count'],1)
    def test_finite_attempt_bound_when_mock_clock_stalls(self):
        r=self.run_probe(always_refused=True,advance=0)
        self.assertFalse(r['passed']);self.assertEqual(r['connection_attempts'],256)
        self.assertEqual(r['request_count'],0);self.context.wrap_socket.assert_not_called()

def run():
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (FixedPsGates,TlsReadinessGates)])
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    value={'schema':'heptabao.mac-fixed-ps-tls-readiness-gates.r2','testsRun':result.testsRun,
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'ok':result.wasSuccessful(),'serviceMutationExecuted':False,'signalDispatched':False,
        'realNetworkOrFilesystemIoPerformed':False}
    print(json.dumps(value,sort_keys=True))
    return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(run())
