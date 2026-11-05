import copy
import json
import time
import unittest
from unittest import mock
import native_restore_gate_controller as f


class GateControllerGuards(unittest.TestCase):
    def value(self,phase=f.PHASES[0]):
        return {'version':1,'phase':phase,'nonce':'a'*64,'pid':123,'old_root':'b'*64,'new_root':'c'*64,
                'local_generation':42,'leader_id':2,'stage_count':3,'stage_index':71,
                'commit_index':None if phase==f.PHASES[0] else 72}
    def validate(self,value):
        return f.validate_ready(value,phase=value['phase'],nonce='a'*64,pid=123,node_id=2,generation=42)

    def test_p_and_q_have_distinct_stage_commit_evidence(self):
        for phase in f.PHASES:self.assertTrue(self.validate(self.value(phase))['nonce_matched'])
        for phase,key,bad in [(f.PHASES[0],'stage_count',0),(f.PHASES[0],'commit_index',72),
                (f.PHASES[1],'commit_index',None),(f.PHASES[1],'commit_index',71),(f.PHASES[1],'commit_index',0),
                (f.PHASES[0],'stage_index',0)]:
            value=self.value(phase);value[key]=bad
            with self.assertRaises(ValueError):self.validate(value)

    def test_exact_binding_and_redacted_evidence(self):
        for key,bad in [('pid',124),('nonce','d'*64),('local_generation',43),('leader_id',1),
                ('version',True),('stage_index',True),('new_root','b'*64),('old_root','0'*64),
                ('stage_count',True),('new_root','C'*64)]:
            value=self.value();value[key]=bad
            with self.assertRaises(ValueError):self.validate(value)
        value=self.value();value['password']='SECRET_SENTINEL'
        with self.assertRaises(ValueError):self.validate(value)
        safe=self.validate(self.value());self.assertNotIn('nonce',safe)
        self.assertEqual(safe['root_source'],'feature_instrumentation')

    def test_fragmented_frame_and_one_shot(self):
        gate=f.GateController(f.PHASES[0],'a'*64);self.addCleanup(gate.close)
        data=json.dumps(self.value(),separators=(',',':')).encode();self.assertLessEqual(len(data),510)
        gate.child.sendall(len(data).to_bytes(2,'big')+data)
        result=gate.ready(pid=123,node_id=2,generation=42,deadline=time.monotonic()+1)
        self.assertEqual(result['stage_index'],71)
        with self.assertRaises(ValueError):gate.ready(pid=123,node_id=2,generation=42,deadline=time.monotonic()+1)
        # Controller sends no release bytes, even after valid readiness.
        gate.child.settimeout(0.01)
        with self.assertRaises(TimeoutError):gate.child.recv(1)

    def test_oversize_eof_duplicate_and_deadline_fail_closed(self):
        samples=[b'\x02\x00',b'\x00\x00',b'\x00\x04{}',
                 len(b'{"version":1,"version":1}').to_bytes(2,'big')+b'{"version":1,"version":1}']
        for data in samples:
            gate=f.GateController(f.PHASES[0],'a'*64)
            try:
                gate.child.sendall(data);gate.child.close()
                with self.assertRaises(ValueError):gate.ready(pid=123,node_id=2,generation=42,deadline=time.monotonic()+1)
            finally:gate.close()
        gate=f.GateController(f.PHASES[0],'a'*64)
        try:
            with self.assertRaises(TimeoutError):gate.ready(pid=123,node_id=2,generation=42,deadline=time.monotonic()-1)
        finally:gate.close()

    def test_fd_zero_suffix_is_fixed(self):
        gate=f.GateController(f.PHASES[0],'a'*64);self.addCleanup(gate.close)
        self.assertEqual(gate.arguments(),['--fixture-native-restore-fd','0','--fixture-native-restore-phase',f.PHASES[0],
                                          '--fixture-native-restore-nonce','a'*64])
        with self.assertRaises(ValueError):f.GateController('not-a-phase','a'*64)
