from pathlib import Path
import socket
import tempfile
from types import MethodType,SimpleNamespace
import unittest
from unittest import mock
import native_snapshot_ha_restore_gated_live as f


class GatedFixtureGuards(unittest.TestCase):
    def test_both_complete_phases_are_required_not_a_count(self):
        rows=[{'case':name,'passed':True} for name in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for index in range(len(rows)):self.assertFalse(f.complete(rows[:index]+rows[index+1:]))
        self.assertFalse(f.complete(rows+[rows[0]]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'fixture_exception','passed':True}]))

    def test_direct_socket_stdin_and_ungated_recovery_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            cluster=object.__new__(f.GatedCluster);cluster.phase=f.PHASES[0];cluster.allow_gates=True
            node=SimpleNamespace(root=Path(directory),ha_config=Path(directory)/'ha.json',binary=Path('/instrumented'),
                ordinary_start=mock.Mock(),gate=None,process=None,started_pids=[],wait_ready=mock.Mock())
            node.start=MethodType(cluster._start,node)
            node.start(ha=False)
            node.ordinary_start.assert_called_once_with(ha=False,wait=True)
            child=SimpleNamespace(pid=123)
            def spawn(args,**kwargs):
                self.assertIsInstance(kwargs['stdin'],socket.socket)
                self.assertEqual(kwargs['stdin'].family,socket.AF_UNIX)
                self.assertTrue(kwargs['close_fds']);self.assertTrue(kwargs['start_new_session'])
                self.assertEqual(args[:5],['/instrumented','--config',str(node.root/'server.json'),'--ha-config',str(node.ha_config)])
                self.assertEqual(args[5:7],['--fixture-native-restore-fd','0'])
                return child
            with mock.patch.object(f.subprocess,'Popen',side_effect=spawn) as popen:
                node.start(wait=False)
            self.assertEqual(node.started_pids,[123]);self.assertIs(node.process,child)
            self.assertEqual(node.gate.child.fileno(),-1);node.wait_ready.assert_not_called();popen.assert_called_once()
            gate=node.gate;node.log.close();node.log=None;node.process=None
            cluster.allow_gates=False;node.start(wait=False)
            self.assertEqual(gate.parent.fileno(),-1);self.assertIsNone(node.gate)
            node.ordinary_start.assert_called_with(ha=True,wait=False)

    def test_generation_observation_rejects_bool_and_error(self):
        node=SimpleNamespace(call=mock.Mock(return_value=(200,{'data':{'generation':42}})))
        self.assertEqual(f.generation(node,'token'),42)
        for response in [(200,{'data':{'generation':True}}),(503,{'data':{'generation':42}}),(200,{})]:
            node.call.return_value=response
            with self.assertRaises(f.FixtureError):f.generation(node,'token')
