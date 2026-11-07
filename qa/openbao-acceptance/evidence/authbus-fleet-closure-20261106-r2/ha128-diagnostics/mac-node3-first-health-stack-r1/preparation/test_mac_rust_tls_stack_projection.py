import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('stack_worker_guarded_definitions', HERE / 'mac_rust_tls_worker_stack_r1.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

class ObservationProjectionTests(unittest.TestCase):
    def sample(self, pid=123, path=None):
        return ('Process: heptabao-server [%s]\nPath: %s\nCall graph:\n  Thread_7 heptabao-request\n  10 rustls::server::accept\n' % (pid, path or worker.BIN)).encode()
    def test_exact_synthetic_stack(self):
        self.assertTrue(worker.sample_projection(self.sample(), 123)['sameOriginalPidAndImage'])
    def test_stack_wrong_pid(self):
        with self.assertRaises(worker.Refused): worker.sample_projection(self.sample(124), 123)
    def test_stack_wrong_image(self):
        with self.assertRaises(worker.Refused): worker.sample_projection(self.sample(path='/other/server'), 123)
    def test_stack_duplicate_identity(self):
        with self.assertRaises(worker.Refused): worker.sample_projection(self.sample()+self.sample(), 123)
    def test_exact_synthetic_socket(self):
        raw=b'p123\nf9\ntIPv4\nn192.168.0.8:31040->192.168.0.8:56000\nTST=ESTABLISHED\nTQR=0\nTQS=0\n'
        self.assertTrue(worker.lsof_projection(raw,123)['sameOriginalPid'])
    def test_socket_wrong_pid(self):
        with self.assertRaises(worker.Refused): worker.lsof_projection(b'p124\nf9\n',123)
    def test_socket_foreign_endpoint(self):
        with self.assertRaises(worker.Refused): worker.lsof_projection(b'p123\nf9\nn192.168.0.8:31040->192.168.0.4:1234\n',123)
    def test_socket_unknown_field(self):
        with self.assertRaises(worker.Refused): worker.lsof_projection(b'p123\nf9\nzunknown\n',123)

if __name__ == '__main__': unittest.main(verbosity=2)
