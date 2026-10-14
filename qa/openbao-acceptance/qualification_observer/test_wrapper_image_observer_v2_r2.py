import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from wrapper_image_observer_v2 import (ObservationGone, ObservationRejected,
                                    descriptor, observe_image, require_equal)


class PureIdentityTests(unittest.TestCase):
    def test_equal_identity(self):
        require_equal({'pid': 2, 'uid': 10}, {'pid': 2, 'uid': 10}, 'identity')

    def test_different_uid_is_rejected(self):
        with self.assertRaises(ObservationRejected):
            require_equal({'uid': 1}, {'uid': 2}, 'identity')


@unittest.skipUnless(hasattr(os, 'memfd_create') and Path('/proc/self/exe').exists(),
                     'requires Linux procfs and memfd')
class KernelImageTests(unittest.TestCase):
    def setUp(self):
        self.image = os.memfd_create('heptabao-owned-observer-test',
                                    os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x10)
        self.original = Path(shutil.which('sleep')).read_bytes()
        os.write(self.image, self.original)
        os.fchmod(self.image, 0o500)
        self.digest = hashlib.sha256(self.original).hexdigest()
        self.child = None
        self.owner = os.getpid()
        self.owner_ticks = self.ticks(self.owner)

    def tearDown(self):
        if self.child is not None:
            if self.child.poll() is None:
                self.child.terminate()
            self.child.wait(timeout=5)
        os.close(self.image)

    @staticmethod
    def ticks(pid):
        return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]

    def launch(self, sealed=True):
        if sealed:
            fcntl.fcntl(self.image, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                        fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        self.child = subprocess.Popen([f'/proc/{self.owner}/fd/{self.image}', '20'])
        self.identity = {'pid': self.child.pid, 'start_ticks': self.ticks(self.child.pid),
                         'exe_descriptor': descriptor(os.stat(f'/proc/{self.child.pid}/exe'))}

    def observe(self, **overrides):
        args = dict(pid=self.child.pid, expected=self.identity, digest=self.digest,
                    producer_pid=self.owner, producer_start_ticks=self.owner_ticks,
                    producer_fd=self.image)
        args.update(overrides)
        return observe_image(**args)

    def test_same_sealed_image(self):
        self.launch()
        self.assertEqual(self.observe()['producer_slot_state'], 'same_image')

    def test_reused_parent_slot_preserves_actual_image_authority(self):
        self.launch()
        with tempfile.TemporaryFile() as unrelated:
            os.dup2(unrelated.fileno(), self.image)
            with self.assertRaises(OSError) as failure:
                fcntl.fcntl(self.image, fcntl.F_GET_SEALS)
            self.assertEqual(failure.exception.errno, 22)
            witness = self.observe()
            self.assertEqual(witness['producer_slot_state'], 'reused')
            self.assertEqual(witness['actual_executable_sha256'], self.digest)
            self.assertEqual(witness['actual_memfd_seals'] & 15, 15)

    def test_wrong_actual_hash_rejected(self):
        self.launch()
        with self.assertRaises(ObservationRejected):
            self.observe(digest='0' * 64)

    def test_unsealed_actual_image_rejected(self):
        self.launch(sealed=False)
        with self.assertRaises(ObservationRejected):
            self.observe()

    def test_reused_child_identity_rejected(self):
        self.launch()
        with self.assertRaises(ObservationRejected):
            self.observe(expected={**self.identity, 'start_ticks': '0'})

    def test_reused_owner_identity_rejected(self):
        self.launch()
        with self.assertRaises(ObservationRejected):
            self.observe(producer_start_ticks='0')

    def test_foreign_image_descriptor_rejected(self):
        self.launch()
        bad = {**self.identity, 'exe_descriptor': {**self.identity['exe_descriptor'], 'inode': 0}}
        with self.assertRaises(ObservationRejected):
            self.observe(expected=bad)

    def test_exited_child_gives_no_positive_witness(self):
        self.launch()
        self.child.terminate()
        self.child.wait(timeout=5)
        with self.assertRaises(ObservationGone):
            self.observe()

    def test_live_permission_error_remains_failure(self):
        self.launch()
        with mock.patch('wrapper_image_observer_v2.fcntl.fcntl',
                        side_effect=PermissionError(13, 'synthetic permission rejection')):
            with self.assertRaises(PermissionError):
                self.observe()
        self.assertIsNone(self.child.poll())

    def test_permission_on_kernel_confirmed_exit_gives_no_witness(self):
        self.launch()
        def exit_then_deny(*args):
            self.child.terminate()
            self.child.wait(timeout=5)
            raise PermissionError(13, 'synthetic exit race')
        with mock.patch('wrapper_image_observer_v2.fcntl.fcntl', side_effect=exit_then_deny):
            with self.assertRaises(ObservationGone):
                self.observe()

    def test_regular_disk_executable_is_not_a_sealed_memfd(self):
        with tempfile.TemporaryDirectory(prefix='heptabao-observer-owned-') as directory:
            disk_image = Path(directory) / 'sleep'
            disk_image.write_bytes(self.original)
            disk_image.chmod(0o500)
            self.child = subprocess.Popen([str(disk_image), '20'])
            self.identity = {'pid': self.child.pid, 'start_ticks': self.ticks(self.child.pid),
                             'exe_descriptor': descriptor(os.stat(f'/proc/{self.child.pid}/exe'))}
            with self.assertRaises(OSError) as failure:
                self.observe()
            self.assertEqual(failure.exception.errno, 22)



if __name__ == '__main__':
    unittest.main(verbosity=2)
