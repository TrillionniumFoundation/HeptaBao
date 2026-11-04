#!/usr/bin/env python3
"""Narrow local observer refusal/metadata tests; not manager qualification."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


P = Path(__file__).with_name('authbus_owned_proc_runtime_observer.py')
spec = importlib.util.spec_from_file_location('owned_proc_observer',P)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ObserverContract(unittest.TestCase):
    def payload(self):
        root = '/home/qian/fresh-owned-review'
        run = '123456789abc'
        name = 'heptabao-authbus-installed-qa-' + run + '-1.service'
        return {'plan':{'schema':'heptabao.installed-supervisor-system-plan.v1',
                        'actor':{'uid':1000,'gid':1000},'runId':run,'workDir':root,
                        'units':[{'name':name,'ordinal':1,
                                  'runtime':'/run/systemd/system/' + name,
                                  'proposal':root+'/installation-a/'+name}]},
                'ordinal':1,'pid':1234,'startTime':'5678','bindingSha256':'a'*64,
                'controlGroup':'/system.slice/'+name}

    def refused_before_any_filesystem_read(self, payload, code):
        with mock.patch.object(observer.os,'geteuid',return_value=0), \
             mock.patch.object(observer.os,'getegid',return_value=0), \
             mock.patch.dict(observer.os.environ,{'SUDO_UID':'1000','SUDO_GID':'1000'},clear=True), \
             mock.patch.object(observer,'directory') as directory:
            with self.assertRaisesRegex(observer.Refused,code):
                observer.observe(payload,{})
            directory.assert_not_called()

    def test_foreign_cgroup_is_not_observed(self):
        payload = self.payload(); payload['controlGroup'] = '/system.slice/ssh.service'
        self.refused_before_any_filesystem_read(payload,'fixed_system_unit_cgroup')

    def test_unrelated_unit_path_is_not_observed(self):
        payload = self.payload(); payload['plan']['units'][0]['runtime'] = '/etc/passwd'
        self.refused_before_any_filesystem_read(payload,'exact_unit_paths')

    def test_nonfresh_path_is_not_observed(self):
        payload = self.payload(); payload['plan']['workDir'] = '/home/qian/../other'
        self.refused_before_any_filesystem_read(payload,'fixed_work_path')

    def test_root_actor_is_not_accepted(self):
        payload = self.payload(); payload['plan']['actor']['uid'] = 0
        self.refused_before_any_filesystem_read(payload,'original_nonroot_observer')

    def test_metadata_reader_refuses_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'regular').write_bytes(b'x'*5)
            (root/'link').symlink_to(root/'regular')
            fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(observer.Refused):
                    observer.read_at(fd,'regular',4)
                with self.assertRaises(OSError):
                    observer.read_at(fd,'link',10)
                self.assertEqual(observer.read_at(fd,'regular',5),b'x'*5)
            finally:
                os.close(fd)

    def test_metadata_only_path_fd_supports_fstatvfs(self):
        # Actual Linux descriptor operations, no config/auth bytes are read.
        proc = os.open('/proc/self',os.O_RDONLY|os.O_DIRECTORY)
        try:
            fd = os.open('root/usr/bin/python3',os.O_PATH,dir_fd=proc)
            try:
                self.assertIsInstance(os.fstatvfs(fd).f_flag,int)
                self.assertGreater(os.fstat(fd).st_ino,0)
            finally:
                os.close(fd)
        finally:
            os.close(proc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
