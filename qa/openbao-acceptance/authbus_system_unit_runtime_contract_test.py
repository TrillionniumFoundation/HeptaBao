#!/usr/bin/env python3
"""Real temporary files/dirfds with a projected source-owner identity.

No system manager, sudo command or real runtime unit path is used. The tests
exercise the privileged file primitive in the disposable cloud workspace.
This executor maps only UID 0, so source UID/GID 1000 are projected in fstat;
destination root ownership, inodes, exclusive create, IO and unlink are real.
Actual two-user ownership remains a separate X230 live assertion.
"""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name, relative):
    path = Path(__file__).resolve().parents[2] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load('root_unit_contract_helper', 'tools/authbus/authbus_system_unit_runtime.py')
entry = load('root_unit_contract_entry', 'tools/authbus/authbus_coordinator_installed.py')


@unittest.skipUnless(os.geteuid() == 0, 'temporary ownership contract requires this disposable executor root')
class RootUnitFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.run, self.runtime = self.directory / 'run', self.directory / 'virtual-system-runtime'
        self.run.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        actor = {'uid':1000,'gid':1000,'user':'qian','group':'qian'}
        logical = Path('/home/qian/heptabao-authbus-installed-entry-qa/live-fixed')
        self.plan = {'schema':'heptabao.installed-supervisor-system-plan.v1',
                     'actor':actor,'workDir':str(logical),'runId':'123456789abc','units':[]}
        for ordinal, installation, state in ((1,'installation-a','owner-state-a'),
                                             (2,'installation-restored','owner-state-restored')):
            name = 'heptabao-authbus-installed-qa-123456789abc-' + str(ordinal) + '.service'
            config = {'service_scope':{'manager':'system',**actor},'state_dir':str(logical/state),
                      'ca_file':str(logical/'credentials/ca.crt'),
                      'role_id_file':str(logical/'credentials/role_id'),
                      'secret_id_file':str(logical/'credentials/secret_id')}
            with patch.object(entry, 'ENTRY', logical/'code/authbus_coordinator_installed.py'), \
                 patch.object(entry, 'current_service_identity', return_value=actor):
                raw = entry.service_file_bytes(config, logical/installation/'installation.private.json',
                                               logical/installation/'binding-pin.env')
            parent = self.run/installation
            parent.mkdir(mode=0o700)
            proposal = parent/name
            proposal.write_bytes(raw)
            proposal.chmod(0o600)
            self.plan['units'].append({'ordinal':ordinal,'name':name,
                 'proposal':str(logical/installation/name),'runtime':'/run/systemd/system/'+name,
                 'unitSha256':helper.digest(raw),'unitText':raw.decode()})
        self.payload = {'plan':self.plan,'action':'install','ordinal':1,'startDispatched':False,
                        'runIdentity':{**helper.identity(self.run.stat()),'uid':1000,'gid':1000}}
        self.target = self.runtime/self.plan['units'][0]['name']
        def directory(path, owners):
            actual = {str(logical):self.run,'/run/systemd/system':self.runtime}[str(path)]
            return os.open(actual,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        def fstat(fd):
            observed = os.fstat(fd)
            path = os.readlink('/proc/self/fd/' + str(fd))
            if path == str(self.run) or path.startswith(str(self.run) + '/'):
                fields = {name:getattr(observed,name) for name in dir(observed) if name.startswith('st_')}
                return types.SimpleNamespace(**{**fields,'st_uid':1000,'st_gid':1000})
            return observed
        self.os_proxy = types.SimpleNamespace(**{name:getattr(os,name) for name in (
            'O_RDONLY','O_WRONLY','O_DIRECTORY','O_NOFOLLOW','O_CREAT','O_EXCL',
            'geteuid','getegid','open','close','read','stat','fdopen','fchown','fchmod','fsync','unlink')},
            fstat=fstat,environ={'SUDO_UID':'1000','SUDO_GID':'1000'})
        for context in (
            patch.object(helper,'directory',side_effect=directory),
            patch.object(helper,'os',self.os_proxy),
            patch.object(helper.pwd,'getpwuid',return_value=types.SimpleNamespace(pw_name='qian')),
            patch.object(helper.grp,'getgrgid',return_value=types.SimpleNamespace(gr_name='qian')),
        ):
            context.start()
            self.addCleanup(context.stop)

    def test_create_root_0644_then_remove_exact_inode(self):
        result = helper.root_operation(self.payload)
        self.assertEqual((result['identity']['uid'],result['identity']['gid'],result['identity']['mode']),
                         (0,0,0o644))
        removed = helper.root_operation({**self.payload,'action':'remove',
                                         'stopConfirmed':True,'expectedUnitIdentity':result['identity']})
        self.assertTrue(removed['removed'])
        self.assertFalse(self.target.exists())

    def test_existing_destination_is_never_replaced(self):
        helper.root_operation(self.payload)
        before = self.target.read_bytes(),helper.identity(self.target.stat())
        with self.assertRaises(helper.FileMutationFailed) as caught:
            helper.root_operation(self.payload)
        self.assertTrue(caught.exception.result['noFileCreated'])
        self.assertFalse(caught.exception.result['unknown_outcome'])
        self.assertEqual((self.target.read_bytes(),helper.identity(self.target.stat())),before)

    def test_unpinned_proposal_cannot_create_root_file(self):
        proposal = self.run/'installation-a'/self.target.name
        proposal.write_bytes(proposal.read_bytes()+b'ExecStartPost=+unexpected\n')
        with self.assertRaisesRegex(helper.Refused,'exact_proposal_bytes'):
            helper.root_operation(self.payload)
        self.assertFalse(self.target.exists())

    def test_same_bytes_replacement_inode_cannot_be_removed(self):
        result = helper.root_operation(self.payload)
        original = self.runtime/'original-unit-retained'
        self.target.rename(original)
        self.target.write_bytes(original.read_bytes())
        self.target.chmod(0o644)
        with self.assertRaisesRegex(helper.Refused,'exact_owned_unit_removal'):
            helper.root_operation({**self.payload,'action':'remove','stopConfirmed':True,
                                   'expectedUnitIdentity':result['identity']})
        self.assertTrue(self.target.exists() and original.exists())

    def test_existing_symlink_is_never_followed(self):
        foreign = self.runtime/'foreign-file'
        foreign.write_bytes(b'untouched\n')
        self.target.symlink_to(foreign)
        with self.assertRaises(helper.FileMutationFailed):
            helper.root_operation(self.payload)
        self.assertEqual(foreign.read_bytes(),b'untouched\n')
        self.assertTrue(self.target.is_symlink())

    def test_partial_mode_failure_unlinks_only_original_unstarted_fd(self):
        with patch.object(self.os_proxy,'fchmod',side_effect=OSError('injected chmod failure')):
            with self.assertRaises(helper.FileMutationFailed) as caught:
                helper.root_operation(self.payload)
        result = caught.exception.result
        self.assertTrue(result['selfFailureCleanup']['complete'])
        self.assertTrue(result['selfFailureCleanup']['removedOriginalInode'])
        self.assertTrue(result['selfFailureCleanup']['parentSynced'])
        self.assertFalse(result['unknown_outcome'])
        self.assertFalse(self.target.exists())

    def test_failure_does_not_unlink_replacement_at_original_name(self):
        original_fsync = os.fsync
        retained = self.runtime/'original-inode-retained'
        def fail_after_replacement(fd):
            if os.readlink('/proc/self/fd/' + str(fd)) == str(self.target):
                self.target.rename(retained)
                self.target.write_bytes(retained.read_bytes())
                self.target.chmod(0o644)
                raise OSError('injected replacement before fsync reply')
            return original_fsync(fd)
        with patch.object(self.os_proxy,'fsync',side_effect=fail_after_replacement):
            with self.assertRaises(helper.FileMutationFailed) as caught:
                helper.root_operation(self.payload)
        result = caught.exception.result
        self.assertFalse(result['selfFailureCleanup']['complete'])
        self.assertFalse(result['selfFailureCleanup']['removedOriginalInode'])
        self.assertTrue(result['unknown_outcome'])
        self.assertTrue(self.target.exists() and retained.exists())


if __name__ == '__main__':
    unittest.main()
