import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import native_snapshot_cli_live as fixture


class NativeSnapshotCliGuards(unittest.TestCase):
    def setUp(self):
        # Guard-only scratch stays beside this SSD-staged source, never ambient TMP.
        self.directory = tempfile.TemporaryDirectory(prefix='guard-', dir=Path(fixture.__file__).parent)
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def archive(self, name='input.snap', *, state=b'HBB2'+b'encrypted-placeholder'*20, extra=False):
        metadata = json.dumps({'format':'heptabao-native-snapshot-v1',
            'state_format':'heptabao-encrypted-backup-v1/HBB2','generation':7,'state_bytes':len(state)}).encode()
        sums = (hashlib.sha256(metadata).hexdigest()+'  meta.json\n'+hashlib.sha256(state).hexdigest()+'  state.bin\n').encode()
        path = self.root/name
        with tarfile.open(path,'w:gz',format=tarfile.USTAR_FORMAT) as archive:
            for name,data in [('meta.json',metadata),('state.bin',state),('SHA256SUMS',sums),('SHA256SUMS.sealed',b'authenticated-placeholder')]:
                member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
            if extra:
                member=tarfile.TarInfo('foreign');archive.addfile(member,io.BytesIO())
        return path

    def test_required_real_milestones_unique_not_case_count(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'additional_actual_observation','passed':True}]+rows[-1:]))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        self.assertFalse(fixture.complete([{'case':f'case_{i}','passed':True} for i in range(1000)]+[{'case':'complete','passed':True}]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':True,'raw':'secret'}]))

    def test_archive_is_streamed_with_native_metadata_and_exact_members(self):
        path=self.archive()
        summary=fixture.inspect_archive(path)
        self.assertEqual(summary['generation'],7)
        self.assertEqual(summary['members'],fixture.NAMES)
        self.assertNotIn('state',summary)
        with self.assertRaises(ValueError):fixture.inspect_archive(self.archive('extra.snap',extra=True))
        with self.assertRaises(ValueError):fixture.inspect_archive(self.archive('foreign.snap',state=b'not-HBB2'))

    def test_tamper_preserves_outer_gzip_tar_and_plain_checksums(self):
        original=self.archive();tampered=self.root/'tampered.snap'
        fixture.tamper_sealed(original,tampered)
        self.assertEqual(fixture.inspect_archive(original),fixture.inspect_archive(tampered))
        with tarfile.open(original,'r:gz') as a,tarfile.open(tampered,'r:gz') as b:
            for name in fixture.NAMES[:-1]:
                self.assertEqual(a.extractfile(name).read(),b.extractfile(name).read())
            before=a.extractfile(fixture.NAMES[-1]).read();after=b.extractfile(fixture.NAMES[-1]).read()
            self.assertEqual(before[1:],after[1:]);self.assertEqual(before[0]^after[0],1)
        self.assertEqual(tampered.stat().st_mode & 0o777,0o600)

    def test_cli_is_fixed_operator_command_with_no_ambient_credentials(self):
        instance=SimpleNamespace(address='https://127.0.0.1:1234',root=self.root,token='synthetic-token')
        with mock.patch.dict(os.environ,{'VAULT_NAMESPACE':'evil','HTTPS_PROXY':'bad','BAO_SKIP_VERIFY':'true'}):
            env=fixture.cli_environment(instance,self.root)
        self.assertNotIn('VAULT_NAMESPACE',env);self.assertNotIn('HTTPS_PROXY',env);self.assertNotIn('BAO_SKIP_VERIFY',env)
        self.assertEqual(env['TMPDIR'],str(self.root));self.assertEqual(env['BAO_MAX_RETRIES'],'0')
        with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=2,stderr=b'Code: 400. Errors:\nredacted')) as run:
            self.assertTrue(fixture.cli(Path('/fixed/bao'),instance,self.root,'restore',self.root/'input.snap',True,400))
            args=run.call_args.args[0]
            self.assertEqual(args[:6],['/fixed/bao','operator','raft','snapshot','restore','-force'])
            self.assertNotIn(instance.token,args)
        with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=2,stderr=b'Code: 503. Errors:')):
            self.assertFalse(fixture.cli(Path('/fixed/bao'),instance,self.root,'restore',self.root/'input.snap',True,400))

    def test_work_parent_and_report_samples_have_no_ambient_fallback(self):
        self.assertEqual(fixture.private_parent(self.root),self.root)
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):fixture.private_parent(link)
        path=self.root/'scan';path.write_bytes(b'x'*(fixture.BLOCK-3)+b'synthetic-secret')
        self.assertTrue(fixture.contains_any(path,[b'synthetic-secret']))
        self.assertFalse(fixture.contains_any(path,[b'absent-secret']))

if __name__=='__main__':unittest.main()
