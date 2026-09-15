"""Prevent fresh-runner dependency failures and weakened real-service gates."""
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_openbao_oracle', ROOT / 'scripts/prepare_openbao_oracle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReadinessPrerequisiteTests(unittest.TestCase):
    def release(self):
        return {'tag_name': 'v'+module.VERSION, 'draft': False, 'prerelease': False,
                'assets': [{'digest': 'sha256:'+module.ARTIFACT_SHA256,
                            'size': 10, 'browser_download_url': module.PREFIX+'fixture.tar.gz'}]}

    def test_acceptance_crypto_dependency_is_explicit_and_pinned(self):
        text = (ROOT/'requirements-plan.txt').read_text()
        self.assertRegex(text, r'(?m)^cryptography==\d+\.\d+\.\d+$')

    def test_only_exact_release_and_archive_are_selected(self):
        release = self.release()
        self.assertEqual(module.select_asset(release), release['assets'][0])
        for key, value in [('tag_name', 'v0.0.0'), ('draft', True), ('prerelease', True), ('draft', 0)]:
            with self.subTest(key=key, value=value):
                changed=copy.deepcopy(release);changed[key]=value
                with self.assertRaises(ValueError):module.select_asset(changed)

    def test_missing_duplicate_and_other_origin_are_rejected(self):
        for transform in (lambda x:x.update(assets=[]),
                          lambda x:x['assets'].append(x['assets'][0]),
                          lambda x:x['assets'][0].update(browser_download_url='https://example.invalid/input')):
            changed=self.release();transform(changed)
            with self.assertRaises(ValueError):module.select_asset(changed)

    def test_size_is_strictly_integer_and_bounded(self):
        for size in (True, 0, -1, module.LIMIT+1, '10'):
            changed=self.release();changed['assets'][0]['size']=size
            with self.subTest(size=size), self.assertRaises(ValueError):module.select_asset(changed)

    def archive(self, names=('bao',), symlink=False):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as tar:
            for name in names:
                entry=tarfile.TarInfo(name)
                if symlink:
                    entry.type=tarfile.SYMTYPE;entry.linkname='/outside'
                    tar.addfile(entry)
                else:
                    entry.size=7;tar.addfile(entry,io.BytesIO(b'fixture'))
        return output.getvalue()

    def test_binary_is_checked_before_any_executable_is_published(self):
        raw=self.archive()
        with patch.object(module,'ARTIFACT_SHA256',hashlib.sha256(raw).hexdigest()), \
             patch.object(module,'BINARY_SHA256',hashlib.sha256(b'fixture').hexdigest()):
            self.assertEqual(module.extract_verified(raw,len(raw)),b'fixture')
            with self.assertRaises(ValueError):module.extract_verified(raw,len(raw)+1)
            with self.assertRaises(ValueError):module.extract_verified(raw+b'x',len(raw)+1)

    def test_symlink_duplicate_and_missing_binary_are_rejected(self):
        for raw in (self.archive(symlink=True),self.archive(('bao','./bao')),self.archive(('other',))):
            with patch.object(module,'ARTIFACT_SHA256',hashlib.sha256(raw).hexdigest()), \
                 self.assertRaises(ValueError):module.extract_verified(raw,len(raw))

    def test_pinned_archive_cannot_supply_different_binary(self):
        raw=self.archive()
        with patch.object(module,'ARTIFACT_SHA256',hashlib.sha256(raw).hexdigest()), \
             self.assertRaises(ValueError):module.extract_verified(raw,len(raw))

    def test_acquisition_failure_is_blocked_and_cleans_its_new_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/'new-oracle'
            with patch.object(sys,'argv',['prepare','--output',str(out)]), \
                 patch.object(module.platform,'system',return_value='Linux'), \
                 patch.object(module.platform,'machine',return_value='x86_64'), \
                 patch.object(module,'download',side_effect=OSError('unavailable')):
                self.assertEqual(module.main(),77)
            self.assertFalse(out.exists())

    def test_every_redirect_hop_must_remain_https(self):
        request=module.urllib.request.Request(module.RELEASE)
        handler=module.HttpsOnlyRedirect()
        for url in ('http://example.invalid/a','file:///etc/passwd','ftp://example.invalid/a'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request,None,302,'redirect',{},url)

    def test_current_ci_invokes_real_not_model_only_acceptance(self):
        workflow=(ROOT/'.github/workflows/codex-openbao-replacement-ci.yml').read_text()
        for entry in ('postgres_live.py','run_official_comparison.py','live_migration_rehearsal.py',
                      'raft_membership_live.py','--dead-cleanup','prepare_openbao_oracle.py'):
            with self.subTest(entry=entry):self.assertIn(entry,workflow)
        self.assertIn('--postgres-bin /usr/lib/postgresql/17/bin',workflow)
        self.assertNotIn('continue-on-error',workflow)
        self.assertNotIn('postgres_pipeline_simulated.py',workflow)
        self.assertIn('["head","merge"]',workflow)
        self.assertIn('persist-credentials: false',workflow)
        self.assertNotIn('contents: write',workflow)


if __name__=='__main__':unittest.main()
