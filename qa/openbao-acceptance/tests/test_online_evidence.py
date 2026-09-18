"""Evidence must not promote incomplete, replaced, dirty or changed inputs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from online_evidence import admit_output, source_identity, complete_checks, publish


class OnlineEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        os.chmod(self.root, 0o700)
        self.output = self.root / 'report.json'
    def tearDown(self):
        self.directory.cleanup()
    def test_checks_require_nonempty_exact_distinct_true_boolean_rows(self):
        valid = [{'case':'one', 'passed':True}]
        self.assertTrue(complete_checks(valid,1))
        for rows, count in [([],0),(valid,2),(valid*2,2),([{'case':'one','passed':1}],1),
                ([{'case':'one','passed':False}],1),([{'case':'one','passed':'true'}],1),
                ([{'case':'private/value','passed':True}],1),([{'case':'one','passed':True,'token':'no'}],1)]:
            self.assertFalse(complete_checks(rows,count))
    def test_existing_output_and_dangling_symlink_reject(self):
        self.output.write_text('earlier partial result')
        with self.assertRaises(ValueError): admit_output(self.output)
        self.output.unlink();self.output.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError): admit_output(self.output)
    def test_private_parent_rejects_setgid_and_group_access(self):
        for mode in (0o750,0o2700,0o755):
            os.chmod(self.root,mode)
            with self.assertRaises(ValueError): admit_output(self.output)
        os.chmod(self.root,0o700)
    def test_linked_parent_or_ancestor_rejects(self):
        actual=self.root/'actual';actual.mkdir(mode=0o700)
        link=self.root/'link';link.symlink_to(actual,target_is_directory=True)
        with self.assertRaises(ValueError): admit_output(link/'new.json')
        child=actual/'nested';child.mkdir(mode=0o700)
        with self.assertRaises(ValueError): admit_output(link/'nested/new.json')
    def test_output_reserved_by_another_caller_never_overwrites(self):
        parent=admit_output(self.output)
        self.output.write_text('original')
        with self.assertRaises(ValueError):
            publish(self.output,parent,{'checks':[{'case':'one','passed':True}],'failure':None},{},{},1)
        self.assertEqual(self.output.read_text(),'original')
    def test_changed_source_cannot_be_reported_successful(self):
        report={'checks':[{'case':'one','passed':True}],'failure':None}
        publish(self.output,admit_output(self.output),report,{'binary_sha256':'a'},{'binary_sha256':'b'},1)
        saved=json.loads(self.output.read_text())
        self.assertEqual(saved['status'],'failed')
        self.assertFalse(saved['source_and_binary_unchanged'])
        self.assertFalse(saved['independent_qualification'])
        self.assertEqual(self.output.stat().st_mode & 0o777,0o600)
    def test_failure_not_erased_by_complete_checks(self):
        report={'checks':[{'case':'one','passed':True}],'failure':'fixture_runtime_error'}
        publish(self.output,admit_output(self.output),report,{},{},1)
        self.assertEqual(json.loads(self.output.read_text())['status'],'failed')
    def test_source_identity_covers_uncommitted_bytes_and_binary(self):
        repo=self.root/'repo';repo.mkdir();binary=self.root/'binary';binary.write_bytes(b'synthetic-not-executed')
        def git(*args):subprocess.run(['git',*args],cwd=repo,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        git('init');git('config','user.name','Synthetic test');git('config','user.email','test@example.invalid')
        file=repo/'source';file.write_text('a');git('add','.');git('commit','-m','test')
        initial=source_identity(repo,binary);self.assertFalse(initial['source_dirty'])
        file.write_text('b');dirty=source_identity(repo,binary)
        file.write_text('c');dirty2=source_identity(repo,binary)
        self.assertEqual(dirty['source_commit'],dirty2['source_commit'])
        self.assertNotEqual(dirty['source_content_sha256'],dirty2['source_content_sha256'])
        new=repo/'new';new.write_text('new')
        self.assertNotEqual(source_identity(repo,binary)['source_content_sha256'],dirty2['source_content_sha256'])
        binary.write_bytes(b'changed')
        self.assertNotEqual(source_identity(repo,binary)['binary_sha256'],initial['binary_sha256'])
    def test_failed_prerequisite_does_not_assert_official_issuer(self):
        # Executable reports infer observation only from a successful real login.
        for name,case in [('oidc_code_live','issuer_real_enduser_login'),('online_auth_ha','issuer_login')]:
            text=(Path(__file__).resolve().parents[1]/(name+'.py')).read_text()
            self.assertIn(f'c["case"]=="{case}" and c["passed"] is True',text)
            self.assertNotIn('"actual_official_issuer":True',text)

if __name__=='__main__':unittest.main()
