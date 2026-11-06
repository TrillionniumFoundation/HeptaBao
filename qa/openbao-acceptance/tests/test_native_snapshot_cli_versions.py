"""Exercise release admission with real private files and synthetic release pins.

The snapshot workload is stubbed; these are controller guards, not live service
qualification. Archive, executable and selected-release verification stay real.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from bao_http import BaoError
import native_snapshot_cli_live as fixture
import official_openbao_launcher as launcher


class NativeSnapshotCliVersionSelection(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix='cli-version-guard-', dir=Path(fixture.__file__).parent)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.candidate = self.root / 'candidate'
        self.candidate.write_bytes(b'synthetic candidate, never executed')
        self.output = self.root / 'receipt.json'
        self.releases = {}
        self.pins = {}
        for version in launcher.SUPPORTED_VERSIONS:
            data = ('synthetic official CLI ' + version).encode()
            binary = self.root / ('bao-' + version)
            binary.write_bytes(data)
            archive = self.root / ('bao-' + version + '.tar.gz')
            with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as bundle:
                entry = tarfile.TarInfo('bao')
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
            pin = {
                'binary_sha256': hashlib.sha256(data).hexdigest(),
                'artifact_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
            self.releases[version] = (binary, archive, pin)
            self.pins[version] = {('linux', 'amd64'): pin}
        # Preserve the real platform distinction that caused the Mac blockage.
        self.pins['2.7.1'][('darwin', 'arm64')] = self.releases['2.7.1'][2]

    def arguments(self, version=None):
        args = ['--binary', str(self.candidate), '--build-source-commit', 'a' * 40,
                '--work-parent', str(self.root), '--output', str(self.output)]
        return args if version is None else args + ['--official-version', version]

    @staticmethod
    def completed_workload(binary, bao, work, checks, observations, postgres_bin):
        checks.extend({'case': name, 'passed': True}
                      for name in sorted(fixture.REQUIRED - {'complete'}))
        checks.append({'case': 'complete', 'passed': True})

    @contextlib.contextmanager
    def admitted_files(self, version, *, system='Linux', machine='x86_64', workload=None):
        binary, archive, _ = self.releases[version]
        identity = {'source_commit': 'a' * 40, 'source_dirty': False,
                    'binary_sha256': hashlib.sha256(self.candidate.read_bytes()).hexdigest()}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(launcher.PINNED_RELEASES, self.pins, clear=True))
            stack.enter_context(mock.patch.object(launcher.platform, 'system', return_value=system))
            stack.enter_context(mock.patch.object(launcher.platform, 'machine', return_value=machine))
            stack.enter_context(mock.patch.dict(os.environ, {
                'HB_ORACLE_BINARY': str(binary), 'HB_ORACLE_ARCHIVE': str(archive)}))
            stack.enter_context(mock.patch.object(fixture, 'source_identity', return_value=identity))
            runner = stack.enter_context(mock.patch.object(
                fixture, 'run', side_effect=workload or self.completed_workload))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield runner

    def assert_selected_receipt(self, version):
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual(receipt['official_cli_version'], version)
        self.assertEqual(receipt['official_cli_pinned_artifact'], self.releases[version][2])
        self.assertEqual(receipt['official_cli_sha256'], self.releases[version][2]['binary_sha256'])
        self.assertEqual(receipt['official_cli_provenance_url'],
                         'https://github.com/openbao/openbao/releases/tag/v' + version)
        self.assertTrue(receipt['official_cli_unchanged'])
        self.assertTrue(receipt['synthetic_only'])
        self.assertFalse(receipt['production_authority'])
        self.assertFalse(receipt['independent_qualification'])
        self.assertFalse(receipt['full_openbao_compatibility'])
        self.assertFalse(receipt['ha_restore_covered'])

    def test_legacy_default_and_every_explicit_supported_release_bind_real_files(self):
        for selected in (None, *launcher.SUPPORTED_VERSIONS):
            version = '2.6.2' if selected is None else selected
            with self.subTest(selected=selected):
                self.output = self.root / ('receipt-' + str(selected) + '.json')
                with self.admitted_files(version) as runner:
                    self.assertEqual(fixture.main(self.arguments(selected)), 0)
                runner.assert_called_once()
                self.assertEqual(runner.call_args.args[1], self.releases[version][0])
                self.assert_selected_receipt(version)

    def test_darwin_arm64_271_can_admit_and_reports_its_selected_pins(self):
        with self.admitted_files('2.7.1', system='Darwin', machine='arm64') as runner:
            self.assertEqual(fixture.main(self.arguments('2.7.1')), 0)
        runner.assert_called_once()
        self.assert_selected_receipt('2.7.1')

    def test_other_pinned_release_is_rejected_before_work_directory_or_workload(self):
        with self.admitted_files('2.6.2') as runner, \
                mock.patch.object(fixture.tempfile, 'mkdtemp') as allocate:
            with self.assertRaisesRegex(BaoError, 'official_oracle_pinned_digest_mismatch'):
                fixture.main(self.arguments('2.7.1'))
        allocate.assert_not_called()
        runner.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_unverified_platform_cannot_fall_back_to_linux_report_pins(self):
        with self.admitted_files('2.6.2', system='Darwin', machine='arm64') as runner, \
                mock.patch.object(fixture.tempfile, 'mkdtemp') as allocate:
            with self.assertRaisesRegex(BaoError, 'official_oracle_unsupported_platform'):
                fixture.main(self.arguments())
        allocate.assert_not_called()
        runner.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_cli_changed_between_pin_verification_and_capture_cannot_start(self):
        def change_after_verification(*, version):
            binary = launcher.verify_inputs(version=version)
            binary.write_bytes(b'changed immediately after pin verification')
            return binary

        with self.admitted_files('2.7.1') as runner, \
                mock.patch.object(fixture, 'verify_inputs', side_effect=change_after_verification), \
                mock.patch.object(fixture.tempfile, 'mkdtemp') as allocate:
            with self.assertRaisesRegex(ValueError, 'official_cli_changed_after_verification'):
                fixture.main(self.arguments('2.7.1'))
        allocate.assert_not_called()
        runner.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_changed_cli_cannot_publish_a_passing_selected_release_receipt(self):
        def changed(*args):
            self.completed_workload(*args)
            args[1].write_bytes(b'changed after admission')

        with self.admitted_files('2.7.1', workload=changed):
            self.assertEqual(fixture.main(self.arguments('2.7.1')), 1)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['failure'], 'source_binary_cli_or_runner_changed')
        self.assertEqual(receipt['official_cli_version'], '2.7.1')
        self.assertEqual(receipt['official_cli_pinned_artifact'], self.releases['2.7.1'][2])
        self.assertFalse(receipt['official_cli_unchanged'])
        self.assertFalse(receipt['official_cli_transport_covered'])
        self.assertFalse(receipt['production_authority'])

    def test_unsupported_release_is_rejected_at_the_command_entry(self):
        with mock.patch.object(fixture, 'verify_inputs') as verify, \
                mock.patch.object(fixture, 'run') as runner, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                fixture.main(self.arguments('9.9.9'))
        self.assertEqual(error.exception.code, 2)
        verify.assert_not_called()
        runner.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
