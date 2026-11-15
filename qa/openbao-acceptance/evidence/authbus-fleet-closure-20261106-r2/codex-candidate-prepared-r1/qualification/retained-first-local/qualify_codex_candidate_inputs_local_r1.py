#!/usr/bin/env python3
"""Real local candidate-file custody with synthetic bytes and rebased paths."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import time
from unittest.mock import patch

import mac_codex_candidate_backend_r1 as classifier
import mac_codex_fixed_candidate_inputs_r1 as core

HERE = Path(__file__).resolve().parent
PINS = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
    ('mac_codex_candidate_backend_r1.py', 'mac_codex_fixed_candidate_inputs_r1.py')}
cases = []


def need(value):
    if not value:
        raise AssertionError('synthetic_candidate_custody_case_failed')


def refuses(fn):
    try:
        fn()
    except (core.InputsRefused, classifier.CandidateRefused, OSError):
        return
    raise AssertionError('candidate_custody_expected_refusal')


@contextmanager
def fixture(*, absent=False, no_config=False):
    home = Path(tempfile.mkdtemp(prefix='heptabao-codex-candidate-local-', dir=Path.home()))
    source, output = home / '.codex', home / 'output'
    output.mkdir(mode=0o700)
    if not absent:
        source.mkdir(mode=0o700)
        if not no_config:
            (source / 'config.toml').write_bytes(b'cli_auth_credentials_store="file"\n')
            (source / 'config.toml').chmod(0o600)
        (source / 'auth.json').write_bytes(b'{"tokens":{"refresh_token":"synthetic-private-candidate-value"}}')
        (source / 'auth.json').chmod(0o600)
    packets = []
    def write(name, value):
        raw = json.dumps(value).encode()
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            at = 0
            while at < len(raw):
                count = os.write(fd, raw[at:]); need(count > 0); at += count
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        packets.append(value)
    with patch.multiple(core, HOME=home, SOURCE=source, UID=os.getuid(), GID=os.getgid()), \
         patch.multiple(classifier, HOME=PurePosixPath(home), CANDIDATE=PurePosixPath(source)):
        selected = {'private': {'selectors': {'HOME': str(home)},
            'candidateHome': {'kind': 'default_candidate_from_observed_home', 'path': str(source)},
            'profileV2Selector': None, 'profileSelector': None, 'storageModeOverride': None},
            'public': {'configurationKeyBoundToOfficialV0133Source': True,
                'environmentSectionState': 'entries_returned', 'profileV2SelectionPresent': False,
                'otherConfigurationOverrides': 0}}
        values = [copy.deepcopy(selected) for _ in range(4)]
        inputs = core.FixedCandidateInputs(until=time.monotonic() + 20,
            source_fence=lambda: None, private_write=write)
        try:
            yield inputs, values, source, packets
        finally:
            inputs.close()
            shutil.rmtree(home)


def run(name, fn):
    fn(); cases.append({'name': name, 'passed': True})


def complete():
    with fixture() as (inputs, selected, source, packets):
        report = inputs.capture(selected)
        need(report['ok'] and report['sourceFileContentsRead'] == 2 and len(packets) == 1)
        need('synthetic-private-candidate-value' not in json.dumps(report))
        report = inputs.close()
        need(report['allSourceDescriptorsClosedOnce'] and report['closedSourceNamesStillExact'])


def alias():
    with fixture() as (inputs, selected, source, _):
        original = source / 'auth.json'; other = source / 'other'
        original.rename(other); original.symlink_to(other.name)
        refuses(lambda: inputs.capture(selected))
        need(inputs.close()['allSourceDescriptorsClosedOnce'])


def replaced():
    with fixture() as (inputs, selected, source, _):
        inputs.capture(selected)
        original = source / 'auth.json'; saved = original.read_bytes()
        original.unlink(); original.write_bytes(saved); original.chmod(0o600)
        refuses(inputs.verify)
        report = inputs.close()
        need(not report['ok'] and report['allSourceDescriptorsClosedOnce'])


def absent():
    with fixture(absent=True) as (inputs, selected, source, _):
        report = inputs.capture(selected)
        need(report['sourceFileContentsRead'] == 0 and not report['candidateAuthShape']['candidateAuthPresent'])
        need(not report['effectiveRuntimeBackendQualified'] and not report['productionRefreshAdmission'])
        need(inputs.close()['closedSourceNamesStillExact'])


def absence_changed():
    with fixture(no_config=True) as (inputs, selected, source, _):
        inputs.capture(selected)
        (source / 'config.toml').write_bytes(b'')
        refuses(inputs.verify)
        need(inputs.close()['allSourceDescriptorsClosedOnce'])


def linked():
    with fixture() as (inputs, selected, source, _):
        os.link(source / 'auth.json', source / 'other')
        refuses(lambda: inputs.capture(selected))
        need(inputs.close()['allSourceDescriptorsClosedOnce'])


run('I01_two_complete_private_files_and_closed_full9', complete)
run('I02_symlink_candidate_refused_without_target_read', alias)
run('I03_same_bytes_new_inode_refused', replaced)
run('I04_absent_candidate_directory_not_runtime_exclusion', absent)
run('I05_absent_source_name_appearing_refused', absence_changed)
run('I06_hardlinked_auth_candidate_refused', linked)
need(PINS == {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in PINS})
report = {'schema': 'heptabao.codex-candidate-inputs-local-filesystem-qualification.r1',
    'ok': True, 'passed': len(cases), 'expected': 6, 'cases': cases,
    'sourcePinsBeforeAndAfterExact': PINS, 'realLocalFilesystemUsed': True,
    'productionPathsUidAndGidReboundOnlyInSyntheticFixture': True,
    'actualMacProcessesObserved': 0, 'actualCredentialFilesRead': 0, 'providerCalls': 0,
    'productionRefreshAdmission': False}
(HERE / 'codex-candidate-inputs-local-r1.result.public.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
