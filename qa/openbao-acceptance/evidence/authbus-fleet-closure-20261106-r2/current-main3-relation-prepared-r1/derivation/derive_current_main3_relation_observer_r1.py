#!/usr/bin/env python3
"""Derive one bounded same-parent candidate/current-main3 observation."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE / 'observe_fixed_codex_candidate_files_r1.py'
OLD_SHA = '595334506609bd51c746f1d2dd81482a54e8f6602218512ecac8cc73896f8d40'
old = OLD.read_bytes()
assert len(old) == 83443 and hashlib.sha256(old).hexdigest() == OLD_SHA
tree = ast.parse(old)
node = next(item for item in tree.body if isinstance(item, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in item.targets))
payload = ast.literal_eval(node.value)
assignment = ast.get_source_segment(old.decode(), node)
text = old.decode().replace(assignment, 'PAYLOAD = __RELATION_PAYLOAD__', 1)
prior = text


def replace(before, after):
    global text
    assert text.count(before) == 1, before[:140]
    text = text.replace(before, after, 1)


replace('import signal\n', 'import signal\nimport subprocess\n')
replace('"""Read finite source selectors of four prior-bound processes; no auth-file IO."""',
        '"""Same-parent fixed candidate files and one fresh main3 SQL projection, privately."""')
replace('UNTIL = START + 20', 'UNTIL = START + 45')
replace("ROOT = Path('/Users/qianqi/heptabao-authbus-finite-codex-candidate-files-20261107-r1')",
        "ROOT = Path('/Users/qianqi/heptabao-authbus-current-main3-candidate-relation-20261107-r1')\n"
        "QUAL = Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2/qa')")
replace('candidate_inputs = None', 'candidate_inputs = None\nowner = child = None\ncurrent_private = None')
replace("'schema': 'heptabao.finite-codex-candidate-file-observation.r1'",
        "'schema': 'heptabao.current-main3-candidate-relation.parent.r1'")
replace("'keychainReads': 0, 'sqliteCalls': 0, 'networkRequests': 0, 'childProcesses': 0,",
        "'keychainReads': 0, 'currentMainSqlObservationCount': 0, 'providerNetworkRequests': 0, 'childProcesses': 0,")
replace("'parentSeconds': 20, 'supervisorSeconds': 30,",
        "'parentSeconds': 45, 'candidateAndSqlWorkerSeconds': 20, 'supervisorSeconds': 70,")
replace("for path in (Path('/'), Path('/Users'), CALLER_HOME, ROOT, ROOT / 'output'):",
        "for path in (Path('/'), Path('/Users'), CALLER_HOME, ROOT, ROOT / 'code', ROOT / 'output'):\n"
        "        if path == ROOT / 'output':\n"
        "            parent = directories[ROOT]")
assert text.count("if path in (ROOT, ROOT / 'output'):") == 2
text = text.replace("if path in (ROOT, ROOT / 'output'):", "if path in (ROOT, ROOT / 'code', ROOT / 'output'):")

support = '''
def bounded_original_read(path, maximum, *, private=False):
    row = opened(path, os.O_RDONLY)
    try:
        value = os.fstat(row['fd'])
        need(stat.S_ISREG(value.st_mode) and value.st_uid in (0, 501) and value.st_nlink == 1
             and not stat.S_IMODE(value.st_mode) & 0o022 and 0 < value.st_size <= maximum,
             'relation_parent_bounded_original_file')
        if private:
            need(value.st_uid == 501 and value.st_gid == 20 and stat.S_IMODE(value.st_mode) == 0o600,
                 'relation_parent_private_owned_file')
        parts, count = [], 0
        while count <= value.st_size:
            remaining()
            part = os.read(row['fd'], min(65536, value.st_size + 1 - count))
            if not part:
                break
            parts.append(part); count += len(part)
        need(count == value.st_size and full9(value) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
             'relation_parent_whole_file_full_nine')
        return b''.join(parts), full9(value)
    finally:
        close_once(row)


def create_owned(path, raw):
    need(path.parent in (ROOT, ROOT / 'code', ROOT / 'output') and type(raw) is bytes
         and len(raw) <= 2097152, 'relation_parent_exact_new_output_scope')
    parent = directories[path.parent]['row']
    row = opened(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=parent['fd'])
    try:
        view = memoryview(raw)
        while view:
            remaining(); count = os.write(row['fd'], view)
            need(count > 0, 'relation_parent_create_only_write_progress'); view = view[count:]
        os.fsync(row['fd'])
        value = os.fstat(row['fd'])
        need(stat.S_ISREG(value.st_mode) and value.st_uid == 501 and value.st_gid == 20
             and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
             and value.st_size == len(raw) and os.pread(row['fd'], len(raw) + 1, 0) == raw
             and full9(value) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
             'relation_parent_durable_owned_original_bytes')
        os.fsync(parent['fd'])
    finally:
        close_once(row)
    check_directories()


def prepare_reader():
    need(set(PAYLOAD['readerSources']) == {'main3_source_authority.py', 'mac_current_selected_main3_r1.py',
         'mac_codex_candidate_backend_r1.py', 'read_current_main3_candidate_relation_r1.py'},
         'relation_parent_four_reader_sources')
    for name, source in PAYLOAD['readerSources'].items():
        need(hashlib.sha256(source.encode()).hexdigest() == PAYLOAD['readerPins'][name],
             'relation_parent_reader_source_hash')
        compile(source, name, 'exec')
        create_owned(ROOT / 'code' / name, source.encode())
    create_owned(ROOT / 'code/reader-plan.public.json', (json.dumps({
        'schema': 'heptabao.current-main3-relation-reader-plan.r1', 'readerPins': PAYLOAD['readerPins'],
        'originalChildren': 1, 'providerCalls': 0, 'sourceWritesAuthorized': False,
        'historicalCapsuleUsedOnlyForAuthorizedIds': True}, sort_keys=True) + '\\n').encode())
    create_owned(ROOT / 'protected-read', b'synthetic read-denial fixture\\n')
    policy = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))',
        '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)']
    for name in ('/System', '/usr', '/bin', '/sbin', '/Library', '/private/etc', '/opt/homebrew', '/dev/fd'):
        policy.append('(allow file-read* (subpath ' + json.dumps(name) + '))')
    for path in (ROOT / 'code', ROOT / 'output'):
        policy.append('(allow file-read* (subpath ' + json.dumps(str(path)) + '))')
    fixed = {Path('/Users/qianqi/.openclaw/openclaw.json'),
        Path('/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r4/output/selected-owner-credentials.private.json'),
        *[QUAL / name for name in PAYLOAD['originalReaderSourcePins']],
        *[Path('/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite' + suffix)
          for suffix in ('', '-wal', '-shm', '-journal')]}
    literals = set(fixed) | {ROOT, *ROOT.parents, QUAL, *QUAL.parents}
    for path in fixed:
        literals.update(path.parents)
    for path in sorted(literals, key=str):
        policy.append('(allow file-read* (literal ' + json.dumps(str(path)) + '))')
    for name in ('/dev/null', '/dev/random', '/dev/urandom'):
        policy.append('(allow file-read* (literal ' + json.dumps(name) + '))')
    policy.extend(['(allow file-write* (subpath ' + json.dumps(str(ROOT / 'output')) + '))',
                   '(allow file-write* (literal "/dev/null"))'])
    create_owned(ROOT / 'reader.sb', ('\\n'.join(policy) + '\\n').encode())
    authority = PAYLOAD['custodyQualificationAuthority']
    need(authority['job_id'] == '1a1b141ef40-fc05-7750' and authority['state'] == 'succeeded'
         and authority['exit_code'] == 0 and all(authority[key] is True for key in
             ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(authority[key] is False for key in ('timed_out', 'cancelled', 'automatic_retry')),
         'relation_parent_original_custody_authority')
    proof, _ = bounded_original_read(QUAL.parent / 'result.public.json', 65536)
    need(len(proof) == 58701 and hashlib.sha256(proof).hexdigest()
         == '67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e',
         'relation_parent_original_actual_custody_proof')
    value = json.loads(proof)
    need(value['ok'] and value['allCasesMatched'] and value['allOwnedClosed']
         and value['custody']['passed_process_custody'] and value['custody']['original_count'] == 18,
         'relation_parent_original_eighteen_custody_cases')
    return None


def reader_source_fence():
    remaining()
    for name, expected in PAYLOAD['readerPins'].items():
        raw, _ = bounded_original_read(ROOT / 'code' / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_parent_reader_whole_source_exact')
    for name, expected in {**PAYLOAD['originalReaderSourcePins'], **PAYLOAD['custodyPins']}.items():
        raw, _ = bounded_original_read(QUAL / name, 65536)
        need(hashlib.sha256(raw).hexdigest() == expected, 'relation_parent_original_readonly_sources_exact')
    raw, _ = bounded_original_read(Path('/usr/bin/sandbox-exec'), 2097152)
    need(hashlib.sha256(raw).hexdigest() == 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
         'relation_parent_actual_sandbox_runtime_exact')


def close_original_streams():
    if child is not None:
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def execute_reader(candidate_until):
    global owner, child
    reader_source_fence()
    for name in PAYLOAD['custodyPins']:
        need(Path(name).stem not in sys.modules, 'relation_original_custody_import_once')
    sys.path.insert(0, str(QUAL))
    import kv2_dr_process_custody as custody
    with custody.activated() as owner:
        left = min(20, candidate_until - time.monotonic(), UNTIL - time.monotonic())
        need(left > 0, 'relation_original_reader_fits_remaining_candidate_deadline')
        report['originalReadonlyChildLaunchAttempts'] = 1
        report['childProcesses'] = None
        report['currentMainSqlObservationCount'] = None
        child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(ROOT / 'reader.sb'), str(PYTHON),
            '-I', '-S', '-B', str(ROOT / 'code/read_current_main3_candidate_relation_r1.py'),
            repr(min(candidate_until, UNTIL))], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(ROOT),
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/qianqi', 'LANG': 'C', 'LC_ALL': 'C'})
        report['childProcesses'] = 1
        out, err = child.communicate(timeout=left)
        close_original_streams()
        need(len(out) <= 65536 and len(err) <= 65536, 'relation_original_child_bounded_streams')
        create_owned(ROOT / 'output/reader.stdout.public.json', out)
        create_owned(ROOT / 'output/reader.stderr.private', err)
        report['originalReader'] = {'exitCode': child.returncode, 'stdoutBytes': len(out),
            'stderrBytes': len(err), 'streamsClosed': True}
        if out:
            report['currentReader'] = json.loads(out)
            report['credentialEqualityCompared'] = report['currentReader'].get(
                'privateCandidateEqualityComparisonPerformed') is True
            closure = report['currentReader'].get('currentReadClosure')
            if type(closure) is dict:
                report['currentMainSqlObservationCount'] = closure.get('queryCount')
        need(child.returncode == 0 and not err and report['currentReader']['ok'],
             'relation_original_reader_known_success')
        value = report['currentReader']
        need(value['currentSelectedOwnerCount'] == 3 and value['providerCalls'] == 0
             and value['sdkImports'] == 0 and value['productionWrites'] == 0
             and value['serviceActions'] == 0 and value['keychainReads'] == 0
             and value['allOriginalDescriptorsClosedOnce'] and value['closedScopeNamesExact']
             and value['scopeClosure']['allOriginalDescriptorsClosedOnce']
             and len(value['kernelDenials']) == 4 and all(row['denied'] for row in value['kernelDenials'])
             and value['probeSocketClosed'] and value['currentReadClosure']['allOwnedDescriptorsClosed']
             and value['currentReadClosure']['allReturnedConnectionsClosed']
             and value['currentReadClosure']['allExplicitCursorsClosed'],
             'relation_original_current_read_and_resources_closed')
    report['custody'] = owner.receipt()
    need(report['custody']['passed_process_custody'] and report['custody']['original_count'] == 1,
         'relation_original_reader_child_custody_complete')
    reader_source_fence()
    raw, identity = bounded_original_read(ROOT / 'output/current-main3-candidate-relation.private.json',
                                         2097152, private=True)
    value = json.loads(raw)
    need(value['schema'] == 'heptabao.current-main3-candidate-relation.private.r1'
         and value['originalParentPid'] == os.getpid(), 'relation_original_same_parent_private_result')
    for name in ('main3_source_authority.py', 'mac_current_selected_main3_r1.py'):
        source = PAYLOAD['readerSources'][name]
        key = Path(name).stem
        need(key not in sys.modules, 'relation_parent_current_namespace_module_once')
        module = types.ModuleType(key); module.__file__ = str(ROOT / 'code' / name)
        sys.modules[key] = module
        exec(compile(source, module.__file__, 'exec'), module.__dict__)
    from mac_current_selected_main3_r1 import verify_current_namespace
    verify_current_namespace(value['currentSelectedOwners'], until=candidate_until)
    return value, raw, identity, verify_current_namespace


'''
replace('class ArgsReader:\n', support + 'class ArgsReader:\n')
replace('    setup_private_directories()\n', '    setup_private_directories()\n    prepare_reader()\n')
replace('    candidate_inputs = FixedCandidateInputs(until=UNTIL, source_fence=candidate_source_fence,',
        '    candidate_until = min(UNTIL, time.monotonic() + 20)\n'
        '    candidate_inputs = FixedCandidateInputs(until=candidate_until, source_fence=candidate_source_fence,')
replace('    second = []\n',
        '    current_private, current_raw, current_identity, verify_current_namespace = execute_reader(candidate_until)\n'
        '    second = []\n')
replace('    candidate_inputs.verify()\n',
        '    candidate_inputs.verify()\n'
        '    verify_current_namespace(current_private["currentSelectedOwners"], until=candidate_until)\n'
        '    need(bounded_original_read(ROOT / "output/current-main3-candidate-relation.private.json",\n'
        '                               2097152, private=True) == (current_raw, current_identity),\n'
        '         "relation_original_private_result_still_exact")\n')
replace("    report['currentMain3ComparisonPerformed'] = False", "    report['currentMain3ComparisonPerformed'] = True")
replace("    report['candidateFileObservationIsCurrentBackendProof'] = False\n",
        "    report['candidateFileObservationIsCurrentBackendProof'] = False\n"
        "    report['credentialEqualityCompared'] = True\n"
        "    report['currentMainSqlObservationCount'] = report['currentReader']['currentReadClosure']['queryCount']\n"
        "    report['historicalValuesUsedAsCurrent'] = False\n"
        "    report['originalCandidateActualEvidenceMap'] = '0d02daa98cea1a18815f3d3ab0141312910d300d'\n")
replace('finally:\n    errors = []\n',
        'finally:\n    errors = []\n    close_original_streams()\n'
        '    if owner is not None:\n'
        '        report["custody"] = owner.receipt()\n'
        '        if not report["custody"].get("passed_process_custody"):\n'
        '            report["ok"] = False\n')
replace('    for row in reversed(descriptors):\n',
        '    if report["ok"] and current_private is not None:\n'
        '        try:\n'
        '            verify_current_namespace(current_private["currentSelectedOwners"], until=candidate_until)\n'
        '            report["mainGenerationExactAfterCandidateClose"] = True\n'
        '        except BaseException:\n'
        '            report["ok"] = False\n'
        '            report["mainGenerationExactAfterCandidateClose"] = False\n'
        '    for row in reversed(descriptors):\n')

reader_names = ('main3_source_authority.py', 'mac_current_selected_main3_r1.py',
                'mac_codex_candidate_backend_r1.py', 'read_current_main3_candidate_relation_r1.py')
payload['readerSources'] = {name: ((HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4' / name)
    if name == 'main3_source_authority.py' else HERE / name).read_text() for name in reader_names}
payload['readerPins'] = {name: hashlib.sha256(value.encode()).hexdigest()
                         for name, value in payload['readerSources'].items()}
payload['originalReaderSourcePins'] = {
    'mac_guarded_current_capture_r3.py': '606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
    'mac_registry_readonly_wal_r1.py': '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
    'authbus_current_auth_wal.py': 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c'}
payload['custodyPins'] = {'kv2_dr_process_custody.py': '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
                        'owned_process.py': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'}
original = (HERE / 'launch_poststop_registry_qualification_r1.py').read_bytes()
assert hashlib.sha256(original).hexdigest() == '345750b3fb8909245b692472b646f71d6fdfa5615df5499db9b01c9d0d216707'
prior_payload = next(ast.literal_eval(item.value) for item in ast.parse(original).body
    if isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in item.targets))
payload['custodyQualificationAuthority'] = copy.deepcopy(prior_payload['custodyQualificationAuthority'])
prepared = text.replace('__RELATION_PAYLOAD__', repr(payload))
target = HERE / 'observe_current_main3_candidate_relation_r1.py'
compile(prepared, target.name, 'exec')
target.write_text(prepared)
(HERE / 'observe_current_main3_candidate_relation_r1.template.py').write_text(text)
(HERE / 'candidate-to-current-main3-relation-r1.diff').write_text(''.join(difflib.unified_diff(
    prior.splitlines(True), text.splitlines(True), fromfile=OLD.name, tofile=target.name)))
result = {'schema': 'heptabao.current-main3-candidate-relation-prepared.r1', 'sourceOnlyPrepared': True,
    'source': target.name, 'bytes': len(prepared.encode()), 'sha256': hashlib.sha256(prepared.encode()).hexdigest(),
    'originalCandidateSourceBytes': len(old), 'originalCandidateSourceSha256': OLD_SHA,
    'originalCandidateActualEvidenceMap': '0d02daa98cea1a18815f3d3ab0141312910d300d',
    'readerPins': payload['readerPins'], 'unchangedParentSourcePins': payload['sourcePins'],
    'qualifiedAuthReaderPins': payload['originalReaderSourcePins'], 'custodyPins': payload['custodyPins'],
    'parentSeconds': 45, 'candidateAndSqlWorkerSeconds': 20, 'originalAuthQuerySeconds': 3,
    'supervisorSeconds': 70, 'originalReadonlyChildCount': 1, 'providerCalls': 0,
    'productionWrites': 0, 'serviceActions': 0, 'keychainReads': 0,
    'historicalCapsuleUsedOnlyForAuthorizedIds': True, 'historicalCredentialValuesUsedAsCurrent': False,
    'effectiveRuntimeBackendQualified': False, 'runningCachedCredentialRelation': 'unknown',
    'productionRefreshAdmission': False}
(HERE / 'current-main3-candidate-relation-prepared-r1.public.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, sort_keys=True))
