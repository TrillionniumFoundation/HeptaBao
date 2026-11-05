# Composition tail; assembled with the reviewed original-child OwnedRunner.

def directory(path, device=None):
    need(path.resolve(strict=True) == path, 'directory_symlink')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000
         and (device is None or info.st_dev == device), 'owned_directory_identity')
    return info


def owned_ancestors(path, device):
    need(path == ROOT or ROOT in path.parents, 'outside_owned_source_root')
    for current in reversed((path, *path.parents)):
        if current == ROOT or ROOT in current.parents:
            directory(current, device)


def group_members(pgid):
    members = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            raw = (path / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[2]) == pgid:
                members.append(int(path.name))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, IndexError) as error:
            raise RuntimeError('owned_group_observation_incomplete') from error
    return sorted(members)


def hash_tool(path, until):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'tool_path_changed')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 1000)
             and before.st_mode & 0o022 == 0 and before.st_size <= 256 * 1024 * 1024,
             'fixed_tool_file_custody')
        h = hashlib.sha256()
        count = 0
        while True:
            remaining(until)
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            h.update(chunk)
        need(count == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'fixed_tool_file_changed')
        return h.hexdigest()
    finally:
        os.close(fd)


def environment():
    # The original normal profile is retained. Inherited compiler switches,
    # provider credentials, user hooks and proxy variables are not imported.
    env = {'PATH': str(TOOLCHAIN) + ':/usr/bin:/bin',
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'CARGO_HOME': str(CARGO_HOME), 'CARGO_TARGET_DIR': str(TARGET),
           'CARGO_BUILD_JOBS': '1',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_CONFIG_COUNT': '3',
           'GIT_CONFIG_KEY_0': 'core.fsmonitor', 'GIT_CONFIG_VALUE_0': 'false',
           'GIT_CONFIG_KEY_1': 'core.untrackedCache', 'GIT_CONFIG_VALUE_1': 'false',
           'GIT_CONFIG_KEY_2': 'submodule.recurse', 'GIT_CONFIG_VALUE_2': 'false',
           'GIT_AUTHOR_NAME': 'HeptaBao isolated verification',
           'GIT_AUTHOR_EMAIL': 'heptabao-verification@localhost',
           'GIT_COMMITTER_NAME': 'HeptaBao isolated verification',
           'GIT_COMMITTER_EMAIL': 'heptabao-verification@localhost'}
    env.update(NORMAL_PROFILE)
    return env


def verify_admission_input(packet, until):
    # The reviewed draft deliberately contains nulls and cannot pass here.
    need(packet.get('execution_enabled') is True
         and packet.get('unresolved_preflight_job') is None,
         'no_execution_while_preflight_outcome_unknown')
    need(packet.get('mode') in ('compile_only', 'components_and_build'), 'closed_execution_mode')
    # A later successful observation cannot close the original unknown launch.
    # Both the old identity's closure and current successful admission are
    # separately required, even if they eventually refer to the same job.
    closure = packet.get('original_unknown_preflight_resolution')
    need(packet.get('original_unknown_preflight_job') == ORIGINAL_UNKNOWN_PREFLIGHT_JOB
         and isinstance(closure, dict)
         and closure.get('job_id') == ORIGINAL_UNKNOWN_PREFLIGHT_JOB
         and closure.get('outcome_known') is True
         and closure.get('terminal_confirmed') is True
         and closure.get('complete') is True and closure.get('durable') is True
         and closure.get('owned_children_stopped') is True
         and closure.get('remaining') == []
         and re.fullmatch('[0-9a-f]{64}', closure.get('original_sdk_sha256', '')),
         'original_3335_authoritative_closure_required')
    if closure.get('closure_kind') == 'terminal':
        need(type(closure.get('exit_code')) is int
             and type(closure.get('timed_out')) is bool,
             'original_3335_terminal_exit_required')
    else:
        need(closure.get('closure_kind') == 'authoritative_not_launched'
             and closure.get('launch_confirmed_not_started') is True
             and closure.get('exit_code') is None
             and closure.get('automatic_retry') is False
             and closure.get('retried_launch') is False,
             'original_3335_not_launched_authority_required')
    closure_sha = sha(json.dumps(closure, sort_keys=True,
                                separators=(',', ':')).encode())
    resolution = packet.get('authoritative_preflight_resolution')
    pins = packet.get('current_toolchain_pins')
    review = packet.get('current_resource_and_ownership_review')
    need(isinstance(resolution, dict) and resolution.get('terminal_confirmed') is True
         and resolution.get('complete') is True and resolution.get('durable') is True
         and type(resolution.get('exit_code')) is int
         and resolution.get('exit_code') == 0 and resolution.get('timed_out') is False
         and isinstance(resolution.get('job_id'), str)
         and re.fullmatch('[0-9a-f]{64}', resolution.get('original_sdk_sha256', ''))
         and re.fullmatch('[0-9a-f]{64}', resolution.get('stdout_sha256', '')),
         'authoritative_readonly_preflight_required')
    if resolution['job_id'] == ORIGINAL_UNKNOWN_PREFLIGHT_JOB:
        need(closure['closure_kind'] == 'terminal'
             and closure['exit_code'] == 0 and closure['timed_out'] is False
             and closure['original_sdk_sha256'] == resolution['original_sdk_sha256'],
             'same_preflight_requires_same_successful_terminal_receipt')
    need(isinstance(pins, list) and len(pins) == 7
         and isinstance(review, dict) and review.get('configured_host') == 'rog'
         and review.get('source_commit') == BASE_COMMIT and review.get('source_tree') == BASE_TREE
         and review.get('source_clean') is True
         and review.get('preflight_job_id') == resolution['job_id']
         and review.get('original_unknown_preflight_job') == ORIGINAL_UNKNOWN_PREFLIGHT_JOB
         and review.get('original_unknown_preflight_resolution_sha256') == closure_sha
         and re.fullmatch('[0-9a-f]{64}', review.get('review_sha256', '')),
         'current_rog_resource_and_ownership_review_required')
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64'
         and os.getuid() == os.geteuid() == 1000,
         'actual_rog_linux_operator')
    need(socket.gethostname() == review.get('hostname')
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == review.get('boot_id'),
         'current_host_or_boot_changed')
    need(all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'))
         and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
         'original_unreaped_child_wait_required')
    tool_paths = {str(Path('/proc/self/exe').resolve(strict=True)),
                  str(Path('/usr/bin/git').resolve(strict=True)),
                  str(TOOLCHAIN / 'cargo'), str(TOOLCHAIN / 'rustc'),
                  str(TOOLCHAIN / 'clippy-driver'), str(TOOLCHAIN / 'rustfmt'),
                  str(Path('/usr/bin/openssl').resolve(strict=True))}
    need(len(tool_paths) == 7 and {x.get('path') for x in pins} == tool_paths,
         'exact_current_tool_paths_required')
    for item in pins:
        remaining(until)
        need(re.fullmatch('[0-9a-f]{64}', item.get('sha256', '')) is not None
             and hash_tool(Path(item['path']), until) == item['sha256'],
             'actual_toolchain_hash_changed')
    need(shutil.which('openssl', path=environment()['PATH']) == '/usr/bin/openssl',
         'openssl_path_shadowed')
    if packet['mode'] == 'components_and_build':
        need(review.get('rog_timed_fixture_window_available') is True
             and review.get('active_rog_fixture_controllers_reconciled') is True
             and isinstance(review.get('fixture_evidence_refs'), list)
             and bool(review['fixture_evidence_refs']),
             'separate_rog_timed_fixture_review_required')
    return review


def source_pins(entries, device, until):
    result = []
    seen = set()
    for entry in entries:
        remaining(until)
        relative = Path(entry['path'])
        need(not relative.is_absolute() and '..' not in relative.parts
             and str(relative) not in seen, 'closed_source_pin_path')
        seen.add(str(relative))
        path = SOURCE / relative
        owned_ancestors(path.parent, device)
        raw = read_owned(path, 4 * 1024 * 1024)
        need(len(raw) == entry['bytes'] and sha(raw) == entry['sha256']
             and blob(raw) == entry['git_blob'], 'source_pin_changed')
        result.append({'path': str(relative), 'bytes': len(raw),
                       'sha256': sha(raw), 'git_blob': blob(raw)})
    return result


def guard_boundary_observation(guard, until, timed):
    remaining(until)
    compile_report = guard['compile_admission']()
    timed_report = guard['exclusive_timed_test_admission']() if timed else None
    rows, daemons = guard['process_snapshot']()
    need(len(rows) <= 2048, 'operator_process_observation_bound')
    overlaps = []
    products = []
    for pid, row in sorted(rows.items()):
        remaining(until)
        if pid == os.getpid():
            continue
        if any(guard['under'](row['cwd'], p) or guard['under'](row['executable_path'], p)
               for p in (SOURCE, TARGET, CACHE)):
            overlaps.append({'pid': pid, 'kind': 'cwd_or_executable',
                             'cwd': row['cwd'], 'executable': row['executable_path']})
        unused, descriptor_overlaps = guard['inspect_fds'](row)
        if descriptor_overlaps:
            overlaps.append({'pid': pid, 'kind': 'descriptor', 'paths': descriptor_overlaps})
        if row['executable_basename'] in ('heptabao-server', 'heptabao-seed', 'bao', 'openbao',
                                         'retained-heptabao-server', 'retained-heptabao-seed'):
            products.append(row)
    need(not overlaps, 'foreign_process_crosses_owned_build_boundary')
    need(not timed or not products, 'external_product_process_present_during_timed_admission')
    remaining(until)
    return {'compile_guard': compile_report, 'timed_guard': timed_report,
            'boundary_overlaps': overlaps, 'product_named_processes': products,
            'pinned_session_daemons': daemons, 'observed_unix_ns': time.time_ns(),
            'scope': 'operator_uid_invocation_time_only', 'persistent_reservation': False,
            'mac_window_release_claimed': False, 'argv_or_environment_read': False}


def stage_source_payload(packet, runner, device, until):
    manifest = packet['manifest']
    need(manifest['review_commit'] == REVIEW_COMMIT and manifest['expected_tree'] == INPUT_TREE
         and manifest['base_commit'] == BASE_COMMIT and manifest['base_tree'] == BASE_TREE
         and len(manifest['changed_files']) == 33, 'exact_full_candidate_delta')
    compressed = base64.b64decode(packet['source_files_gzip_base64'], validate=True)
    need(len(compressed) <= 512 * 1024 and sha(compressed) == packet['source_files_gzip_sha256'],
         'source_packet_compressed_pin')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    need(len(raw) == packet['source_files_json_bytes'] <= 4 * 1024 * 1024
         and sha(raw) == packet['source_files_json_sha256'], 'source_packet_plain_pin')
    payload = json.loads(raw)
    need(payload['schema'] == 'heptabao.closed-33-source-files.v1'
         and len(payload['files']) == 33, 'source_packet_closed_shape')
    contents = {item['path']: item['content'].encode() for item in payload['files']}
    paths = {entry['path'] for entry in manifest['changed_files']}
    need(len(contents) == 33 and set(contents) == paths, 'source_packet_paths')
    for entry in manifest['changed_files']:
        relative = Path(entry['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'candidate_path_boundary')
        data = contents[entry['path']]
        after = entry['after']
        need(after['mode'] == '100644' and after['type'] == 'blob'
             and len(data) == after['bytes'] and sha(data) == after['sha256']
             and blob(data) == after['git_blob'], 'candidate_file_pin')
        destination = SOURCE / relative
        before = entry['before']
        if before is None:
            need(not os.path.lexists(destination), 'new_candidate_file_already_exists')
        else:
            old = read_owned(destination)
            need(blob(old) == before['git_blob'] and len(old) == before['bytes'],
                 'candidate_base_file_changed')
    # Create a distinct branch; the retained physical 7071 branch/ref survives.
    check = runner.run('new-branch-absent', ['/usr/bin/git', '-C', str(SOURCE),
                       'show-ref', '--verify', '--quiet', 'refs/heads/' + BRANCH],
                       until, expect_zero=False)
    need(not check and runner.records[-1]['exit_code'] == 1, 'candidate_branch_already_exists_or_error')
    runner.git('new-candidate-branch', until, 'switch', '--create', BRANCH)
    for entry in manifest['changed_files']:
        remaining(until)
        destination = SOURCE / entry['path']
        pending = []
        parent = destination.parent
        while not parent.exists():
            pending.append(parent)
            parent = parent.parent
        owned_ancestors(parent, device)
        for parent in reversed(pending):
            parent.mkdir(mode=0o700)
            sync_dir(parent.parent)
        owned_ancestors(destination.parent, device)
        temporary = destination.with_name(destination.name + '.linux-candidate-61ff-r1')
        write_raw(temporary, contents[entry['path']])
        os.replace(temporary, destination)
        sync_dir(destination.parent)
    runner.git('candidate-add', until, 'add', '--', *sorted(paths))
    changed = runner.git('candidate-changed-paths', until, 'diff', '--cached', '--name-only').splitlines()
    need(set(changed) == paths and len(changed) == 33
         and runner.git('candidate-exact-tree', until, 'write-tree') == INPUT_TREE,
         'candidate_full_tree_mismatch')
    runner.git('candidate-input-commit', until, 'commit', '--quiet', '-m',
               'Freeze reviewed combined snapshot source for isolated Linux validation')
    observed = source_state(runner, 'candidate-input', until)
    need(observed['tree'] == INPUT_TREE and observed['status'] == '', 'candidate_input_not_clean')
    return observed


def main():
    global work_started
    began = BUILD_BEGAN
    until = began + SHARED_SECONDS
    packet = BUILD_INPUT
    need(__debug__ and sys.flags.optimize == 0, 'guard_assertions_required')
    need(packet['new_candidate_budget_seconds'] == SHARED_SECONDS
         and packet['supervisor_seconds'] == 3900, 'fixed_new_attempt_budget')
    review = verify_admission_input(packet, until)
    device = directory(ROOT).st_dev
    for path in (SOURCE, TARGET):
        directory(path, device)
    for path in (CACHE, CARGO_HOME):
        directory(path)
    need(not os.path.lexists(ATTEMPT) and not os.path.lexists(SOURCE / '.git/index.lock'),
         'fresh_attempt_or_git_index_lock_refused')
    need(sha(packet['guard_source'].encode()) == GUARD_SHA
         and sha(packet['base_frozen_source'].encode()) == BASE_FROZEN_SHA,
         'pinned_guard_or_base_manifest')
    guard = {'__name__': 'heptabao_original_r6_guard'}
    exec(compile(packet['guard_source'], '<pinned-original-r6-guard>', 'exec'), guard)
    initial_admission = guard_boundary_observation(guard, until, False)
    ATTEMPT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700)
    OUTPUT.mkdir(mode=0o700)
    (OUTPUT / 'artifacts').mkdir(mode=0o700)
    (OUTPUT / 'private-tests').mkdir(mode=0o700)
    sync_dir(ROOT)
    work_started = True
    runner = OwnedRunner(OUTPUT, environment())
    result = {'schema': 'heptabao.linux.synthetic-candidate-attempt.v1', 'status': 'failed',
              'configured_host': 'rog', 'mode': packet['mode'], 'review_commit': REVIEW_COMMIT,
              'review_input_tree': INPUT_TREE, 'physical_base_commit': BASE_COMMIT,
              'shared_budget_seconds': SHARED_SECONDS, 'started_unix_ns': BUILD_STARTED_UNIX_NS,
              'deadline_monotonic': until, 'preflight_resolution': packet['authoritative_preflight_resolution'],
              'original_unknown_preflight_resolution': packet['original_unknown_preflight_resolution'],
              'current_resource_and_ownership_review': review,
              'initial_admission': initial_admission, 'critical_tests': CRITICAL_TESTS,
              'observed_tests': [], 'completed_tests': [], 'source_write_started': False,
              'production_linked': False, 'normal_https_observer_executed': False,
              'full_workspace_executed': False, 'physical_ha_qualified': False,
              'mac_window_released': False, 'full_replacement_qualified': False}
    lock_fd = None
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    def compile_step(label, argv):
        write_json(OUTPUT / (label + '-admission.public.json'),
                   guard_boundary_observation(guard, until, False))
        return runner.run(label, argv, until)

    try:
        write_json(CONTROL / 'candidate-input.public.json', packet)
        write_raw(CONTROL / 'run_linux_candidate_r1.py', BUILD_DRIVER_SOURCE.encode())
        before = source_state(runner, 'base', until)
        need(before == {'commit': BASE_COMMIT, 'tree': BASE_TREE, 'status': ''}
             and runner.git('base-branch', until, 'symbolic-ref', 'HEAD') == BASE_BRANCH,
             'physical_base_source_drifted')
        base_manifest = json.loads(packet['base_frozen_source'])
        need(base_manifest['source'] == BASE_COMMIT and base_manifest['tree'] == BASE_TREE
             and len(base_manifest['files']) == 62, 'base_manifest_shape')
        result['base_source_files'] = source_pins(base_manifest['files'], device, until)
        lock_path = TARGET / 'release/.cargo-lock'
        owned_ancestors(lock_path.parent, device)
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        lock_info = os.fstat(lock_fd)
        need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 1000
             and lock_info.st_dev == device and lock_info.st_nlink == 1
             and lock_info.st_size == 0, 'existing_owned_target_lock')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'target_lock_identity_changed')
        result['source_write_started'] = True
        result['actual_input_source'] = stage_source_payload(packet, runner, device, until)
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'target_lock_identity_changed')
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        lock_fd = None
        result['target_preparation_lock_released_before_cargo'] = True
        rustc_vv = runner.run('rustc-version', [str(TOOLCHAIN / 'rustc'), '-vV'], until).decode()
        need('host: x86_64-unknown-linux-gnu' in rustc_vv
             and 'release: 1.98.0' in rustc_vv, 'actual_native_linux_toolchain_version')
        result['rustc_vv'] = rustc_vv
        cargo = str(TOOLCHAIN / 'cargo')
        compile_step('cargo-fmt', [cargo, 'fmt', '--all'])
        compile_step('cargo-fmt-check', [cargo, 'fmt', '--all', '--', '--check'])
        modified = runner.git('formatted-paths', until, 'diff', '--name-only').splitlines()
        allowed = {entry['path'] for entry in packet['manifest']['changed_files']
                   if entry['path'].endswith('.rs')}
        need(set(modified) <= allowed, 'format_changed_unreviewed_source')
        formatted_diff = runner.run('format-diff', ['/usr/bin/git', '-C', str(SOURCE),
                       'diff', '--no-ext-diff', '--no-textconv'], until)
        if modified:
            runner.git('format-add', until, 'add', '--', *sorted(modified))
            runner.git('format-commit', until, 'commit', '--quiet', '-m',
                       'Format isolated combined snapshot validation source')
        frozen = source_state(runner, 'frozen', until)
        need(frozen['status'] == '', 'formatted_source_dirty')
        all_paths = {entry['path'] for entry in base_manifest['files']}
        all_paths.update(entry['path'] for entry in packet['manifest']['changed_files'])
        need(len(all_paths) == 84, 'complete_frozen_catalog_count')
        files = []
        for relative in sorted(all_paths):
            remaining(until)
            raw = read_owned(SOURCE / relative)
            files.append({'path': relative, 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw)})
        frozen_manifest = {'schema': 'heptabao.linux.candidate-frozen-source.v1',
            'source': frozen['commit'], 'tree': frozen['tree'], 'source_path': str(SOURCE),
            'review_input_commit': REVIEW_COMMIT, 'review_input_tree': INPUT_TREE,
            'actual_input_source': result['actual_input_source'], 'files': files,
            'critical_tests': CRITICAL_TESTS, 'formatted': True, 'compiled': False,
            'format_changed_paths': sorted(modified), 'format_diff_sha256': sha(formatted_diff),
            'normal_profile': NORMAL_PROFILE, 'full_replacement_qualified': False}
        result['frozen_source'] = frozen
        result['frozen_manifest_sha256'] = write_json(CONTROL / 'frozen-source.public.json', frozen_manifest)
        strict_args = [cargo, 'clippy', '--release', '--locked', '--offline',
                       '--workspace', '--all-targets', '--exclude', 'qrcode', '--', '-D', 'warnings']
        compile_step('strict-clippy', strict_args)
        write_json(CONTROL / 'clippy-qualified-source.public.json', {
            'source': frozen['commit'], 'tree': frozen['tree'],
            'frozen_manifest_sha256': result['frozen_manifest_sha256'],
            'strict_clippy': runner.records[-1], 'normal_profile': NORMAL_PROFILE,
            'production_linked': False, 'workspace_tests_passed': False,
            'qualified_full_replacement': False})
        test_raw = compile_step('server-tests-compile', [cargo, 'test', '--release', '--locked',
                    '--offline', '-p', 'heptabao-server', '--lib', '--no-run',
                    '--message-format=json-render-diagnostics'])
        matches = [e for e in artifact_events(test_raw) if e.get('reason') == 'compiler-artifact'
                   and e.get('executable') and e.get('target', {}).get('src_path')
                   == str(SOURCE / 'crates/heptabao-server/src/lib.rs')
                   and e.get('profile', {}).get('test') is True]
        need(len(matches) == 1, 'unique_current_server_libtest_artifact')
        test_artifact = retain_artifact(matches[0], 'heptabao-server-tests', device, until, True)
        result['test_artifact'] = test_artifact
        binary = test_artifact['path']
        if packet['mode'] == 'compile_only':
            result['status'] = 'strict_and_server_libtest_compiled_only'
        else:
            write_json(OUTPUT / 'test-list-admission.public.json',
                       guard_boundary_observation(guard, until, True))
            listed = runner.run('server-tests-list', [binary, '--list'], until).decode('utf-8', 'strict')
            available = [line[:-6] for line in listed.splitlines() if line.endswith(': test')]
            need(len(CRITICAL_TESTS) == len(set(CRITICAL_TESTS)) == 19
                 and all(available.count(name) == 1 for name in CRITICAL_TESTS),
                 'exact_nineteen_test_inventory')
            for index, name in enumerate(CRITICAL_TESTS, 1):
                label = 'critical-test-' + str(index).zfill(2)
                write_json(OUTPUT / (label + '-admission.public.json'),
                           guard_boundary_observation(guard, until, True))
                private_tmp = OUTPUT / 'private-tests' / str(index).zfill(2)
                private_tmp.mkdir(mode=0o700)
                previous_environment = runner.environment
                runner.environment = {**previous_environment, 'TMPDIR': str(private_tmp)}
                try:
                    raw = runner.run(label, [binary, '--exact', name, '--nocapture',
                                      '--test-threads=1'], until, expect_zero=False)
                finally:
                    runner.environment = previous_environment
                output = raw.decode('utf-8', 'strict')
                empty = not any(private_tmp.iterdir())
                observed = {'name': name, 'record': str(OUTPUT / (label + '.public.json')),
                    'stdout_sha256': runner.records[-1]['stdout_sha256'],
                    'stderr_sha256': runner.records[-1]['stderr_sha256'],
                    'artifact_sha256': test_artifact['sha256'],
                    'private_tmp_path': str(private_tmp), 'private_tmp_empty': empty,
                    'passed': (runner.records[-1]['exit_code'] == 0
                        and output.count('running 1 test') == 1
                        and output.count('test result: ok. 1 passed; 0 failed;') == 1 and empty)}
                result['observed_tests'].append(observed)
                if observed['passed']:
                    result['completed_tests'].append(observed)
            result['failed_tests'] = [x['name'] for x in result['observed_tests'] if not x['passed']]
            need(len(result['observed_tests']) == 19 and not result['failed_tests'],
                 'critical_test_failures')
            need(hash_owned(Path(binary), until) == test_artifact['sha256'], 'test_artifact_changed')
            production_args = [cargo, 'build', '--release', '--locked', '--offline',
                '-p', 'heptabao-server', '--bin', 'heptabao-server', '--bin', 'heptabao-seed',
                '--message-format=json-render-diagnostics']
            production_raw = compile_step('production-build', production_args)
            artifacts = {}
            events = artifact_events(production_raw)
            for name in ('heptabao-server', 'heptabao-seed'):
                found = [e for e in events if e.get('reason') == 'compiler-artifact'
                         and e.get('target', {}).get('name') == name and e.get('executable')
                         and e.get('manifest_path') == str(SOURCE / 'crates/heptabao-server/Cargo.toml')]
                need(len(found) == 1, 'exact_production_artifact_' + name)
                artifacts[name] = retain_artifact(found[0], name, device, until, False)
            result.update(artifacts=artifacts, production_linked=True,
                          status='normal_candidate_built_after_nineteen_components')
        need(source_state(runner, 'final', until) == frozen, 'source_changed_during_validation')
        source_pins(files, device, until)
        result['source_freeze_verified'] = True
    except BaseException as error:
        result.update(status='failed', failure_class=type(error).__name__,
                      failure_code=str(error) if isinstance(error, RuntimeError) else None)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        result['commands'] = runner.records
        try:
            result['last_owned_child_cleanup'] = runner.cleanup()
            cleanup = result['last_owned_child_cleanup']
            if cleanup and (cleanup.get('remaining') or cleanup.get('forced')):
                result.update(status='failed', failure_code='owned_group_cleanup_incomplete')
        except Exception as error:
            result.update(status='failed', cleanup_error_class=type(error).__name__)
        finally:
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        result['elapsed_seconds'] = time.monotonic() - began
        result['remaining_seconds'] = max(0, until - time.monotonic())
        if time.monotonic() > until:
            result.update(status='failed', failure_code='new_attempt_absolute_deadline')
        result_sha = write_json(CONTROL / 'candidate-result.public.json', result)
        print(json.dumps({'status': result['status'], 'result_sha256': result_sha,
              'result_path': str(CONTROL / 'candidate-result.public.json'),
              'source': result.get('frozen_source'), 'observed_tests': len(result['observed_tests']),
              'passed_tests': len(result['completed_tests']), 'full_replacement_qualified': False},
              sort_keys=True), flush=True)
    return 0 if result['status'] in ('strict_and_server_libtest_compiled_only',
                                    'normal_candidate_built_after_nineteen_components') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_after_evidence_root_created' if work_started
                          else 'refused_before_mutation', 'error_class': type(error).__name__,
                          'error_code': str(error) if isinstance(error, RuntimeError) else None,
                          'full_replacement_qualified': False}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
