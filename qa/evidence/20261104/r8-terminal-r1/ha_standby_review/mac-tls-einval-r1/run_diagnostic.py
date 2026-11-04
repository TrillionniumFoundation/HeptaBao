#!/usr/bin/env python3
"""One fresh diagnostic invocation; the retained R8 failure is never rewritten."""
import ast, hashlib, json, os, re, signal, stat, subprocess, sys, time
from pathlib import Path

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
R8 = BASE / 'continuation-20261104-native-ssh-http-r8'
source = R8 / 'source'
output = R8 / 'mac-tls-einval-diagnostic-r1'
OLD_RESULT = R8 / 'normal-exact33-r1/result.public.json'
OLD_RESULT_SHA = 'fc6677c0f65ba0e2050f0fe20d25356cba33a20ab2c287de5e0e0c7d4dd56557'
HEAD = '2d9a2efd4cfc3a9ee60a450eee58866828a3f5ad'
TREE = 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04'
LIBTEST_SHA = '648236a59ebf23aee2ebd02039e6045fb491cebff80ac8d4e564b78b3e316aab'
LIBTEST_BYTES = 154048544
ORIGINAL_CONTROLLER_SHA = 'eb6f53b842f79d221e78b79628690df6db37002284c0ca4a400b18eac817b728'
TEST = 'http::snapshot::redirect_tests::native_http_redirect_tcp_tls_first_record_is_complete_with_unread_upload'
os.umask(0o077)
def need(value, label):
    if not value:
        raise RuntimeError(label)
def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
def put(path, raw, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    parent_fd = os.open(Path(path).parent, os.O_RDONLY)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def copy_exact(old, new, wanted, size):
    fd = os.open(old, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
             and not before.st_mode & 0o022 and before.st_size == size, 'original_libtest_custody')
        outfd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
        h = hashlib.sha256(); copied = 0
        with os.fdopen(outfd, 'wb') as out:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block: break
                h.update(block); copied += len(block); out.write(block)
            out.flush(); os.fsync(out.fileno())
        need(copied == size and h.hexdigest() == wanted and identity(os.fstat(fd)) == identity(before), 'retained_libtest_exact')
        need(identity(os.lstat(old)) == identity(before), 'original_libtest_path_unchanged')
        need(digest(new) == wanted and os.stat(new).st_nlink == 1, 'retained_libtest_readback')
        pfd = os.open(new.parent, os.O_RDONLY)
        try: os.fsync(pfd)
        finally: os.close(pfd)
        return {'source': str(old), 'retained': str(new), 'bytes': copied, 'sha256': wanted,
                'source_identity': list(identity(before)), 'retained_mode': stat.S_IMODE(os.stat(new).st_mode)}
    finally:
        os.close(fd)

need(os.uname().sysname == 'Darwin' and os.uname().machine == 'arm64' and os.getuid() == 501, 'exact_mac_host_abi_uid')
need(R8.resolve(strict=True) == R8 and source.resolve(strict=True) == source, 'owned_root_no_symlink')
need(not output.exists() and not output.is_symlink(), 'fresh_diagnostic_root_required')
payload = json.loads(sys.stdin.read())
need(set(payload) == {'observer', 'observer_sha256', 'original_controller'}, 'exact_input_fields')
observer = payload['observer'].encode()
need(hashlib.sha256(observer).hexdigest() == payload['observer_sha256'], 'observer_source_pin')
controller = payload['original_controller'].encode()
need(hashlib.sha256(controller).hexdigest() == ORIGINAL_CONTROLLER_SHA, 'unchanged_lifecycle_controller_pin')
need(digest(OLD_RESULT) == OLD_RESULT_SHA, 'original_failed_result_pin')
old_result = json.loads(OLD_RESULT.read_bytes())
need(old_result['status'] == 'failed' and old_result['source_commit'] == HEAD and old_result['source_tree'] == TREE, 'original_failed_source')
need(old_result['binary']['sha256'] == LIBTEST_SHA and old_result['binary']['bytes'] == LIBTEST_BYTES, 'original_libtest_receipt')
need(all(c['direct_child_reaped'] and not c['remaining'] for c in old_result['cleanup']), 'original_owned_groups_stopped')
need(not any(k.startswith('DYLD_') for k in os.environ), 'no_inherited_dyld_override')
output.mkdir(mode=0o700)
(output / 'tmp').mkdir(mode=0o700)
code = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
put(output / 'controller.py', code)
put(output / 'observe_errno.c', observer)
put(output / 'original_lifecycle_controller.py', controller)

# Compile the exact previously reviewed lifecycle function bodies. No argparse,
# build, source mutation, original output directory or original main is executed.
selected = {'Cancelled', 'signal_received', 'sha', 'write', 'git', 'freeze',
            'group_members', 'terminate_owned', 'owned'}
nodes = [n for n in ast.parse(controller).body
         if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in selected]
need(len(nodes) == len(selected) and {n.name for n in nodes} == selected, 'exact_lifecycle_ast_selection')
children = []; protected = 0; pending_signal = None
environment = dict(os.environ)
environment.update({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(output / 'tmp')})
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(output / 'original_lifecycle_controller.py'), 'exec'), globals())
for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, signal_received)
result = {'schema': 'heptabao.mac-r8-tls-einval-single-diagnostic.v1', 'status': 'failed',
          'diagnostic_only': True, 'qualification': False, 'production_changed': False,
          'original_failed_result_sha256': OLD_RESULT_SHA, 'source_commit': HEAD, 'source_tree': TREE,
          'observer_source_sha256': payload['observer_sha256'], 'controller_sha256': hashlib.sha256(code).hexdigest(),
          'reused_lifecycle_controller_sha256': ORIGINAL_CONTROLLER_SHA,
          'exact_test': TEST, 'new_operation_attempts': 0, 'old_operation_replayed': False,
          'original_test_deadline_seconds': 5, 'original_group_envelope_seconds': 600,
          'io_buffers_logged': False, 'syscall_return_values_or_errno_changed': False,
          'startup_ns': time.time_ns()}
write('intent.public.json', result)
try:
    before = freeze()
    need(before == {'commit': HEAD, 'tree': TREE, 'status': ''}, 'source_freeze')
    retained = output / 'retained-r8-libtest'
    result['retention'] = copy_exact(Path(old_result['binary']['path']), retained, LIBTEST_SHA, LIBTEST_BYTES)
    write('retention.public.json', result['retention'])
    compiler = owned('observer-compile', ['/usr/bin/clang', '-arch', 'arm64', '-std=c11', '-O2',
                     '-Wall', '-Wextra', '-Werror', '-dynamiclib', str(output / 'observe_errno.c'),
                     '-o', str(output / 'observe_errno.dylib')], 120)
    result['compiler'] = compiler
    need(compiler['exit_code'] == 0 and not compiler['timed_out'], 'observer_compile')
    library = output / 'observe_errno.dylib'
    need(library.is_file() and not library.is_symlink() and library.stat().st_nlink == 1, 'observer_library_custody')
    os.chmod(library, 0o500)
    result['observer_library_sha256'] = digest(library)
    listing = owned('exact-list', [str(retained), TEST, '--exact', '--list'], 30)
    selected_names = [line[:-6] for line in (output / 'exact-list.stdout').read_text().splitlines() if line.endswith(': test')]
    need(listing['exit_code'] == 0 and not listing['timed_out'] and selected_names == [TEST], 'one_exact_test_selected')
    environment['DYLD_INSERT_LIBRARIES'] = str(library)
    result['new_operation_attempts'] = 1
    result['test'] = owned('observed-exact', [str(retained), TEST, '--exact', '--nocapture', '--test-threads=1'], 600)
    stderr = (output / 'observed-exact.stderr').read_text()
    loaded = stderr.count('HB_EINVAL_OBSERVER_LOADED v1\n')
    events = [json.loads(line[len('HB_EINVAL_EVENT '):]) for line in stderr.splitlines() if line.startswith('HB_EINVAL_EVENT ')]
    counts = [json.loads(line[len('HB_EINVAL_COUNT '):]) for line in stderr.splitlines() if line.startswith('HB_EINVAL_COUNT ')]
    totals = [int(line[len('HB_EINVAL_TOTAL '):]) for line in stderr.splitlines() if line.startswith('HB_EINVAL_TOTAL ')]
    result.update({'observer_loaded_count': loaded, 'events': events, 'call_counts': counts, 'total_einval': totals})
    need(loaded == 1 and len(counts) == 16 and len(totals) == 1 and totals[0] <= 32, 'complete_bounded_observer_output')
    names = {'setsockopt','getsockopt','read','write','readv','writev','recv','send',
             'recvfrom','sendto','connect','bind','listen','accept','shutdown','poll'}
    need(len(events) == totals[0] and sorted(x['sequence'] for x in events) == list(range(1, totals[0] + 1))
         and all(x['errno'] == 22 and x['call'] in names and x['result'] < 0 for x in events), 'all_error_events_complete')
    need({x['call'] for x in counts} == names and all(isinstance(x['count'], int) and x['count'] >= 0 for x in counts), 'exact_unique_call_counters')
    need(any(x['call'] == 'setsockopt' and x['count'] > 0 for x in counts), 'actual_syscalls_observed')
    stdout = (output / 'observed-exact.stdout').read_text()
    outcomes = re.findall(r'^test (.+) \.\.\. (ok|FAILED)$', stdout, re.M)
    need(len(outcomes) == 1 and outcomes[0][0] == TEST, 'one_actual_test_outcome')
    need(result['test']['exit_code'] == (0 if outcomes[0][1] == 'ok' else 101), 'actual_test_exit_matches_outcome')
    result['actual_test_outcome'] = outcomes[0][1]
    need(digest(library) == result['observer_library_sha256'] and digest(output / 'observe_errno.c') == payload['observer_sha256'], 'observer_unchanged')
    result['status'] = 'observed'
except BaseException as error:
    result['error_type'] = type(error).__name__
    result['error'] = str(error)
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
    cleanup = []
    for label, process in reversed(children):
        try:
            remaining = terminate_owned(process)
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None, 'remaining': remaining})
        except BaseException as error:
            cleanup.append({'label': label, 'pid': process.pid, 'cleanup_error_type': type(error).__name__})
    result['cleanup'] = cleanup
    result['all_owned_stopped'] = all(x.get('direct_child_reaped') and not x.get('remaining') and not x.get('cleanup_error_type') for x in cleanup)
    try:
        result['source_unchanged'] = freeze() == {'commit': HEAD, 'tree': TREE, 'status': ''}
        result['original_failed_result_unchanged'] = digest(OLD_RESULT) == OLD_RESULT_SHA
        result['original_libtest_unchanged'] = digest(old_result['binary']['path']) == LIBTEST_SHA
        if (output / 'retained-r8-libtest').exists(): result['retained_libtest_unchanged'] = digest(output / 'retained-r8-libtest') == LIBTEST_SHA
    except BaseException as error:
        result['final_fence_error_type'] = type(error).__name__
    if pending_signal is not None or not result['all_owned_stopped'] or not all(result.get(k) for k in ['source_unchanged','original_failed_result_unchanged','original_libtest_unchanged','retained_libtest_unchanged']):
        result['status'] = 'failed'
    result['terminal_ns'] = time.time_ns()
    write('result.public.json', result)
    print(json.dumps({'status': result['status'], 'diagnostic_only': True, 'qualification': False,
                      'result_path': str(output / 'result.public.json'), 'result_sha256': digest(output / 'result.public.json'),
                      'all_owned_stopped': result['all_owned_stopped']}), flush=True)
raise SystemExit(0 if result['status'] == 'observed' else 1)
