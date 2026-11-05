import ast
import copy
import errno
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
checks = []
def need(value, name):
    assert value, name
    checks.append(name)
def sha(raw):
    return hashlib.sha256(raw.encode()).hexdigest()
def functions(source):
    return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
def strict_apply(before, diff):
    src = before.splitlines(keepends=True); dst = []; lines = diff.splitlines(keepends=True); cursor = 0; n = 2; hunks = 0
    assert lines[0].startswith('--- ') and lines[1].startswith('+++ ')
    while n < len(lines):
        m = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n', lines[n]); assert m
        start = int(m[1]) - 1; old = int(m[2]) if m[2] is not None else 1; new = int(m[4]) if m[4] is not None else 1
        assert start >= cursor; dst.extend(src[cursor:start]); cursor = start; n += 1; seen_old = seen_new = 0
        while n < len(lines) and not lines[n].startswith('@@ '):
            row = lines[n]; n += 1; assert row and row[0] in ' +-'
            if row[0] in ' -':
                assert cursor < len(src) and src[cursor] == row[1:]; cursor += 1; seen_old += 1
            if row[0] in ' +':
                dst.append(row[1:]); seen_new += 1
        assert (seen_old, seen_new) == (old, new); hunks += 1
    dst.extend(src[cursor:]); return ''.join(dst), hunks

base = (ROOT/'reference/mac-wrapper-unbound.py').read_text()
unbound = (ROOT/'candidate/mac-wrapper-system-git.UNBOUND.py').read_text()
bound = (ROOT/'proposed-bound/run_current_mac_full34_r1.py').read_text()
pub0 = (ROOT/'reference/inert-original.py').read_text()
pub1 = (ROOT/'candidate/inert-publisher.UNBOUND.py').read_text()
pub2 = (ROOT/'proposed-bound/inert-publisher.py').read_text()
hunk_counts = {}
for name, before, after in [('mac-wrapper-system-git.diff', base, unbound), ('metadata-binding.diff', unbound, bound), ('inert-original-to-mac.diff', pub0, pub1), ('publisher-binding.diff', pub1, pub2)]:
    rebuilt, count = strict_apply(before, (ROOT/'diff'/name).read_text())
    need(rebuilt == after, 'strict_whole:' + name); hunk_counts[name] = count
for source_name, source in [('base', base), ('unbound', unbound), ('bound', bound), ('publisher0', pub0), ('publisher1', pub1), ('publisher2', pub2)]:
    compile(source, '<' + source_name + '>', 'exec'); need(True, 'compile_only:' + source_name)
f0, f1, f2 = functions(base), functions(unbound), functions(bound)
for name in f0:
    if name != 'readonly_prepare': need(f0[name] == f1[name], 'original_function_byte_equal:' + name)
need(f1 == f2, 'metadata_binding_all_functions_byte_equal')
need(f0['fixed_file'] == f2['fixed_file'], 'generic_single_link_guard_unchanged')
for name in ['sha', 'ident', 'sync_dir']: need(functions(pub0)[name] == functions(pub1)[name], 'publisher_original_helper:' + name)
need(functions(pub1) == functions(pub2), 'publisher_binding_all_functions_byte_equal')
edits = json.loads((ROOT/'review/publisher-literal-edits.public.json').read_text()); reverse = pub1
for i, edit in reversed(list(enumerate(edits))):
    need(reverse.count(edit['after']) == 1, 'publisher_unique_inverse:' + str(i)); reverse = reverse.replace(edit['after'], edit['before'], 1)
need(reverse == pub0, 'publisher_full_inverse')

table = json.loads((ROOT/'proposed-bound/input-metadata.public.json').read_text())
ids = table['git']['identity']; expected_digest = table['git']['sha256']
selected_names = {'need', 'full9', 'prepare_remaining', 'fixed_system_git'}
selected = [n for n in ast.parse(bound).body if isinstance(n, ast.FunctionDef) and n.name in selected_names]
need(len(selected) == 4, 'four_actual_selected_definitions')
module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
selected_code = compile(module, '<actual-selected-system-git>', 'exec')
component_rows = []
cases = ['exact', 'metadata_links1', 'metadata_owner501', 'symlink_named', 'symlink_open', 'fd_before_drift', 'fd_after_drift', 'short_read', 'body_overrun', 'extra_eof', 'digest_mismatch', 'name_after_drift', 'expired_after_close', 'close_error']
for case in cases:
    state = {'opened': 0, 'close_attempts': 0, 'closed': 0, 'fd_stats': 0, 'named_stats': 0, 'returned': 0, 'hashed': 0, 'read_requests': [], 'open_flags': None}
    input_metadata = {'git': copy.deepcopy(table['git'])}
    if case == 'metadata_links1': input_metadata['git']['identity'][5] = 1
    if case == 'metadata_owner501': input_metadata['git']['identity'][2] = 501
    def info(values):
        return SimpleNamespace(**dict(zip(['st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'], values)))
    class FakePath:
        def __init__(self, path): assert path == '/usr/bin/git'
        def __str__(self): return '/usr/bin/git'
        def lstat(self):
            state['named_stats'] += 1; values = list(ids)
            if case == 'symlink_named': values[4] = stat.S_IFLNK | 0o755
            if case == 'name_after_drift' and state['named_stats'] == 2: values[1] += 1
            return info(values)
    def fd_stat(fd):
        assert fd == 123; state['fd_stats'] += 1; values = list(ids)
        if case == 'fd_before_drift' and state['fd_stats'] == 1: values[1] += 1
        if case == 'fd_after_drift' and state['fd_stats'] == 2: values[8] += 1
        return info(values)
    def os_open(path, flags):
        assert str(path) == '/usr/bin/git'; state['open_flags'] = flags
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        if case == 'symlink_open': raise OSError(errno.ELOOP, 'synthetic')
        state['opened'] += 1; return 123
    class Stream:
        position = 0
        def __enter__(self): return self
        def __exit__(self, typ, value, tb):
            state['close_attempts'] += 1
            if case == 'close_error': raise OSError('synthetic close refusal')
            state['closed'] += 1
        def fileno(self): return 123
        def read(self, count):
            state['read_requests'].append(count)
            if case == 'short_read' and self.position == 0: return b''
            if case == 'body_overrun' and self.position == 0: data = b'x' * 118641
            elif self.position >= 118640: data = b'x' if case == 'extra_eof' else b''
            else: data = b'x' * min(count, 118640 - self.position)
            self.position += len(data); state['returned'] += len(data); return data
    def fake_open(path, mode, *, opener):
        assert mode == 'rb'; assert opener(path, os.O_RDONLY) == 123; return Stream()
    class Digest:
        def update(self, data): state['hashed'] += len(data)
        def hexdigest(self): return '0' * 64 if case == 'digest_mismatch' else expected_digest
    def monotonic(): return 61.0 if case == 'expired_after_close' and state['closed'] else 1.0
    namespace = {'INPUT_METADATA': input_metadata, 'INPUT_PATHS': {'git': '/usr/bin/git'}, 'Path': FakePath, 'stat': stat, 'os': SimpleNamespace(open=os_open, fstat=fd_stat, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK), 'hashlib': SimpleNamespace(sha256=Digest), 'open': fake_open, 'time': SimpleNamespace(monotonic=monotonic), '_PREPARE_UNTIL': 60.0}
    exec(selected_code, namespace)
    returned = False; error = None
    try:
        observed = namespace['fixed_system_git'](); returned = True
        need(observed == table['git'], 'component:' + case + ':exact_metadata_return')
    except (RuntimeError, OSError) as exc:
        error = type(exc).__name__ + ':' + str(exc)
    need(returned is (case == 'exact'), 'component:' + case + ':correct_result')
    need(state['close_attempts'] == state['opened'], 'component:' + case + ':once_close_attempt')
    need(state['closed'] == state['opened'] or case == 'close_error', 'component:' + case + ':close_outcome')
    if case == 'exact':
        need(state['read_requests'] == [65536, 53104, 1] and state['returned'] == 118640 and state['hashed'] == 118640, 'component:exact:body_and_eof_bounded')
    if case in ('metadata_links1', 'metadata_owner501', 'symlink_named', 'symlink_open'): need(state['opened'] == 0, 'component:' + case + ':no_owned_fd')
    component_rows.append({'case': case, 'returned': returned, 'error': error, **state})

inert = json.loads((ROOT/'proposed-bound/INERT.request.REVIEW-ONLY.json').read_text())
prepare = json.loads((ROOT/'proposed-bound/PREPARE.request.REVIEW-ONLY.json').read_text())
carrier = (ROOT/'proposed-bound/carrier.json').read_text()
need(inert['host'] == prepare['host'] == 'mac', 'exact_request_host')
need(inert['executable'] == prepare['executable'] == table['python']['path'], 'exact_observed_regular_python')
need(inert['args'] == ['-I', '-S', '-B', '-c', pub2] and inert['stdin'] == carrier, 'inert_exact_source_and_stdin')
need(inert['timeout_seconds'] == 60 and prepare['timeout_seconds'] == 90, 'separate_publication_and_prepare_caps')
need(prepare['args'] == ['-I', '-S', '-B', prepare['cwd'] + '/control/run_current_mac_full34_r1.py', '--prepare-only'], 'prepare_exact_argv')
need(len(inert['idempotency_key'].encode()) <= 128 and len(prepare['idempotency_key'].encode()) <= 128 and inert['idempotency_key'] != prepare['idempotency_key'], 'distinct_stable_request_keys')
need('1800' in f2['main'] or 'ORIGINAL_RUNTIME_OUTER_SECONDS=1800' in bound, 'runtime_outer_literal_unchanged')
result = {'schema': 'heptabao.mac-full34-publication-and-system-git-source-verification.v1', 'status': 'SOURCE_ONLY_OFFLINE_PASS', 'checks_passed': len(checks), 'checks': checks, 'strict_hunks': hunk_counts, 'selected_fake_io_component_count': len(component_rows), 'components': component_rows, 'fake_io_and_fake_digest_only': True, 'actual_git_body_read_here': False, 'actual_mac_open_or_close_executed_here': False, 'runtime_requests_submitted': 0, 'wrapper_generic_fixed_file_byte_equal': True, 'proposed_ready_source_is_not_runtime_authority': True}
raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
(ROOT/'review/source-checks.public.json').write_text(raw)
print(json.dumps({'checks_passed': len(checks), 'selected_components': len(component_rows), 'strict_hunks': hunk_counts, 'result_bytes': len(raw.encode()), 'result_sha256': sha(raw)}))
