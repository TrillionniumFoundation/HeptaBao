#!/usr/bin/env python3
"""Offline AST and selected fake-I/O checks. The stage main and QA are never run."""
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import ast
import copy
import hashlib
import json
import os as real_os
import stat

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'proposal'
before = (ROOT / 'input/before-stage.py').read_text()
after = (OUT / 'stage_h2_r1.py').read_text()
old_ast, new_ast = ast.parse(before), ast.parse(after)
compile(new_ast, '<H2-stage-compile-only>', 'exec')
checks = []

def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

def definitions(tree, text):
    out = {}
    def walk(node, prefix=''):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[name] = ast.get_source_segment(text, child)
                walk(child, name + '.')
            else:
                walk(child, prefix)
    walk(tree)
    return out

old_defs, new_defs = definitions(old_ast, before), definitions(new_ast, after)
check('same eighteen ordered definitions', list(old_defs) == list(new_defs) and len(old_defs) == 18)
changed = [name for name in old_defs if old_defs[name] != new_defs[name]]
check('only five existing definitions changed', changed == ['NewDirectories.__init__', 'NewDirectories.create', 'NewDirectories.write', 'NewDirectories.copy', 'main'])
for name in old_defs:
    if name not in changed:
        check('unchanged whole definition: ' + name, old_defs[name] == new_defs[name])
check('imports exactly unchanged', [ast.dump(n) for n in old_ast.body if isinstance(n, (ast.Import, ast.ImportFrom))] == [ast.dump(n) for n in new_ast.body if isinstance(n, (ast.Import, ast.ImportFrom))])
check('no process/network/importlib APIs introduced', not any(isinstance(n, ast.Name) and n.id in {'subprocess', 'socket', 'requests', 'urllib', 'importlib'} for n in ast.walk(new_ast)))
check('original close/failure/deadline tail whole unchanged', before[before.index('    except BaseException as error:\n        result.update(status="failed"'):] == after[after.index('    except BaseException as error:\n        result.update(status="failed"'):])
check('single original internal deadline assignment', after.count('UNTIL = started + 300_000_000_000') == 1)
check('original input cap', after.count('sys.stdin.buffer.read(1024 * 1024 + 1)') == 1)
check('original chunk bound', after.count('os.read(fd, 65536)') == before.count('os.read(fd, 65536)'))
check('no official executable dependency or binding member', 'OFFICIAL' not in after and 'spec["official_cli"]' not in after and 'official = capture(' not in after)
check('source and six old fences retained before any creation', after.index('old_fences = [capture(') < after.index('owned = NewDirectories()'))
check('no additional class or function', sum(isinstance(n, ast.ClassDef) for n in ast.walk(old_ast)) == sum(isinstance(n, ast.ClassDef) for n in ast.walk(new_ast)))

def literal(name, tree=new_ast):
    node = next(n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'json' and node.func.attr == 'loads':
        return json.loads(ast.literal_eval(node.args[0]))
    return ast.literal_eval(node)

check('original three product-copy tuples whole value', literal('COPY') == literal('COPY', old_ast))
check('six fence constants unchanged', literal('OLD_FENCES') == literal('OLD_FENCES', old_ast) and len(literal('OLD_FENCES')) == 6)
for const in ('BASE', 'SOURCE', 'INCOMING', 'MACHINE_SHA', 'HEAD', 'TREE'):
    old_node = next(n for n in old_ast.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == const for t in n.targets))
    new_node = next(n for n in new_ast.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == const for t in n.targets))
    check('unchanged fixed constant ' + const, ast.dump(old_node) == ast.dump(new_node))
payload_raw = (OUT / 'source-carrier.json').read_bytes()
payload = json.loads(payload_raw)
check('eight-member exact payload SHA/size', len(payload['files']) == 8 and len(payload_raw) == literal('PAYLOAD_BYTES') and hashlib.sha256(payload_raw).hexdigest() == literal('PAYLOAD_SHA'))
file_pins = literal('FILES')
check('payload members exactly FILES', set(payload['files']) == set(file_pins))
for name, raw in payload['files'].items():
    check('whole payload member ' + name, len(raw.encode()) == file_pins[name]['bytes'] and hashlib.sha256(raw.encode()).hexdigest() == file_pins[name]['sha256'])
spec = json.loads(payload['files']['binding.partially-resolved.json'])
template = (ROOT / 'input/fixture-template.private.json').read_text()
check('template whole unchanged, still unresolved', payload['files']['binding.partially-resolved.json'] == template and spec['ready_for_readonly_prepare'] is False)
for name in literal('QA_NAMES'):
    check('unchanged whole H2 QA ' + name, payload['files'][name] == (ROOT / 'input/qa' / name).read_text())
check('all twenty-two target roles distinct', len({x['path'] for category in ('qa_files', 'artifacts', 'h2_client') for x in spec[category].values()}) == 22)
imap = json.loads((ROOT / 'input/instrument12-map.public.json').read_text())
for row in imap['rows']:
    v = literal('H2_COPY')[row['role']]
    src, target = row['desktop_incoming_receiver'], row['h2_planned_target']
    check('exact copy tuple role ' + row['role'], v == (row['name'], src['bytes'], src['sha256'], src['mode'], target['mode']))
check('five info slots still unobserved', [r['index'] for r in imap['rows'] if r['independent_desktop_incoming_info'] is None] == [7, 8, 9, 10, 11])
check('all instrument target identity slots null', all(r['h2_target_actual_identity'] is None for r in imap['rows']))
check('new h2qa FD immediately enters existing ledger', 'self.fds.append(fd)\n            self.children.append' in new_defs['NewDirectories.create'])
check('new H2 incoming in unchanged final directory fence', 'for path in (SOURCE, INCOMING, H2_INCOMING)' in after and 'for name, captured_directory in directory_fences.items():' in after)
check('new H2 source whole metadata after copy', '*[entry["source"] for entry in h2_copied.values()]' in after)

# Only selected original functions and the existing directory class are defined
# into a fake-only namespace. No imports, constants with calls, main, module tail,
# QA code, native FD, filesystem I/O, child or network calls run there.
selected_names = {'StageError', 'need', 'remaining', 'sha', 'identity', 'directory_identity', 'absent', 'open_source', 'finish_source', 'NewDirectories'}
selected = [copy.deepcopy(n) for n in new_ast.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in selected_names]
check('selected definitions only, never main', len(selected) == len(selected_names) and all(n.name != 'main' for n in selected))
selected_code = compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), '<selected-H2-stage-definitions-fake-OS-only>', 'exec')

class Clock:
    def __init__(self):
        self.now = 1
    def monotonic_ns(self):
        return self.now

class FakePath:
    def __init__(self, fs, path):
        self.fs, self.path = fs, PurePosixPath(str(path))
    @property
    def parent(self):
        return FakePath(self.fs, self.path.parent)
    @property
    def name(self):
        return self.path.name
    def __truediv__(self, name):
        return FakePath(self.fs, self.path / name)
    def __str__(self):
        return str(self.path)
    def __eq__(self, other):
        return isinstance(other, FakePath) and self.fs is other.fs and self.path == other.path
    def is_absolute(self):
        return self.path.is_absolute()
    def resolve(self, strict=True):
        self.lstat()
        return self
    def lstat(self):
        return self.fs.stat(str(self))
    def is_dir(self):
        return stat.S_ISDIR(self.lstat().st_mode)

class FakeFS:
    def __init__(self, clock):
        self.clock, self.nodes, self.handles, self.opened, self.closes = clock, {}, {}, [], []
        self.next_fd, self.next_ino = 10, 100
        self.fail_h2_stat = False
        self.close_fail_paths = set()
        self.source_after_read = None
        self.corrupt_target_read = False
        self.bad_target_name = False
        self.read_events = []
        self.OS = SimpleNamespace(**{name: getattr(real_os, name) for name in ('O_RDONLY', 'O_RDWR', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CREAT', 'O_EXCL', 'SEEK_SET')})
        for name in ('open', 'close', 'stat', 'fstat', 'mkdir', 'fsync', 'read', 'write', 'fchmod', 'lseek', 'listdir'):
            setattr(self.OS, name, getattr(self, name))
    def add(self, path, directory=False, mode=0o700, raw=b''):
        self.next_ino += 1
        self.nodes[path] = {'path': path, 'directory': directory, 'mode': mode, 'uid': 1000, 'gid': 1000, 'links': 1, 'ino': self.next_ino, 'data': bytearray(raw), 'mtime': 7, 'ctime': 7}
        return self.nodes[path]
    def _path(self, value, dir_fd=None):
        if dir_fd is None:
            return str(value)
        return str(PurePosixPath(self.handles[dir_fd]['node']['path']) / str(value))
    def _st(self, node):
        return SimpleNamespace(st_dev=1, st_ino=node['ino'], st_uid=node['uid'], st_gid=node['gid'], st_mode=(stat.S_IFDIR if node['directory'] else stat.S_IFREG) | node['mode'], st_nlink=node['links'], st_size=0 if node['directory'] else len(node['data']), st_mtime_ns=node['mtime'], st_ctime_ns=node['ctime'])
    def stat(self, path, dir_fd=None, follow_symlinks=False):
        name = self._path(path, dir_fd)
        if name not in self.nodes:
            raise FileNotFoundError(name)
        value = self._st(self.nodes[name])
        if self.bad_target_name and name.startswith('/base/control/h2qa/'):
            value.st_ino += 1
        return value
    def open(self, path, flags, mode=0o600, dir_fd=None):
        name = self._path(path, dir_fd)
        assert flags & real_os.O_NOFOLLOW
        if flags & real_os.O_CREAT:
            assert flags & real_os.O_EXCL
            if name in self.nodes:
                raise FileExistsError(name)
            self.add(name, mode=mode)
        if name not in self.nodes:
            raise FileNotFoundError(name)
        self.next_fd += 1
        self.handles[self.next_fd] = {'node': self.nodes[name], 'position': 0}
        self.opened.append((self.next_fd, name))
        return self.next_fd
    def fstat(self, fd):
        node = self.handles[fd]['node']
        if self.fail_h2_stat and node['path'] == '/base/control/h2qa':
            self.fail_h2_stat = False
            raise OSError('fake h2 fstat failure after registration')
        return self._st(node)
    def close(self, fd):
        self.closes.append(fd)
        handle = self.handles[fd]
        if handle['node']['path'] in self.close_fail_paths:
            raise OSError('fake once-close uncertain failure')
        del self.handles[fd]
    def mkdir(self, path, mode, dir_fd):
        name = self._path(path, dir_fd)
        if name in self.nodes:
            raise FileExistsError(name)
        self.add(name, directory=True, mode=mode)
    def fsync(self, fd):
        assert fd in self.handles
    def read(self, fd, count):
        h = self.handles[fd]
        raw = bytes(h['node']['data'][h['position']:h['position'] + count])
        h['position'] += len(raw)
        self.read_events.append((h['node']['path'], len(raw)))
        if h['node']['path'].startswith('/incoming/h2/') and raw and self.source_after_read:
            self.source_after_read(h['node'])
        if self.corrupt_target_read and raw and h['node']['path'].startswith('/base/control/h2qa/'):
            raw = bytes([raw[0] ^ 1]) + raw[1:]
        return raw
    def write(self, fd, raw):
        h = self.handles[fd]
        part = bytes(raw[:17])
        h['node']['data'].extend(part)
        h['node']['mtime'] += 1
        h['node']['ctime'] += 1
        h['position'] += len(part)
        return len(part)
    def fchmod(self, fd, mode):
        self.handles[fd]['node']['mode'] = mode
    def lseek(self, fd, offset, whence):
        assert whence == real_os.SEEK_SET and offset == 0
        self.handles[fd]['position'] = 0
    def listdir(self, fd):
        parent = PurePosixPath(self.handles[fd]['node']['path'])
        return [PurePosixPath(p).name for p in self.nodes if PurePosixPath(p).parent == parent]

def setup(create=True):
    clock = Clock()
    fs = FakeFS(clock)
    for path in ('/', '/base', '/incoming', '/incoming/h2', '/incoming/product'):
        fs.add(path, directory=True)
    raw = b'public synthetic instrument bytes\n' * 5
    digest = hashlib.sha256(raw).hexdigest()
    fs.add('/incoming/h2/test.rs', mode=0o400, raw=raw)
    fs.add('/incoming/product/product', mode=0o500, raw=raw)
    ns = {'os': fs.OS, 'stat': stat, 'hashlib': hashlib, 'time': clock, 'UNTIL': 300_000_000_000,
          'BASE': FakePath(fs, '/base'), 'CONTROL': FakePath(fs, '/base/control'),
          'INCOMING': FakePath(fs, '/incoming/product'), 'H2_INCOMING': FakePath(fs, '/incoming/h2'),
          'QA_NAMES': ('qa.py',), 'H2_COPY': {'rust_source': ('test.rs', len(raw), digest, 0o400, 0o600)},
          'COPY': (('product', len(raw), digest, 0o500, 0o500),)}
    exec(selected_code, ns)
    owned = ns['NewDirectories']()
    if create:
        owned.create()
    return ns, fs, clock, owned

def expect_error(fn, wanted):
    try:
        fn()
    except BaseException as error:
        check('selected refusal ' + wanted, str(error) == wanted)
    else:
        raise AssertionError('missing ' + wanted)

fake_cases = []

ns, fs, clock, owned = setup()
copied = owned.copy(*ns['H2_COPY']['rust_source'], h2=True)
check('H2 copy exact fixed source and target', copied['source']['path'] == '/incoming/h2/test.rs' and copied['target']['path'] == '/base/control/h2qa/test.rs')
check('H2 copy source and same-FD target EOF both observed', ('/incoming/h2/test.rs', 0) in fs.read_events and ('/base/control/h2qa/test.rs', 0) in fs.read_events)
check('H2 file fds closed before directory closure', all(fd not in fs.handles for fd, path in fs.opened if path.endswith('test.rs')))
check('H2 directory enters original five-FD ledger', owned.h2fd in owned.fds and len(owned.fds) == 5)
saved_fds = list(owned.fds)
check('all fake directory closes succeed', owned.close() == [])
check('reverse once-close on five owned directories', fs.closes[-5:] == list(reversed(saved_fds)) and not fs.handles and len(fs.closes) == len(set(fs.closes)))
fake_cases.append('H2 successful copy and exact reverse directory closure')

for label, invoke, error in [
    ('instrument cannot use product route', lambda o, n: o.copy(*n['H2_COPY']['rust_source']), 'fixed_copy_member'),
    ('product cannot use instrument route', lambda o, n: o.copy(*n['COPY'][0], h2=True), 'fixed_copy_member'),
    ('non-boolean route rejected', lambda o, n: o.copy(*n['H2_COPY']['rust_source'], h2=1), 'fixed_copy_route'),
    ('instrument wrong content tuple rejected', lambda o, n: o.copy('test.rs', 1, '0' * 64, 0o400, 0o600, h2=True), 'fixed_copy_member'),
    ('h2qa is never raw-write destination', lambda o, n: o.write(o.h2fd, 'test.rs', b'x'), 'owned_destination_fd'),
    ('QA name cannot be written into artifact directory', lambda o, n: o.write(o.artfd, 'qa.py', b'x'), 'closed_destination_filename'),
    ('binding cannot be written into QA directory', lambda o, n: o.write(o.qafd, 'binding.private.json', b'x'), 'closed_destination_filename'),
]:
    ns, fs, clock, owned = setup()
    before_opened = len(fs.opened)
    expect_error(lambda: invoke(owned, ns), error)
    check(label + ': refusal before opening file', len(fs.opened) == before_opened)
    check(label + ': directory close', owned.close() == [] and not fs.handles)
    fake_cases.append(label)

for label, mutation, error in [
    ('instrument hardlink rejected', lambda fs, clock: fs.nodes['/incoming/h2/test.rs'].update(links=2), 'regular_single_link_source'),
    ('instrument source changed while read', lambda fs, clock: setattr(fs, 'source_after_read', lambda node: node.update(ctime=node['ctime'] + 1)), 'source_changed_during_read'),
    ('instrument target readback corruption', lambda fs, clock: setattr(fs, 'corrupt_target_read', True), 'copy_target_sha'),
    ('instrument target named identity changed', lambda fs, clock: setattr(fs, 'bad_target_name', True), 'copy_target_name_identity'),
    ('original absolute deadline expires during copy', lambda fs, clock: setattr(fs, 'source_after_read', lambda node: setattr(clock, 'now', 300_000_000_000)), 'local_stage_original_300_seconds'),
]:
    ns, fs, clock, owned = setup()
    mutation(fs, clock)
    expect_error(lambda: owned.copy(*ns['H2_COPY']['rust_source'], h2=True), error)
    owned.close()
    check(label + ': every opened fake FD once closed', not fs.handles and sorted(fs.closes) == sorted(fd for fd, _ in fs.opened) and len(fs.closes) == len(set(fs.closes)))
    if label != 'instrument hardlink rejected':
        check(label + ': failure target retained, no deletion', '/base/control/h2qa/test.rs' in fs.nodes)
    fake_cases.append(label)

ns, fs, clock, owned = setup(create=False)
fs.fail_h2_stat = True
try:
    owned.create()
except OSError:
    pass
else:
    raise AssertionError('missing h2 fstat failure')
check('h2 FD recorded before failing fstat', len(owned.fds) == 5)
owned.close()
check('h2 create failure all five fake FDs close once', not fs.handles and len(fs.closes) == 5 and len(set(fs.closes)) == 5)
fake_cases.append('h2 directory fstat failure after ledger append')

ns, fs, clock, owned = setup()
fs.close_fail_paths.add('/base/control/h2qa/test.rs')
try:
    owned.copy(*ns['H2_COPY']['rust_source'], h2=True)
except OSError:
    pass
else:
    raise AssertionError('missing target close failure')
sourcefd = next(fd for fd, path in fs.opened if path == '/incoming/h2/test.rs')
targetfd = next(fd for fd, path in fs.opened if path == '/base/control/h2qa/test.rs')
check('uncertain target close still closes source exactly once', fs.closes.count(targetfd) == 1 and fs.closes.count(sourcefd) == 1 and sourcefd not in fs.handles)
owned.close()
check('uncertain target FD is not retried or claimed closed', targetfd in fs.handles and fs.closes.count(targetfd) == 1)
fake_cases.append('target close failure remains uncertain; source/owned dirs close once')

# Exercise only the preserved main finally statements against the new h2qa
# close failure. This is not an execution of main or of publication.
main_node = next(n for n in new_ast.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
main_try = next(n for n in main_node.body if isinstance(n, ast.Try))
final_code = compile(ast.fix_missing_locations(ast.Module(body=copy.deepcopy(main_try.finalbody), type_ignores=[])), '<original-finally-fake-only>', 'exec')
ns, fs, clock, owned = setup()
fs.close_fail_paths.add('/base/control/h2qa')
ns.update(owned=owned, result={'status': 'passed'}, started=0)
exec(final_code, ns)
check('h2 directory close failure cannot stay green', ns['result']['status'] == 'failed' and ns['result']['all_stage_fds_closed'] is False and ns['result']['fd_close_errors'] == ['OSError'])
check('failed h2 directory close attempted once with all other dirs attempted', len(fs.closes) == 5 and len(set(fs.closes)) == 5)
fake_cases.append('preserved finally rejects h2 directory once-close error')

membership_nodes = [copy.deepcopy(n) for n in ast.walk(main_try) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == 'need' and len(n.value.args) > 1 and isinstance(n.value.args[1], ast.Constant) and n.value.args[1].value in ('exact_created_h2_members', 'exact_created_control_members')]
check('two fixed membership statements selected', len(membership_nodes) == 2)
membership_code = compile(ast.fix_missing_locations(ast.Module(body=membership_nodes, type_ignores=[])), '<selected-membership-fake-only>', 'exec')
ns, fs, clock, owned = setup()
owned.copy(*ns['H2_COPY']['rust_source'], h2=True)
fs.add('/base/control/binding.private.json', mode=0o600, raw=b'{}')
ns['owned'] = owned
exec(membership_code, ns)
fs.add('/base/control/h2qa/unlisted', mode=0o600)
expect_error(lambda: exec(membership_code, ns), 'exact_created_h2_members')
del fs.nodes['/base/control/h2qa/unlisted']
fs.add('/base/control/unlisted', mode=0o600)
expect_error(lambda: exec(membership_code, ns), 'exact_created_control_members')
owned.close()
check('membership negatives leave no fake FD pending', not fs.handles)
fake_cases.append('exact H2 and root membership reject extra entries')

result = {'schema': 'heptabao.h2-stage.offline-source-selected-checks.v1', 'status': 'PASS_SOURCE_AND_SELECTED_FAKE_ONLY',
          'checks_count': len(checks), 'checks': checks, 'selected_fake_cases_count': len(fake_cases), 'selected_fake_cases': fake_cases,
          'unchanged_definition_count': len(old_defs) - len(changed), 'changed_existing_definitions': changed,
          'Runtime_calls': 0, 'actual_native_FDs': 0, 'actual_child_processes_from_candidate': 0,
          'main_executed': False, 'QA_modules_executed': False,
          'scope': 'Selected AST definition execution uses only in-memory fake OS/paths/clock. The one deliberately failed fake close remains uncertain; it is not retried or reported closed. These checks confer no host or H2 product qualification.'}
(OUT / 'selected-checks.actual.public.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, sort_keys=True))
