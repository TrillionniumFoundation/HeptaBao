"""Prepare exact5f9d4 from the retained clean4b source and one fixed public bundle.

No Rust compilation, service, cache mutation, source patch application or
network download. All Git children use the existing pinned original-custody
implementation. The old source and its 322 closed public inputs stay unchanged.
"""
from pathlib import Path
import hashlib, json, os, platform, stat, subprocess, sys, time, types

ROOT = Path('/home/alex/heptabao-kv2-ha-convergence-5f9d4-authbus-20261107-r2')
OUT = ROOT / 'build-test-r1'
SOURCE = ROOT / 'source-5f9d4'
BASE_ROOT = Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
BASE = BASE_ROOT / 'source-4bde9'
BASE_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BASE_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
OTHER_PREREQUISITE = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
COMMIT = '5f9d4263b136685244aba93e45a69139cb8aba41'
TREE = '2c69f04159c112a883abe57f0d367a2627197c7a'
PARENT = '7d9e933d5ccab83d51c4de9ae7f028fe70e92302'
BUNDLE_PIN = (9985724, 'e57a93e8f3c13f83259cc6f1a5ca1ddb2ebe8451a0da5ff677c38c83ee8d3d72')
SELECTION_PIN = (142663, '869feff2d8672fe37a26a2fb671cdc853b3c9d7f889edfe76650eed8103f44e9')
HELPERS = {
    'owned_process': (28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
    'kv2_dr_process_custody': (26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
}
PRODUCT_PINS = {
    'crates/heptabao-server/src/state_records.rs': (18031, 'b419525a98f096c85681869b6037fb8356837fc5b8664ad3c09d9e2adc609e45'),
    'crates/heptabao-server/src/state_records/tests.rs': (33657, '2ce1ed3614bedf4531428df21dcdb3ccf938616a34f25cbdf867ef7b79a3c526'),
    'crates/heptabao-server/src/engines/kv2_native_paged.rs': (53305, '39dc30eb361590691ce4102446597037b485f600d9baf18cf6564653c024bc10'),
    'crates/heptabao-server/src/engines/kv2_native_payload_validation_tests.rs': (14344, '9db53e2932ce7db1e0750966383e78b65a37d7c1079c158615ef6ecbdd7e246d'),
}
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
       'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '2',
       'GIT_CONFIG_KEY_0': 'core.hooksPath', 'GIT_CONFIG_VALUE_0': '/dev/null',
       'GIT_CONFIG_KEY_1': 'core.fsmonitor', 'GIT_CONFIG_VALUE_1': 'false'}
START = time.monotonic()
END = START + 480
FDS = []
PUBLIC = {}
OWNER = None
REPORT = {'schema': 'heptabao.pocket4-product5f9d4-source-preparation.v1', 'status': 'failed',
          'source_commit': COMMIT, 'source_tree': TREE, 'source_parent': PARENT,
          'source': str(SOURCE), 'steps': [], 'outerBudgetSeconds': 480,
          'automatic_retry': False, 'rust_build_executed': False, 'rust_tests_executed': False,
          'product_binary_executions': 0, 'production_changed': False,
          'original_source_preserved': False, 'original_input_count': 322,
          'all_original_inputs_unchanged': False, 'normal107_qualified': False,
          'remoteClosureUnknown': False}

class Refused(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refused(code)

def live():
    need(time.monotonic() < END - 10, 'original_preparation_deadline')

def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def file_pin(path, expected=None, *, contents=False, maximum=128 * 1024 * 1024):
    live()
    path = Path(path)
    before = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode)
         and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
         and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
         'bounded_owned_regular_public_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    row = {'fd': fd, 'attempts': 0, 'closed': False}; FDS.append(row)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'same_open_public_input')
        digest, size, raw = hashlib.sha256(), 0, bytearray()
        while True:
            live()
            part = os.read(fd, min(1048576, before.st_size + 1 - size))
            if not part:
                break
            size += len(part)
            need(size <= before.st_size, 'input_size_growth')
            digest.update(part)
            if contents:
                raw.extend(part)
        pin = (size, digest.hexdigest())
        need(size == before.st_size and identity(os.fstat(fd)) == identity(path.lstat()) == identity(before),
             'complete_public_input_unchanged')
        need(expected is None or pin == expected, 'exact_public_input_pin')
        PUBLIC.setdefault(path, (pin, identity(before)))
        return pin, bytes(raw)
    finally:
        row['attempts'] = 1
        os.close(fd); row['closed'] = True

def directory(path, private=False):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and not info.st_mode & 0o022
         and (not private or stat.S_IMODE(info.st_mode) == 0o700), 'owned_canonical_directory')
    return identity(info)[:5]

def new_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    need(path.parent == OUT and path.name == 'preparation.result.public.json'
         and len(raw) <= 1048576, 'exact_bounded_new_receipt')
    held = []
    def opened(name, flags, parent=None):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, **({} if parent is None else {'dir_fd': parent}))
        row = {'fd': fd, 'attempts': 0, 'closed': False}
        FDS.append(row); held.append(row)
        return fd
    try:
        parent = opened(OUT, os.O_RDONLY | os.O_DIRECTORY)
        parent_identity = identity(os.fstat(parent))[:5]
        need(parent_identity == identity(OUT.lstat())[:5]
             and os.fstat(parent).st_uid == os.getuid()
             and stat.S_IMODE(os.fstat(parent).st_mode) == 0o700,
             'exact_private_receipt_parent')
        fd = opened(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent)
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_uid == os.getuid()
             and first.st_gid == os.getgid() and first.st_nlink == 1
             and stat.S_IMODE(first.st_mode) == 0o600 and first.st_size == 0,
             'new_empty_private_receipt')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:]); need(count > 0, 'receipt_write_progress'); offset += count
        os.fsync(fd)
        final_identity = identity(os.fstat(fd))
        need(final_identity[:6] == identity(first)[:6]
             and final_identity[6] == len(raw)
             and final_identity == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
             'complete_named_receipt_identity')
        readback = opened(path.name, os.O_RDONLY, parent)
        need(identity(os.fstat(readback)) == final_identity, 'same_receipt_readback_descriptor')
        actual = bytearray()
        while True:
            need(time.monotonic() < END, 'receipt_readback_deadline')
            block = os.read(readback, min(1048576, len(raw) + 1 - len(actual)))
            if not block:
                break
            actual.extend(block)
            need(len(actual) <= len(raw), 'receipt_readback_bound')
        need(bytes(actual) == raw and identity(os.fstat(readback)) == identity(os.fstat(fd))
             == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == final_identity,
             'complete_receipt_bytes_and_full9_readback')
        os.fsync(parent)
        need(identity(os.fstat(parent))[:5] == identity(OUT.lstat())[:5] == parent_identity
             and identity(path.lstat()) == final_identity, 'durable_receipt_named_parent_unchanged')
    finally:
        first_error = None
        for row in reversed(held):
            row['attempts'] = 1
            try:
                os.close(row['fd']); row['closed'] = True
            except BaseException as error:
                first_error = first_error or error
        if first_error is not None:
            raise first_error

def run(label, args, cap):
    live()
    budget = min(cap, END - 10 - time.monotonic())
    need(budget > 0, 'original_command_budget')
    began = time.monotonic()
    so, se = OUT / (label + '.stdout'), OUT / (label + '.stderr')
    with so.open('xb') as out, se.open('xb') as err:
        proc = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                              cwd=OUT, env=ENV, timeout=budget, start_new_session=True)
        out.flush(); err.flush(); os.fsync(out.fileno()); os.fsync(err.fileno())
    OWNER.assert_retired()
    stdout, raw = file_pin(so, contents=True, maximum=1048576)
    stderr, _ = file_pin(se, maximum=1048576)
    REPORT['steps'].append({'label': label, 'argv': args, 'originalCapSeconds': cap,
                           'effectiveBudgetSeconds': budget, 'exitCode': proc.returncode,
                           'elapsedSeconds': time.monotonic() - began,
                           'stdoutBytes': stdout[0], 'stdoutSha256': stdout[1],
                           'stderrBytes': stderr[0], 'stderrSha256': stderr[1]})
    need(proc.returncode == 0, label + '_failed')
    return raw.decode('utf-8', 'strict').strip()

def git(label, source, *args, cap=15):
    return run(label, ['/usr/bin/git', '-C', str(source), *args], cap)

def old_source_state(prefix):
    head = git(prefix + '-head', BASE, 'rev-parse', 'HEAD')
    tree = git(prefix + '-tree', BASE, 'rev-parse', 'HEAD^{tree}')
    dirty = git(prefix + '-clean', BASE, 'status', '--porcelain', '--untracked-files=all')
    need(head == BASE_COMMIT and tree == BASE_TREE and not dirty, 'clean_original_base_source')
    return {'head': head, 'tree': tree, 'clean': True}

try:
    os.umask(0o077)
    need(platform.node() == 'alex-G1628-04' and platform.system() == 'Linux'
         and platform.machine() == 'x86_64' and os.getuid() == 1000, 'exact_pocket4_account')
    directories = {p: directory(p, private=True) for p in (ROOT, OUT, BASE_ROOT, BASE)}
    need(not os.path.lexists(SOURCE), 'source_must_be_new')
    need(all(not os.path.lexists(OUT / name) for name in
             ('preparation.result.public.json', 'result.public.json', 'progress.public.json', 'artifacts')),
         'preparation_and_formal_outputs_must_be_new')
    bundle = OUT / 'candidate.bundle'
    bundle_pin, _ = file_pin(bundle, BUNDLE_PIN)
    _, selection_bytes = file_pin(BASE_ROOT / 'build-test-r1/test-selection.public.json', SELECTION_PIN,
                                  contents=True, maximum=524288)
    selection = json.loads(selection_bytes)
    inputs = selection['old_retained_artifacts']
    need(type(inputs) is dict and len(inputs) == 322, 'original_closed_input_set')
    for value in inputs.values():
        file_pin(Path(value['path']), (value['bytes'], value['sha256']))
    file_pin(Path('/usr/bin/git'), maximum=32 * 1024 * 1024)
    modules = {}
    for name, pin in HELPERS.items():
        path = BASE / 'qa/openbao-acceptance' / (name + '.py')
        _, raw = file_pin(path, pin, contents=True, maximum=65536)
        need(name not in sys.modules, 'custody_helper_not_preloaded')
        module = types.ModuleType(name); module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules[name] = module
    with modules['kv2_dr_process_custody'].activated() as owner:
        OWNER = owner
        before = old_source_state('base-before')
        for n, commit in enumerate((BASE_COMMIT, OTHER_PREREQUISITE)):
            git('prerequisite-' + str(n), BASE, 'cat-file', '-e', commit + '^{commit}')
        git('prerequisite-ancestor', BASE, 'merge-base', '--is-ancestor', OTHER_PREREQUISITE, BASE_COMMIT)
        run('prepare-clone', ['/usr/bin/git', 'clone', '--no-hardlinks', '--no-local', '--no-checkout', str(BASE), str(SOURCE)], 180)
        git('prepare-bundle-verify', SOURCE, 'bundle', 'verify', str(bundle), cap=30)
        heads = git('prepare-bundle-heads', SOURCE, 'bundle', 'list-heads', str(bundle), cap=30)
        need(heads == COMMIT + ' HEAD', 'unique_exact_advertised_bundle_head')
        git('prepare-fetch', SOURCE, 'fetch', str(bundle), 'HEAD', cap=30)
        need(git('fetched-head', SOURCE, 'rev-parse', 'FETCH_HEAD') == COMMIT, 'exact_fetched_commit')
        git('prepare-checkout', SOURCE, 'checkout', '--detach', COMMIT, cap=30)
        git('prepare-fsck', SOURCE, 'fsck', '--full', '--strict', cap=60)
        need(git('candidate-head', SOURCE, 'rev-parse', 'HEAD') == COMMIT
             and git('candidate-tree', SOURCE, 'rev-parse', 'HEAD^{tree}') == TREE
             and git('candidate-parent', SOURCE, 'rev-parse', 'HEAD^') == PARENT,
             'exact_candidate_identity')
        need(not git('candidate-clean', SOURCE, 'status', '--porcelain', '--untracked-files=all'), 'clean_candidate_source')
        changed = git('candidate-product-diff', SOURCE, 'diff', '--name-only', BASE_COMMIT, COMMIT,
                      '--', '.', ':(exclude)qa', ':(exclude)docs').splitlines()
        need(sorted(changed) == sorted(PRODUCT_PINS), 'exact_four_product_paths')
        for name, pin in PRODUCT_PINS.items():
            file_pin(SOURCE / name, pin)
        for name, old_key in (('Cargo.lock', 'pocket4_source_Cargo_lock'),
                              ('Cargo.toml', 'pocket4_source_workspace_manifest')):
            old = inputs[old_key]
            file_pin(SOURCE / name, (old['bytes'], old['sha256']))
        objects = list((SOURCE / '.git/objects').rglob('*'))
        need(objects and not (SOURCE / '.git/objects/info/alternates').exists()
             and all(not p.is_symlink() and (p.is_dir() or p.is_file() and p.stat().st_nlink == 1)
                     for p in objects), 'unshared_new_git_objects')
        after = old_source_state('base-after')
        need(before == after, 'original_base_source_changed')
    REPORT['processCustody'] = OWNER.assert_retired()
    for path, (expected, original) in list(PUBLIC.items()):
        file_pin(path, expected)
        need(identity(path.lstat()) == original, 'public_input_final_generation_changed')
    need(all(directory(path, private=True) == expected for path, expected in directories.items()),
         'original_directory_identity_changed')
    live()
    REPORT.update(status='passed', source_clean=True, source_at_exact_published_commit=True,
                  source_parent=PARENT, no_hardlinks=True, original_source_preserved=True,
                  all_original_inputs_unchanged=True, bundle={'bytes': bundle_pin[0], 'sha256': bundle_pin[1]},
                  actual_bundle_prerequisites=[BASE_COMMIT, OTHER_PREREQUISITE],
                  prerequisite_09c_is_ancestor_of_4b=True, normal_build_flags_unchanged=True,
                  changed_product_paths=sorted(PRODUCT_PINS))
except BaseException as error:
    REPORT['failure'] = str(error) if isinstance(error, Refused) else type(error).__name__
finally:
    if OWNER is not None:
        REPORT['processCustody'] = OWNER.receipt()
        REPORT['remoteClosureUnknown'] = not (OWNER.finished and all(
            row.get('original_wait_completed') is True and row.get('no_live_members_before_reap') is True
            for row in OWNER.rows))
        if not REPORT['processCustody']['passed_process_custody']:
            REPORT['status'] = 'failed'
    for row in reversed(FDS):
        if row['attempts'] == 0:
            row['attempts'] = 1
            try:
                os.close(row['fd']); row['closed'] = True
            except BaseException:
                REPORT['status'] = 'failed'
    REPORT['allInputDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
    if not REPORT['allInputDescriptorsClosedOnce'] or REPORT['remoteClosureUnknown'] or time.monotonic() >= END:
        REPORT['status'] = 'failed'
    REPORT['elapsedSeconds'] = time.monotonic() - START
    try:
        new_json(OUT / 'preparation.result.public.json', REPORT)
    except BaseException as error:
        REPORT['status'] = 'failed'; REPORT['resultPublishError'] = type(error).__name__
    REPORT['allDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
    REPORT['descriptorCount'] = len(FDS)
    if not REPORT['allDescriptorsClosedOnce'] or time.monotonic() >= END:
        REPORT['status'] = 'failed'
    print(json.dumps(REPORT, sort_keys=True), flush=True)
raise SystemExit(0 if REPORT['status'] == 'passed' else 1)
