#!/usr/bin/env python3
"""One create-only public dependency relay through existing Mac SSH aliases."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import signal
import stat
import subprocess
import sys
import time

PARENT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OUT = PARENT / 'public-linux-closure-transfer-20261106-r1'
POCKET_ROOT = '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1'
INBOX = POCKET_ROOT + '/linux-public-closure-inbox-r1'
AI_ROOT = '/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1'
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
SSH = '/usr/bin/ssh'
TOOL_PINS = {
    PYTHON: (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    SSH: (1584576, '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3'),
}
FILES = [
    ('manifest.public.json', AI_ROOT + '/pocket4-dependency-export-r3/manifest.public.json',
     207549, '0d74878d414151a41fa85927ff0732ea2ab123dcdf0955aa8cd75c5be2216897'),
    ('linux-locked-dependencies.tar', AI_ROOT + '/pocket4-dependency-export-r3/linux-locked-dependencies.tar',
     67880960, '8e771190e6df05560f8a41bbf7992586137ee4ab730123301c6dba0d595759c9'),
    ('offline-resolver-proof.public.json', AI_ROOT + '/pocket4-dependency-export-r3/offline-resolver-proof.public.json',
     5361, 'da7f698027b1d97488aefda02556c807ae4b0a9d4baa435552b96efa626b8e28'),
    ('prior-missing-index-proof.public.json', AI_ROOT + '/pocket4-dependency-export-r2/offline-resolver-proof.public.json',
     45743, '8df38dbaa49ce8ae54fbbcdb662eea188327179d23be17223dccb93b38140e90'),
]
RECEIVER_SHA = '0a78136b730a7c643362db64295ff3eb9ec6ab9f0b5234d6ea8139ab7bf015c6'

RECEIVER = "#!/usr/bin/env python3\n\"\"\"Install one pinned public Cargo dependency packet in a new owned directory.\"\"\"\nfrom pathlib import Path, PurePosixPath\nimport hashlib\nimport io\nimport json\nimport os\nimport re\nimport stat\nimport subprocess\nimport tarfile\nimport time\nimport tomllib\nfrom urllib.parse import urlsplit\n\nCOMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'\nTREE = 'f08493a23f8ea0637073651231865ea9607b790e'\nLOCK = 'd2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5'\nMANIFEST_SHA = '0d74878d414151a41fa85927ff0732ea2ab123dcdf0955aa8cd75c5be2216897'\nPAYLOAD_SHA = '8e771190e6df05560f8a41bbf7992586137ee4ab730123301c6dba0d595759c9'\nROOT = Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')\nINBOX = ROOT / 'linux-public-closure-inbox-r1'\nCARGO_HOME = ROOT / 'cargo-home-public-linux-r1'\nSOURCE = ROOT / 'source-4bde9'\nMAXIMUM = 128 * 1024 * 1024\nPROOFS = {\n    'offline-resolver-proof.public.json': (5361, 'da7f698027b1d97488aefda02556c807ae4b0a9d4baa435552b96efa626b8e28'),\n    'prior-missing-index-proof.public.json': (45743, '8df38dbaa49ce8ae54fbbcdb662eea188327179d23be17223dccb93b38140e90'),\n}\nTREE_HASHES = {\n    'server': '3d112e6e8671700cd9c87b10e7c3f917b95633d469189c63cadf747ed736e707',\n    'peer': '40e70fe078077d01cb304131a61c2fa54c1dbbd9a871fe56151a321cc94c420f',\n}\n\n\ndef need(ok, label):\n    if not ok:\n        raise RuntimeError(label)\n\n\ndef sha(data):\n    return hashlib.sha256(data).hexdigest()\n\n\ndef identity(s):\n    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,\n            s.st_size, s.st_mtime_ns, s.st_ctime_ns)\n\n\ndef read_regular(path, expected=None, maximum=MAXIMUM):\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    try:\n        before = os.fstat(fd)\n        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1\n             and 0 <= before.st_size <= maximum, 'bounded_single_link_regular_file')\n        data = bytearray()\n        while True:\n            part = os.read(fd, 1024 * 1024)\n            if not part:\n                break\n            data.extend(part)\n            need(len(data) <= maximum, 'input_exceeded_bound')\n        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd))\n             == identity(path.lstat()), 'input_identity_changed')\n        data = bytes(data)\n        need(expected is None or sha(data) == expected, 'input_sha256_mismatch')\n        return data\n    finally:\n        os.close(fd)\n\n\ndef index_relative(name):\n    if len(name) == 1:\n        return '1/' + name\n    if len(name) == 2:\n        return '2/' + name\n    if len(name) == 3:\n        return '3/' + name[0] + '/' + name\n    return name[:2] + '/' + name[2:4] + '/' + name\n\n\ndef validate_packet(manifest_raw, payload, lock_raw, manifest_sha, payload_sha):\n    need(sha(manifest_raw) == manifest_sha and sha(payload) == payload_sha, 'packet_sha256')\n    m = json.loads(manifest_raw)\n    need(m['schema'] == 'heptabao.closed-linux-registry-transfer.v1'\n         and m['source_commit'] == COMMIT and m['source_tree'] == TREE\n         and m['cargo_lock_sha256'] == sha(lock_raw), 'canonical_source_and_lock_binding')\n    need(m['user_cargo_config_or_credentials_included'] is False\n         and m['source_cache_modified'] is False and m['rust_compilation_executed'] is False\n         and m['normal107_qualified'] is False and m['production_changed'] is False\n         and m['cargo_network_downloads_executed'] is False, 'public_metadata_only_scope')\n    need(m['payload']['bytes'] == len(payload) and m['payload']['sha256'] == payload_sha\n         and len(payload) <= MAXIMUM, 'payload_length_pin')\n    packages = {}\n    for p in tomllib.loads(lock_raw.decode())['package']:\n        if p.get('source'):\n            need(p['source'] == 'registry+https://github.com/rust-lang/crates.io-index',\n                 'public_crates_io_lock_only')\n            key = (p['name'], p['version'])\n            need(key not in packages, 'duplicate_registry_lock_package')\n            packages[key] = p['checksum']\n    entries = m['entries']\n    names = [e['member'] for e in entries]\n    need(names == sorted(set(names)) and len(names) <= 1024, 'closed_unique_sorted_members')\n    counts = {'linux_selected_crate': 0, 'offline_resolver_required_crate': 0,\n              'selected_package_sparse_index': 0, 'offline_resolver_required_sparse_index': 0,\n              'public_registry_config': 0}\n    output = []\n    index_records = {}\n    archive_versions = {}\n    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as tar:\n        members = tar.getmembers()\n        need([x.name for x in members] == names, 'tar_missing_extra_duplicate_or_reordered')\n        for info, entry in zip(members, entries):\n            member = PurePosixPath(info.name)\n            need(not member.is_absolute() and all(x not in ('', '.', '..') for x in member.parts)\n                 and str(member) == info.name, 'relative_canonical_member_only')\n            need(info.type == tarfile.REGTYPE and info.size == entry['bytes']\n                 and 0 <= info.size <= 32 * 1024 * 1024 and not info.linkname\n                 and not info.pax_headers and info.mode == 0o600 and info.uid == info.gid == 0\n                 and info.mtime == 0 and not info.uname and not info.gname, 'fixed_regular_tar_metadata')\n            data = tar.extractfile(info).read()\n            need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'member_size_or_sha256')\n            kind = entry['kind']\n            need(kind in counts, 'unsupported_member_kind')\n            counts[kind] += 1\n            if kind in ('linux_selected_crate', 'offline_resolver_required_crate'):\n                name, version = entry['crate'], entry['version']\n                need(re.fullmatch(r'[A-Za-z0-9_-]+', name)\n                     and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', version)\n                     and info.name == 'crates/' + name + '-' + version + '.crate'\n                     and packages.get((name, version)) == sha(data), 'crate_not_exact_canonical_lock')\n                archive_versions.setdefault(name, set()).add(version)\n                output.append(('cache', name + '-' + version + '.crate', data))\n            elif kind in ('selected_package_sparse_index', 'offline_resolver_required_sparse_index'):\n                name = entry['crate']\n                need(re.fullmatch(r'[A-Za-z0-9_-]+', name)\n                     and info.name == 'indexes/' + index_relative(name)\n                     and name not in index_records, 'canonical_unique_sparse_index_path')\n                records = {}\n                for part in data.split(b'\\0'):\n                    if part.startswith(b'{'):\n                        item = json.loads(part)\n                        need(item.get('name') == name and item.get('vers') not in records,\n                             'sparse_index_name_or_duplicate_version')\n                        records[item['vers']] = item\n                versions = entry['locked_versions']\n                need(versions == sorted(set(versions)) and versions\n                     and all((name, v) in packages and records.get(v, {}).get('cksum') == packages[(name, v)]\n                             for v in versions), 'sparse_index_locked_versions_and_checksums')\n                index_records[name] = records\n                output.append(('index', '.cache/' + index_relative(name), data))\n            else:\n                need(info.name == 'registry-config.json', 'public_registry_metadata_filename')\n                config = json.loads(data)\n                need(set(config) == {'dl', 'api'} and all(isinstance(x, str) for x in config.values()),\n                     'anonymous_registry_metadata_only')\n                for value in config.values():\n                    url = urlsplit(value)\n                    need(url.scheme == 'https' and url.hostname in ('crates.io', 'static.crates.io')\n                         and not url.username and not url.password and not url.query and not url.fragment,\n                         'anonymous_public_registry_url')\n                output.append(('index', 'config.json', data))\n    need(counts['public_registry_config'] == 1\n         and counts['linux_selected_crate'] == m['linux_selected_registry_package_count']\n         and counts['offline_resolver_required_crate'] == m['metadata_resolver_additional_archive_count']\n         and counts['selected_package_sparse_index'] + counts['offline_resolver_required_sparse_index']\n         == m['sparse_index_count']\n         and counts['offline_resolver_required_sparse_index']\n         == m['metadata_resolver_additional_index_count'], 'declared_closed_counts')\n    need(all(name in index_records and all(index_records[name].get(v, {}).get('cksum') == packages[(name, v)]\n                                          for v in versions)\n             for name, versions in archive_versions.items()), 'every_archive_has_exact_public_index')\n    return output, counts\n\n\ndef owned_directory(path):\n    st = path.lstat()\n    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022\n         and path.resolve() == path, 'owned_real_parent_directory')\n\n\ndef write_new_cache(path, namespace, entries):\n    owned_directory(path.parent)\n    need(re.fullmatch(r'index\\.crates\\.io-[0-9a-f]{16}', namespace), 'observed_public_registry_namespace')\n    path.mkdir(mode=0o700)\n    for kind, relative, data in entries:\n        dest = path / 'registry' / kind / namespace / relative\n        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)\n        with dest.open('xb') as f:\n            f.write(data)\n            f.flush()\n            os.fsync(f.fileno())\n        need(read_regular(dest) == data, 'installed_file_readback')\n    actual = {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}\n    expected = {'registry/' + kind + '/' + namespace + '/' + rel for kind, rel, _ in entries}\n    need(actual == expected and not any(p.is_symlink() for p in path.rglob('*')), 'installed_closed_file_set')\n\n\ndef source_identity():\n    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0',\n           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}\n    def git(*args):\n        return subprocess.check_output(\n            ['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',\n             '-C', str(SOURCE), *args], env=env, stderr=subprocess.DEVNULL, timeout=15).decode().strip()\n    need(git('rev-parse', 'HEAD') == COMMIT and git('rev-parse', 'HEAD^{tree}') == TREE\n         and not git('status', '--porcelain', '--untracked-files=all'), 'clean_canonical_receiver_source')\n\n\ndef main():\n    os.umask(0o077)\n    result = {'schema': 'heptabao.pocket4-public-dependency-receipt.v1', 'status': 'running',\n              'rust_compilation_executed': False, 'product_binary_executions': 0,\n              'normal107_qualified': False, 'production_changed': False,\n              'existing_user_cache_modified': False, 'user_configuration_or_credentials_opened': False}\n    try:\n        owned_directory(ROOT)\n        owned_directory(INBOX)\n        source_identity()\n        lock_raw = read_regular(SOURCE / 'Cargo.lock', LOCK)\n        manifest_raw = read_regular(INBOX / 'manifest.public.json', MANIFEST_SHA, 1048576)\n        payload = read_regular(INBOX / 'linux-locked-dependencies.tar', PAYLOAD_SHA)\n        need(len(manifest_raw) == 207549 and len(payload) == 67880960, 'fixed_transfer_bytes')\n        proofs = {}\n        for filename, (size, digest) in PROOFS.items():\n            raw = read_regular(INBOX / filename, digest, 1048576)\n            need(len(raw) == size, 'fixed_resolver_evidence_bytes')\n            proofs[filename] = json.loads(raw)\n        proof = proofs['offline-resolver-proof.public.json']\n        good = [s for s in proof['commands'] if s['exit_code'] == 0]\n        need(proof['status'] == 'passed' and proof['source_commit'] == COMMIT\n             and proof['source_tree'] == TREE and proof['cargo_lock_sha256'] == LOCK\n             and len(good) == 2 and {s['label']: s['stdout_sha256'] for s in good} == TREE_HASHES\n             and all(s['stderr_bytes'] == 0 for s in good), 'actual_source_offline_closure_receipt')\n        entries, counts = validate_packet(manifest_raw, payload, lock_raw, MANIFEST_SHA, PAYLOAD_SHA)\n        need(len(entries) == 677, 'fixed_transfer_member_count')\n        namespace_parent = Path('/home/alex/.cargo/registry/index')\n        groups = [p for p in namespace_parent.iterdir() if not p.is_symlink() and p.is_dir()\n                  and (p / '.cache').is_dir() and not (p / '.cache').is_symlink()]\n        need(len(groups) == 1, 'one_observed_existing_public_registry_namespace')\n        write_new_cache(CARGO_HOME, groups[0].name, entries)\n        source_identity()\n        need(read_regular(SOURCE / 'Cargo.lock', LOCK) == lock_raw, 'receiver_lock_unchanged')\n        result.update(status='installed', source_commit=COMMIT, source_tree=TREE,\n                      cargo_lock_sha256=LOCK, manifest_sha256=MANIFEST_SHA,\n                      payload_sha256=PAYLOAD_SHA, payload_bytes=len(payload),\n                      cargo_home=str(CARGO_HOME), installed_file_count=len(entries), counts=counts,\n                      all_installed_files_sha256_readback_equal=True, existing_registry_namespace_reused=True,\n                      receiver_cargo_offline_tree_not_yet_executed=True)\n    except BaseException as error:\n        result.update(status='failed', failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)\n    result['finished_at_unix'] = time.time()\n    with (INBOX / 'receive.result.public.json').open('x') as f:\n        json.dump(result, f, sort_keys=True, indent=2)\n        f.write('\\n')\n        f.flush()\n        os.fsync(f.fileno())\n    print(json.dumps(result, sort_keys=True), flush=True)\n    return 0 if result['status'] == 'installed' else 1\n\n\nif __name__ == '__main__':\n    raise SystemExit(main())\n"

SSH_ARGS = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']
START = time.monotonic()
DEADLINE = START + 840
REPORT = {'schema': 'heptabao.mac-public-linux-dependency-relay.v1', 'status': 'running',
          'steps': [], 'ssh_aliases': ['ai395', 'pocket4'], 'new_private_receiver_cargo_home': True,
          'production_changed': False, 'rust_build_executed': False, 'product_binary_executions': 0,
          'normal107_qualified': False, 'old_cache_modified': False, 'network_crate_downloads': False,
          'credential_files_copied': False, 'automatic_retry': False}

REMOTE_COMMON = """from pathlib import Path
import hashlib,json,os,stat,sys
os.umask(0o077)
def need(ok,label):
 if not ok:raise RuntimeError(label)
def ident(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory(path):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o022 and path.resolve()==path,'owned_real_directory')
def read_file(path,size,sha):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size,'source_regular_size')
  with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(size+1)
  need(len(data)==size and hashlib.sha256(data).hexdigest()==sha and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'source_identity_or_hash')
  return data
 finally:os.close(fd)
"""


def need(ok, label):
    if not ok:
        raise RuntimeError(label)


def ident(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def file_pin(path, size=None, digest=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= 128 * 1024 * 1024, 'bounded_regular_file_pin')
        h = hashlib.sha256()
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            h.update(data)
        need(ident(before) == ident(os.fstat(fd)) == ident(path.lstat()), 'file_changed_during_pin')
        need((size is None or before.st_size == size)
             and (digest is None or h.hexdigest() == digest), 'file_pin_mismatch')
        return {'bytes': before.st_size, 'sha256': h.hexdigest(), 'uid': before.st_uid,
                'mode': stat.S_IMODE(before.st_mode)}
    finally:
        os.close(fd)


def write_exclusive(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def ssh_argv(alias, code):
    need(alias in ('ai395', 'pocket4'), 'existing_alias_only')
    remote = shlex.join(['/usr/bin/python3', '-I', '-S', '-B', '-c', code])
    return [SSH, *SSH_ARGS, alias, remote]


def run(label, alias, code, stdout_path, *, stdin_path=None, seconds=180):
    remaining = DEADLINE - time.monotonic()
    need(remaining > 0, 'relay_absolute_deadline')
    cap = min(seconds, remaining)
    errpath = OUT / (label + '.stderr')
    row = {'label': label, 'alias': alias, 'budget_seconds': cap, 'attempts': 1,
           'timed_out': False, 'owned_ssh_session_signals': []}
    proc = None
    incoming = None
    try:
        incoming = stdin_path.open('rb') if stdin_path is not None else None
        with stdout_path.open('xb') as outstream, errpath.open('xb') as errstream:
            try:
                proc = subprocess.Popen(ssh_argv(alias, code),
                                        stdin=incoming if incoming is not None else subprocess.DEVNULL,
                                        stdout=outstream, stderr=errstream, start_new_session=True)
                row['pid'] = proc.pid
                try:
                    row['exit_code'] = proc.wait(timeout=cap)
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    raise
            finally:
                if proc is not None and proc.poll() is None:
                    need(os.getpgid(proc.pid) == proc.pid, 'owned_ssh_process_group')
                    for sig, budget in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
                        try:
                            os.killpg(proc.pid, sig)
                            row['owned_ssh_session_signals'].append(signal.Signals(sig).name)
                        except ProcessLookupError:
                            break
                        try:
                            proc.wait(timeout=budget)
                            break
                        except subprocess.TimeoutExpired:
                            pass
                    need(proc.poll() is not None, 'owned_ssh_parent_retired')
                outstream.flush()
                errstream.flush()
                os.fsync(outstream.fileno())
                os.fsync(errstream.fileno())
    finally:
        if incoming is not None:
            incoming.close()
        if stdout_path.exists():
            row['stdout'] = file_pin(stdout_path)
        if errpath.exists():
            row['stderr'] = file_pin(errpath)
        REPORT['steps'].append(row)
    need(row.get('exit_code') == 0 and not row['timed_out'], label + '_failed')
    return row


def main():
    os.umask(0o077)
    parent = PARENT.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
         and not parent.st_mode & 0o022 and PARENT.resolve() == PARENT, 'actual_owned_mac_parent')
    OUT.mkdir(mode=0o700)
    try:
        need(str(Path(sys.executable).resolve()) == str(Path(PYTHON).resolve()), 'fixed_mac_python')
        REPORT['tools_before'] = {path: file_pin(path, *pin) for path, pin in TOOL_PINS.items()}
        need(hashlib.sha256(RECEIVER.encode()).hexdigest() == RECEIVER_SHA, 'receiver_source_pin')
        receiver_path = OUT / 'receive_linux_dependencies.py'
        write_exclusive(receiver_path, RECEIVER.encode())
        for name, source, size, digest in FILES:
            code = REMOTE_COMMON + (
                'data=read_file(Path(' + repr(source) + '),' + str(size) + ',' + repr(digest) + ')\n'
                'sys.stdout.buffer.write(data);sys.stdout.buffer.flush()\n')
            run('download-' + name, 'ai395', code, OUT / name)
            file_pin(OUT / name, size, digest)
        prepare = REMOTE_COMMON + (
            'root=Path(' + repr(POCKET_ROOT) + ');directory(root)\n'
            'dest=Path(' + repr(INBOX) + ');dest.mkdir(mode=0o700);directory(dest)\n'
            'print(json.dumps({"status":"created","private_mode":448}),flush=True)\n')
        run('prepare-pocket4-inbox', 'pocket4', prepare, OUT / 'prepare-pocket4-inbox.stdout', seconds=30)
        transfers = [(name, size, digest) for name, _, size, digest in FILES]
        transfers.append(('receive_linux_dependencies.py', len(RECEIVER.encode()), RECEIVER_SHA))
        REPORT['transferred_files'] = []
        for name, size, digest in transfers:
            file_pin(OUT / name, size, digest)
            code = REMOTE_COMMON + (
                'folder=Path(' + repr(INBOX) + ');directory(folder)\n'
                'dest=folder/' + repr(name) + '\n'
                'size=' + str(size) + ';expected=' + repr(digest) + '\n'
                'h=hashlib.sha256();total=0\n'
                'with dest.open("xb") as f:\n'
                ' while True:\n'
                '  data=sys.stdin.buffer.read(min(1048576,size-total+1))\n'
                '  if not data:break\n'
                '  total+=len(data);need(total<=size,"received_bytes_exceed_pin");h.update(data);f.write(data)\n'
                ' need(total==size and h.hexdigest()==expected,"received_whole_hash");f.flush();os.fsync(f.fileno())\n'
                'read_file(dest,size,expected)\n'
                'print(json.dumps({"status":"received","bytes":size,"sha256":expected}),flush=True)\n')
            status_path = OUT / ('upload-' + name + '.stdout')
            run('upload-' + name, 'pocket4', code, status_path, stdin_path=OUT / name)
            status = json.loads(status_path.read_bytes())
            need(status == {'status': 'received', 'bytes': size, 'sha256': digest}, 'receiver_whole_file_readback')
            file_pin(OUT / name, size, digest)
            REPORT['transferred_files'].append({'name': name, 'bytes': size, 'sha256': digest,
                                                'source_mac_receiver_hashes_equal': True})
        code = REMOTE_COMMON + (
            'folder=Path(' + repr(INBOX) + ');directory(folder)\n'
            'path=folder/"receive_linux_dependencies.py"\n'
            'data=read_file(path,' + str(len(RECEIVER.encode())) + ',' + repr(RECEIVER_SHA) + ')\n'
            'exec(compile(data,str(path),"exec"),{"__name__":"__main__","__file__":str(path)})\n')
        install_stdout = OUT / 'install-pocket4-cache.stdout'
        run('install-pocket4-cache', 'pocket4', code, install_stdout, seconds=180)
        receipt = json.loads(install_stdout.read_bytes())
        need(receipt['status'] == 'installed' and receipt['installed_file_count'] == 677
             and receipt['payload_sha256'] == FILES[1][3]
             and receipt['manifest_sha256'] == FILES[0][3]
             and receipt['normal107_qualified'] is False
             and receipt['all_installed_files_sha256_readback_equal'] is True,
             'receiver_installed_complete_public_packet')
        REPORT['tools_after'] = {path: file_pin(path, *pin) for path, pin in TOOL_PINS.items()}
        need(REPORT['tools_after'] == REPORT['tools_before'], 'mac_tools_unchanged')
        REPORT.update(status='transferred_and_installed', receiver=receipt,
                      all_transferred_whole_hashes_equal=True,
                      pocket4_offline_dependency_tree_still_required=True)
    except BaseException as error:
        REPORT.update(status='failed', failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
    REPORT['elapsed_seconds'] = time.monotonic() - START
    write_exclusive(OUT / 'result.public.json', (json.dumps(REPORT, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'status': REPORT['status'], 'result': str(OUT / 'result.public.json'),
                      'rust_build_executed': False, 'normal107_qualified': False}), flush=True)
    return 0 if REPORT['status'] == 'transferred_and_installed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
