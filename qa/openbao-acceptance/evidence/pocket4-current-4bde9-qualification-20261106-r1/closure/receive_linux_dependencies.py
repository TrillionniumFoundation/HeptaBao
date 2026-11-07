#!/usr/bin/env python3
"""Install one pinned public Cargo dependency packet in a new owned directory."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import time
import tomllib
from urllib.parse import urlsplit

COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
LOCK = 'd2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5'
MANIFEST_SHA = '0d74878d414151a41fa85927ff0732ea2ab123dcdf0955aa8cd75c5be2216897'
PAYLOAD_SHA = '8e771190e6df05560f8a41bbf7992586137ee4ab730123301c6dba0d595759c9'
ROOT = Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
INBOX = ROOT / 'linux-public-closure-inbox-r1'
CARGO_HOME = ROOT / 'cargo-home-public-linux-r1'
SOURCE = ROOT / 'source-4bde9'
MAXIMUM = 128 * 1024 * 1024
PROOFS = {
    'offline-resolver-proof.public.json': (5361, 'da7f698027b1d97488aefda02556c807ae4b0a9d4baa435552b96efa626b8e28'),
    'prior-missing-index-proof.public.json': (45743, '8df38dbaa49ce8ae54fbbcdb662eea188327179d23be17223dccb93b38140e90'),
}
TREE_HASHES = {
    'server': '3d112e6e8671700cd9c87b10e7c3f917b95633d469189c63cadf747ed736e707',
    'peer': '40e70fe078077d01cb304131a61c2fa54c1dbbd9a871fe56151a321cc94c420f',
}


def need(ok, label):
    if not ok:
        raise RuntimeError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_regular(path, expected=None, maximum=MAXIMUM):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, 'bounded_single_link_regular_file')
        data = bytearray()
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            data.extend(part)
            need(len(data) <= maximum, 'input_exceeded_bound')
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'input_identity_changed')
        data = bytes(data)
        need(expected is None or sha(data) == expected, 'input_sha256_mismatch')
        return data
    finally:
        os.close(fd)


def index_relative(name):
    if len(name) == 1:
        return '1/' + name
    if len(name) == 2:
        return '2/' + name
    if len(name) == 3:
        return '3/' + name[0] + '/' + name
    return name[:2] + '/' + name[2:4] + '/' + name


def validate_packet(manifest_raw, payload, lock_raw, manifest_sha, payload_sha):
    need(sha(manifest_raw) == manifest_sha and sha(payload) == payload_sha, 'packet_sha256')
    m = json.loads(manifest_raw)
    need(m['schema'] == 'heptabao.closed-linux-registry-transfer.v1'
         and m['source_commit'] == COMMIT and m['source_tree'] == TREE
         and m['cargo_lock_sha256'] == sha(lock_raw), 'canonical_source_and_lock_binding')
    need(m['user_cargo_config_or_credentials_included'] is False
         and m['source_cache_modified'] is False and m['rust_compilation_executed'] is False
         and m['normal107_qualified'] is False and m['production_changed'] is False
         and m['cargo_network_downloads_executed'] is False, 'public_metadata_only_scope')
    need(m['payload']['bytes'] == len(payload) and m['payload']['sha256'] == payload_sha
         and len(payload) <= MAXIMUM, 'payload_length_pin')
    packages = {}
    for p in tomllib.loads(lock_raw.decode())['package']:
        if p.get('source'):
            need(p['source'] == 'registry+https://github.com/rust-lang/crates.io-index',
                 'public_crates_io_lock_only')
            key = (p['name'], p['version'])
            need(key not in packages, 'duplicate_registry_lock_package')
            packages[key] = p['checksum']
    entries = m['entries']
    names = [e['member'] for e in entries]
    need(names == sorted(set(names)) and len(names) <= 1024, 'closed_unique_sorted_members')
    counts = {'linux_selected_crate': 0, 'offline_resolver_required_crate': 0,
              'selected_package_sparse_index': 0, 'offline_resolver_required_sparse_index': 0,
              'public_registry_config': 0}
    output = []
    index_records = {}
    archive_versions = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as tar:
        members = tar.getmembers()
        need([x.name for x in members] == names, 'tar_missing_extra_duplicate_or_reordered')
        for info, entry in zip(members, entries):
            member = PurePosixPath(info.name)
            need(not member.is_absolute() and all(x not in ('', '.', '..') for x in member.parts)
                 and str(member) == info.name, 'relative_canonical_member_only')
            need(info.type == tarfile.REGTYPE and info.size == entry['bytes']
                 and 0 <= info.size <= 32 * 1024 * 1024 and not info.linkname
                 and not info.pax_headers and info.mode == 0o600 and info.uid == info.gid == 0
                 and info.mtime == 0 and not info.uname and not info.gname, 'fixed_regular_tar_metadata')
            data = tar.extractfile(info).read()
            need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'member_size_or_sha256')
            kind = entry['kind']
            need(kind in counts, 'unsupported_member_kind')
            counts[kind] += 1
            if kind in ('linux_selected_crate', 'offline_resolver_required_crate'):
                name, version = entry['crate'], entry['version']
                need(re.fullmatch(r'[A-Za-z0-9_-]+', name)
                     and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', version)
                     and info.name == 'crates/' + name + '-' + version + '.crate'
                     and packages.get((name, version)) == sha(data), 'crate_not_exact_canonical_lock')
                archive_versions.setdefault(name, set()).add(version)
                output.append(('cache', name + '-' + version + '.crate', data))
            elif kind in ('selected_package_sparse_index', 'offline_resolver_required_sparse_index'):
                name = entry['crate']
                need(re.fullmatch(r'[A-Za-z0-9_-]+', name)
                     and info.name == 'indexes/' + index_relative(name)
                     and name not in index_records, 'canonical_unique_sparse_index_path')
                records = {}
                for part in data.split(b'\0'):
                    if part.startswith(b'{'):
                        item = json.loads(part)
                        need(item.get('name') == name and item.get('vers') not in records,
                             'sparse_index_name_or_duplicate_version')
                        records[item['vers']] = item
                versions = entry['locked_versions']
                need(versions == sorted(set(versions)) and versions
                     and all((name, v) in packages and records.get(v, {}).get('cksum') == packages[(name, v)]
                             for v in versions), 'sparse_index_locked_versions_and_checksums')
                index_records[name] = records
                output.append(('index', '.cache/' + index_relative(name), data))
            else:
                need(info.name == 'registry-config.json', 'public_registry_metadata_filename')
                config = json.loads(data)
                need(set(config) == {'dl', 'api'} and all(isinstance(x, str) for x in config.values()),
                     'anonymous_registry_metadata_only')
                for value in config.values():
                    url = urlsplit(value)
                    need(url.scheme == 'https' and url.hostname in ('crates.io', 'static.crates.io')
                         and not url.username and not url.password and not url.query and not url.fragment,
                         'anonymous_public_registry_url')
                output.append(('index', 'config.json', data))
    need(counts['public_registry_config'] == 1
         and counts['linux_selected_crate'] == m['linux_selected_registry_package_count']
         and counts['offline_resolver_required_crate'] == m['metadata_resolver_additional_archive_count']
         and counts['selected_package_sparse_index'] + counts['offline_resolver_required_sparse_index']
         == m['sparse_index_count']
         and counts['offline_resolver_required_sparse_index']
         == m['metadata_resolver_additional_index_count'], 'declared_closed_counts')
    need(all(name in index_records and all(index_records[name].get(v, {}).get('cksum') == packages[(name, v)]
                                          for v in versions)
             for name, versions in archive_versions.items()), 'every_archive_has_exact_public_index')
    return output, counts


def owned_directory(path):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022
         and path.resolve() == path, 'owned_real_parent_directory')


def write_new_cache(path, namespace, entries):
    owned_directory(path.parent)
    need(re.fullmatch(r'index\.crates\.io-[0-9a-f]{16}', namespace), 'observed_public_registry_namespace')
    path.mkdir(mode=0o700)
    for kind, relative, data in entries:
        dest = path / 'registry' / kind / namespace / relative
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with dest.open('xb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        need(read_regular(dest) == data, 'installed_file_readback')
    actual = {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}
    expected = {'registry/' + kind + '/' + namespace + '/' + rel for kind, rel, _ in entries}
    need(actual == expected and not any(p.is_symlink() for p in path.rglob('*')), 'installed_closed_file_set')


def source_identity():
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    def git(*args):
        return subprocess.check_output(
            ['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
             '-C', str(SOURCE), *args], env=env, stderr=subprocess.DEVNULL, timeout=15).decode().strip()
    need(git('rev-parse', 'HEAD') == COMMIT and git('rev-parse', 'HEAD^{tree}') == TREE
         and not git('status', '--porcelain', '--untracked-files=all'), 'clean_canonical_receiver_source')


def main():
    os.umask(0o077)
    result = {'schema': 'heptabao.pocket4-public-dependency-receipt.v1', 'status': 'running',
              'rust_compilation_executed': False, 'product_binary_executions': 0,
              'normal107_qualified': False, 'production_changed': False,
              'existing_user_cache_modified': False, 'user_configuration_or_credentials_opened': False}
    try:
        owned_directory(ROOT)
        owned_directory(INBOX)
        source_identity()
        lock_raw = read_regular(SOURCE / 'Cargo.lock', LOCK)
        manifest_raw = read_regular(INBOX / 'manifest.public.json', MANIFEST_SHA, 1048576)
        payload = read_regular(INBOX / 'linux-locked-dependencies.tar', PAYLOAD_SHA)
        need(len(manifest_raw) == 207549 and len(payload) == 67880960, 'fixed_transfer_bytes')
        proofs = {}
        for filename, (size, digest) in PROOFS.items():
            raw = read_regular(INBOX / filename, digest, 1048576)
            need(len(raw) == size, 'fixed_resolver_evidence_bytes')
            proofs[filename] = json.loads(raw)
        proof = proofs['offline-resolver-proof.public.json']
        good = [s for s in proof['commands'] if s['exit_code'] == 0]
        need(proof['status'] == 'passed' and proof['source_commit'] == COMMIT
             and proof['source_tree'] == TREE and proof['cargo_lock_sha256'] == LOCK
             and len(good) == 2 and {s['label']: s['stdout_sha256'] for s in good} == TREE_HASHES
             and all(s['stderr_bytes'] == 0 for s in good), 'actual_source_offline_closure_receipt')
        entries, counts = validate_packet(manifest_raw, payload, lock_raw, MANIFEST_SHA, PAYLOAD_SHA)
        need(len(entries) == 677, 'fixed_transfer_member_count')
        namespace_parent = Path('/home/alex/.cargo/registry/index')
        groups = [p for p in namespace_parent.iterdir() if not p.is_symlink() and p.is_dir()
                  and (p / '.cache').is_dir() and not (p / '.cache').is_symlink()]
        need(len(groups) == 1, 'one_observed_existing_public_registry_namespace')
        write_new_cache(CARGO_HOME, groups[0].name, entries)
        source_identity()
        need(read_regular(SOURCE / 'Cargo.lock', LOCK) == lock_raw, 'receiver_lock_unchanged')
        result.update(status='installed', source_commit=COMMIT, source_tree=TREE,
                      cargo_lock_sha256=LOCK, manifest_sha256=MANIFEST_SHA,
                      payload_sha256=PAYLOAD_SHA, payload_bytes=len(payload),
                      cargo_home=str(CARGO_HOME), installed_file_count=len(entries), counts=counts,
                      all_installed_files_sha256_readback_equal=True, existing_registry_namespace_reused=True,
                      receiver_cargo_offline_tree_not_yet_executed=True)
    except BaseException as error:
        result.update(status='failed', failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
    result['finished_at_unix'] = time.time()
    with (INBOX / 'receive.result.public.json').open('x') as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'installed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
