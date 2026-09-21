#!/usr/bin/env python3
"""Pinned OpenBao CLI transports candidate-native snapshots on a local TLS server.

Native HBB2 state is deliberately not an OpenBao state.bin. Native v2 binds the
seal: ordinary rollback succeeds within that seal, and rekey rejects old archives
on both restore paths. No HA restore or cross-seal force compatibility claim.
All temporary files require an explicit private SSD/guest work parent. Optional
PostgreSQL 17 uses a fresh private TLS/SCRAM cluster and a nonprivileged storage
owner; native file transfer and restore share the same scenarios for both stores.
"""
from __future__ import annotations
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, oracle_environment
from online_evidence import admit_output, source_identity

MIB = 1024 * 1024
BLOCK = 64 * 1024
ARCHIVE_LIMIT = 131 * MIB
NAMES = ['meta.json', 'state.bin', 'SHA256SUMS', 'SHA256SUMS.sealed']
REQUIRED = frozenset({'record_format', 'all_before_save', 'cli_save', 'archive_above_20mib',
    'archive_contract', 'ordinary_rollback_restored', 'all_ordinary_restored',
    'ordinary_other_owner_restored', 'ordinary_later_absent', 'sealed_tamper_rejected',
    'sealed_tamper_unchanged', 'truncation_rejected', 'truncation_unchanged',
    'oversize_rejected', 'oversize_unchanged', 'unauthorized_before_body',
    'upload_interrupted', 'upload_slot_released', 'upload_unchanged',
    'download_interrupted', 'download_slot_released', 'download_unchanged',
    'all_changed_retained', 'cli_force_restore', 'all_restored', 'other_owner_restored',
    'later_absent', 'chunked_restore', 'all_chunked_restored', 'restart_unsealed',
    'all_reopened', 'reopened_other_owner', 'reopened_later_absent', 'spool_clean',
    'plaintext_absent', 'legacy_v1_outer_contract', 'legacy_v1_ordinary_rejected',
    'legacy_v1_ordinary_unchanged', 'legacy_v1_force_rejected', 'legacy_v1_force_unchanged',
    'rekey_initialized', 'rekey_completed', 'rekey_old_ordinary_rejected',
    'rekey_old_ordinary_unchanged', 'rekey_old_force_rejected', 'rekey_old_force_unchanged',
    'all_rekey_rejected_retained', 'rekey_new_save', 'rekey_new_binding', 'rekey_changed',
    'rekey_new_restore', 'all_rekey_restored', 'old_share_rejected', 'complete'})


PG_SCOPE = 'native-snapshot-cli-fixture'
PG_CHUNK_BYTES = 768 * 1024
PG_ARTIFACT_LIMIT = 64 * MIB
POSTGRES_REQUIRED = frozenset({'fresh_postgresql_owner', 'postgres_owner_unprivileged',
    'postgres_init_nonce_required', 'postgres_init_pending_unavailable',
    'postgres_init_wrong_nonce_rejected', 'postgres_init_same_nonce_recovered',
    'postgres_init_same_nonce_idempotent', 'postgres_init_ack',
    'postgres_no_local_artifact_fallback', 'postgres_unavailable_unseal_rejected',
    'postgres_unavailable_no_local_artifacts', 'postgres_recovered_unseal',
    'all_postgres_recovered', 'postgres_single_authoritative_manifest',
    'postgres_encrypted_artifacts', 'postgres_plaintext_absent'})


def complete(checks, *, postgres=False):
    if not isinstance(checks, list) or not checks: return False
    if any(not isinstance(r, dict) or set(r) != {'case', 'passed'} or r['passed'] is not True
           or not isinstance(r['case'], str) or not re.fullmatch(r'[a-z0-9_]{1,120}', r['case']) for r in checks):
        return False
    names = [r['case'] for r in checks]
    return len(names) == len(set(names)) and names[-1] == 'complete' and (REQUIRED | POSTGRES_REQUIRED if postgres else REQUIRED).issubset(names)


def private_parent(path):
    path = path.absolute()
    for item in [path, *path.parents]:
        mode = item.lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode): raise ValueError('unsafe_work_parent')
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private_work_parent_required')
    return path


def new_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')


def inspect_archive(path, *, legacy_unbound=False):
    """Stream the large member; retain only the three bounded metadata members."""
    hashes, small, names, state_size, magic = {}, {}, [], 0, b''
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            if (not member.isfile() or member.name not in NAMES or member.name in names
                    or member.size < 0 or member.size > 130 * MIB):
                raise ValueError('archive_member')
            names.append(member.name)
            source = archive.extractfile(member)
            digest, count, kept = hashlib.sha256(), 0, bytearray()
            while chunk := source.read(BLOCK):
                if member.name == 'state.bin' and not count: magic = chunk[:4]
                digest.update(chunk); count += len(chunk)
                if member.name != 'state.bin':
                    if count >= 8192: raise ValueError('archive_small_member')
                    kept.extend(chunk)
            if count != member.size: raise ValueError('archive_length')
            hashes[member.name] = digest.hexdigest()
            if member.name == 'state.bin': state_size = count
            else: small[member.name] = bytes(kept)
    if names != NAMES: raise ValueError('archive_order')
    meta = json.loads(small['meta.json'])
    expected = f"{hashes['meta.json']}  meta.json\n{hashes['state.bin']}  state.bin\n".encode()
    expected_format = 'heptabao-native-snapshot-v1' if legacy_unbound else 'heptabao-native-snapshot-v2'
    expected_fields = {'format','state_format','generation','state_bytes'}
    binding = meta.get('seal_identity')
    if legacy_unbound:
        valid_binding = binding is None
    else:
        expected_fields.add('seal_identity')
        valid_binding = (isinstance(binding,dict) and set(binding) == {'format','sha256'}
            and binding['format'] == 'heptabao-seal-metadata-digest-v1'
            and isinstance(binding['sha256'],str)
            and re.fullmatch(r'[0-9a-f]{64}',binding['sha256']) is not None)
    if (set(meta) != expected_fields or not valid_binding or meta.get('format') != expected_format
            or meta.get('state_format') != 'heptabao-encrypted-backup-v1/HBB2'
            or meta.get('state_bytes') != state_size or magic != b'HBB2'
            or small['SHA256SUMS'] != expected or not small['SHA256SUMS.sealed']):
        raise ValueError('archive_contract')
    return {'state_bytes':state_size, 'generation':meta['generation'], 'members':names,
            'seal_identity':binding, 'state_sha256':hashes['state.bin']}



def legacy_unbound_archive(source, destination):
    """Build the old four-field envelope, not a claimed historical AEAD archive.

    Recompute plaintext checksums but retain v2 sealed bytes. Restore must reject
    the missing binding explicitly before authentication; a generic 400 is not
    accepted as evidence for that branch.
    """
    summary = inspect_archive(source)
    metadata = json.dumps({'format':'heptabao-native-snapshot-v1',
        'state_format':'heptabao-encrypted-backup-v1/HBB2',
        'generation':summary['generation'], 'state_bytes':summary['state_bytes']},
        separators=(',',':')).encode()
    sums = (hashlib.sha256(metadata).hexdigest()+'  meta.json\n'+
            summary['state_sha256']+'  state.bin\n').encode()
    with tarfile.open(source,'r|gz') as reader, new_file(destination) as output:
        # The native reader requires exactly two terminal tar blocks; Python's
        # tarfile writer adds record-sized padding and is not suitable here.
        with gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as writer:
            for member in reader:
                if member.name in ('meta.json','SHA256SUMS'):
                    data = metadata if member.name == 'meta.json' else sums
                    replacement = tarfile.TarInfo(member.name); replacement.size = len(data)
                    replacement.mode = 0o600
                    writer.write(replacement.tobuf(format=tarfile.USTAR_FORMAT))
                    writer.write(data); writer.write(b'\0'*((-len(data))%512))
                else:
                    writer.write(member.tobuf(format=tarfile.USTAR_FORMAT))
                    payload = reader.extractfile(member); remaining = member.size
                    while remaining:
                        chunk = payload.read(min(BLOCK,remaining))
                        if not chunk:raise ValueError('legacy_reframe_truncated')
                        writer.write(chunk);remaining -= len(chunk)
                    writer.write(b'\0'*((-member.size)%512))
            writer.write(b'\0'*1024)


def tamper_sealed(source, destination):
    """Preserve every tar byte/header and valid gzip CRC; corrupt only sealed sums."""
    changed = False
    with gzip.open(source, 'rb') as reader, new_file(destination) as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as writer:
            for expected in NAMES:
                header = reader.read(512)
                if len(header) != 512 or header[:100].rstrip(b'\0').decode() != expected:
                    raise ValueError('noncanonical_input')
                length = int(header[124:136].rstrip(b'\0 '), 8)
                writer.write(header)
                remaining = length
                while remaining:
                    chunk = reader.read(min(BLOCK, remaining))
                    if not chunk: raise ValueError('truncated_input')
                    if expected == 'SHA256SUMS.sealed' and not changed:
                        chunk = bytes([chunk[0] ^ 1]) + chunk[1:]; changed = True
                    writer.write(chunk); remaining -= len(chunk)
                padding = (-length) % 512
                writer.write(reader.read(padding))
            while chunk := reader.read(BLOCK): writer.write(chunk)
    if not changed: raise ValueError('no_sealed_checksum')


def cli_environment(instance, work):
    env = oracle_environment(work)
    for prefix in ('BAO', 'VAULT'):
        env.update({prefix+'_ADDR':instance.address, prefix+'_CACERT':str(instance.root/'ca.crt'),
                    prefix+'_TOKEN':instance.token, prefix+'_MAX_RETRIES':'0', prefix+'_CLIENT_TIMEOUT':'60s'})
    return env


def cli_diagnostics(exit_code, stderr, *, timed_out=False):
    """Fixed, bounded classifications only; never return any provider/CLI text."""
    bounded = stderr[:65536].lower()
    categories = [name for name, patterns in (
        ('unexpected_eof', (b'unexpected eof',)),
        ('eof', (b': eof',)),
        ('connection_reset', (b'connection reset',)),
        ('broken_pipe', (b'broken pipe',)),
        ('timeout', (b'timed out', b'timeout', b'deadline exceeded')),
        ('tls', (b'tls:', b'x509:')),
        ('closed_file', (b'file already closed', b'closed file')),
        ('closed_network', (b'use of closed network connection', b'closed network')),
        ('connection_aborted', (b'connection aborted', b'software caused connection abort')),
        ('http_transport', (b'net/http:', b'http/1.x transport connection broken')),
        ('request_body', (b'contentlength', b'body length', b'request.body', b'request body')),
        ('read_syscall', (b'read tcp ', b'read: ', b'read /')),
        ('write_syscall', (b'write tcp ', b'write: ', b'write /')),
        ('server_closed_idle', (b'server closed idle connection',)),
    ) if any(pattern in bounded for pattern in patterns)]
    if timed_out and 'timeout' not in categories: categories.append('timeout')
    statuses = re.findall(rb'Code: ([0-9]{3})(?:[.\s]|$)', stderr[:65536])
    return {'exit_code': exit_code, 'http_status_codes': [int(code) for code in statuses[:16]],
            'stderr_bytes': len(stderr), 'stderr_within_bound': len(stderr) <= 65536,
            'transport_classes': categories, 'subprocess_timeout': timed_out}


def cli(binary, instance, work, command, path, force=False, expected_error=None, expected_message=None,
        diagnostics=None):
    args = [str(binary), 'operator', 'raft', 'snapshot', command]
    if force: args.append('-force')
    args.append(str(path))
    # Never expose stdout/stderr, token environment, request bodies or paths in receipts.
    try:
        result = subprocess.run(args, env=cli_environment(instance, work), cwd=work,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=90)
    except subprocess.TimeoutExpired as error:
        if diagnostics is not None:
            diagnostics.update(cli_diagnostics(None, error.stderr or b'', timed_out=True))
        raise
    if diagnostics is not None:
        diagnostics.update(cli_diagnostics(result.returncode, result.stderr))
    if expected_error is not None:
        # Inspect only the CLI's HTTP status diagnostic; never publish stderr.
        statuses = re.findall(rb'Code: ([0-9]{3})(?:[.\s]|$)', result.stderr)
        return (result.returncode != 0 and len(result.stderr) <= 65536
                and statuses == [str(expected_error).encode()]
                and (expected_message is None or expected_message in result.stderr))
    return result.returncode


def raw_socket(instance):
    raw = socket.create_connection(('127.0.0.1', instance.port), timeout=15)
    try: return instance.context.wrap_socket(raw, server_hostname='localhost')
    except BaseException: raw.close(); raise


def header(instance, method, route='snapshot-force', framing='', token=None):
    token = instance.token if token is None else token
    return (f'{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\nHost: localhost\r\n'
            f'X-Vault-Token: {token}\r\nConnection: close\r\n{framing}\r\n').encode()


def response_status(tls):
    response = http.client.HTTPResponse(tls); response.begin()
    status = response.status
    if len(response.read(65537)) > 65536: raise ValueError('unexpected_large_error')
    response.close()
    return status


def raw_rejection(instance, framing, token=None):
    with raw_socket(instance) as tls:
        tls.sendall(header(instance, 'POST', framing=framing, token=token))
        return response_status(tls)


def chunked_restore(instance, path):
    with raw_socket(instance) as tls, path.open('rb') as source:
        tls.sendall(header(instance, 'POST', framing='Transfer-Encoding: chunked\r\n'))
        while chunk := source.read(BLOCK):
            tls.sendall(f'{len(chunk):x}\r\n'.encode()+chunk+b'\r\n')
        tls.sendall(b'0\r\n\r\n')
        return response_status(tls)


def spool_is_idle(instance):
    spool = instance.root/'data'/'.snapshot-transfer'
    if not spool.is_dir() or any(spool.iterdir()): return False
    for entry in (Path('/proc')/str(instance.process.pid)/'fd').iterdir():
        try: target = os.readlink(entry)
        except FileNotFoundError: continue
        if '.snapshot-transfer/transfer-' in target: return False
    return True


def wait_idle(instance):
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        if spool_is_idle(instance): return True
        time.sleep(0.05)
    return False


def contains_any(path, samples):
    overlap, size = b'', max(map(len, samples))
    with path.open('rb') as stream:
        while chunk := stream.read(BLOCK):
            data = overlap+chunk
            if any(sample in data for sample in samples): return True
            overlap = data[-size:]
    return False




def rekey_share(call, old_share, check):
    status, begin = call('POST','sys/rekey/init',
        {'secret_shares':1,'secret_threshold':1,'require_verification':False})
    check('rekey_initialized',status == 200 and bool(begin.get('nonce')))
    status, rekeyed = call('POST','sys/rekey/update',{'nonce':begin['nonce'],'key':old_share})
    check('rekey_completed',status == 200 and rekeyed.get('complete') is True
          and rekeyed.get('verification_required') is False and len(rekeyed.get('keys_base64',[])) == 1)
    return rekeyed['keys_base64'][0]

def postgres_identity(bin_dir):
    names = ('postgres', 'initdb', 'psql')
    if not all((bin_dir/name).is_file() for name in names):
        raise ValueError('complete_postgresql_binaries_required')
    version = subprocess.check_output([str(bin_dir/'postgres'), '--version'], text=True, timeout=10).strip()
    if not re.fullmatch(r'postgres \(PostgreSQL\) 17\.[0-9]+(?: .*|)', version):
        raise ValueError('postgresql_17_required')
    return {'version': version, 'binary_sha256': {name:file_hash(bin_dir/name) for name in names}}


def configure_postgres(pg, instance, config, check):
    pg.start()
    created = pg.sql("CREATE ROLE hb_storage LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        "NOREPLICATION NOBYPASSRLS PASSWORD '" + pg.manager_password + "'; "
        "CREATE DATABASE app OWNER hb_storage;", database='postgres')
    check('fresh_postgresql_owner', created.returncode == 0)
    role = pg.sql("SELECT rolcanlogin AND NOT (rolsuper OR rolcreatedb OR rolcreaterole "
                  "OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname='hb_storage'")
    owner = pg.sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='app'")
    check('postgres_owner_unprivileged', role.returncode == owner.returncode == 0
          and role.stdout.strip() == 't' and owner.stdout.strip() == 'hb_storage')
    config['postgres_durable'] = dict(endpoint=dict(origin=pg.origin,
        address=f'127.0.0.1:{pg.port}', server_name='localhost',
        ca_pem=(instance.root/'ca.crt').read_text()), connection_url=pg.origin+'/app',
        username='hb_storage', password=pg.manager_password, scope=PG_SCOPE)


def initialize(instance, pg, check):
    params = {'secret_shares':1, 'secret_threshold':1}
    nonce = None
    if pg is not None:
        check('postgres_init_nonce_required', instance.call('POST','sys/init',params)[0] == 400)
        nonce = secrets.token_hex(32); params['recovery_nonce'] = nonce
        pg.stop()
        check('postgres_init_pending_unavailable', instance.call('POST','sys/init',params)[0] == 503)
        instance.stop(); pg.start(); instance.start()
        check('postgres_init_wrong_nonce_rejected', instance.call('POST','sys/init',
              dict(params, recovery_nonce=secrets.token_hex(32)))[0] == 403)
    status, initialized = instance.call('POST','sys/init',params)
    check('initialized', status == 200)
    if pg is not None:
        check('postgres_init_same_nonce_recovered', bool(initialized.get('root_token'))
              and bool(initialized.get('keys_base64')))
        repeated_status, repeated = instance.call('POST','sys/init',params)
        check('postgres_init_same_nonce_idempotent', repeated_status == 200 and repeated == initialized)
    return initialized, nonce


def postgres_metadata_only(instance):
    data = instance.root/'data'; marker = data/'durable-backend.json'
    if not marker.is_file() or marker.is_symlink(): return False
    profile = json.loads(marker.read_text())
    return (profile.get('schema') == 2 and profile.get('backend') == 'postgresql'
            and profile.get('scope') == PG_SCOPE
            and re.fullmatch(r'[0-9a-f]{64}', profile.get('binding','')) is not None
            and all(not (data/name).exists() and not (data/name).is_symlink()
                    for name in ('state.hbs','ledger.hbl','journal.hbj')))


def inspect_postgres_artifacts(pg, samples):
    """Server stopped: page bounded rows, never load the full hex-encoded store.

    Magic/layout and absence of synthetic plaintext are observations, not a
    standalone AEAD proof. The service's full restore/reopen reads authenticate.
    """
    manifest_sql = ("SELECT format_version,revision,snapshot_len,ledger_len,journal_len "
                    "FROM heptabao_durable_v1.manifest_v1 WHERE scope='"+PG_SCOPE+"'")
    row = pg.sql(manifest_sql)
    if row.returncode or len(row.stdout.splitlines()) != 1:
        raise ValueError('postgres_manifest_count')
    fields = row.stdout.strip().split('|')
    if len(fields) != 5 or any(not re.fullmatch(r'[0-9]+', v) for v in fields):
        raise ValueError('postgres_manifest_shape')
    version, revision, *lengths = map(int, fields)
    if version != 1 or revision < 1 or any(n > PG_ARTIFACT_LIMIT for n in lengths) or min(lengths[:2]) == 0:
        raise ValueError('postgres_manifest_bounds')
    summary, chunks, plaintext_absent = {}, 0, True
    overlap_size = max(map(len, samples))
    for artifact, length, magic in zip(('snapshot','ledger','journal'), lengths, (b'HBS2',b'HBL2',b'HBJ2')):
        digest, tail = hashlib.sha256(), b''
        for number in range((length+PG_CHUNK_BYTES-1)//PG_CHUNK_BYTES):
            result = pg.sql("SELECT format_version,revision,encode(bytes,'hex') FROM "
                "heptabao_durable_v1.chunks_v1 WHERE scope='"+PG_SCOPE+"' AND artifact='"+
                artifact+"' AND chunk_no="+str(number)+" LIMIT 2")
            rows = result.stdout.splitlines()
            if result.returncode or len(rows) != 1 or len(rows[0]) > PG_CHUNK_BYTES*2+64:
                raise ValueError('postgres_chunk_count_or_bound')
            parts = rows[0].split('|')
            if len(parts) != 3 or parts[0] != '1' or not parts[1].isdigit() or not 0 < int(parts[1]) <= revision:
                raise ValueError('postgres_chunk_revision')
            if not re.fullmatch(r'[0-9a-f]*', parts[2]): raise ValueError('postgres_chunk_encoding')
            payload = bytes.fromhex(parts[2])
            if len(payload) != min(PG_CHUNK_BYTES, length-number*PG_CHUNK_BYTES):
                raise ValueError('postgres_chunk_length')
            if number == 0 and not payload.startswith(magic): raise ValueError('postgres_artifact_magic')
            joined = tail+payload
            plaintext_absent = plaintext_absent and not any(sample in joined for sample in samples)
            tail = joined[-overlap_size:]; digest.update(payload); chunks += 1
        summary[artifact] = {'bytes':length, 'sha256':digest.hexdigest()}
    count = pg.sql("SELECT count(*) FROM heptabao_durable_v1.chunks_v1 WHERE scope='"+PG_SCOPE+"'")
    again = pg.sql(manifest_sql)
    if count.returncode or count.stdout.strip() != str(chunks) or again.returncode or again.stdout != row.stdout:
        raise ValueError('postgres_extra_chunks_or_manifest_changed')
    return {'manifest_count':1, 'revision':revision, 'chunk_count':chunks,
            'artifacts':summary, 'plaintext_absent':plaintext_absent,
            'standalone_aead_verified':False}

def run(binary, bao, work, checks, observations, postgres_bin=None):
    from kv1_record_scale_live import Dataset, MOUNT
    from remote_jwks_live import Instance
    instance = pg = None
    def check(name, condition):
        checks.append({'case':name, 'passed':condition is True})
        if condition is not True: raise ScenarioFailure(name)
    try:
        instance = Instance(binary, work/'instance')
        config_path = instance.root/'server.json'; config = json.loads(config_path.read_text())
        config.update(lifecycle_interval_seconds=0, outbound_endpoints=[], timeout_seconds=60)
        if postgres_bin is not None:
            from postgres_live import Postgres
            pg = Postgres(postgres_bin, work/'postgres', instance.root/'tls.crt',
                          instance.root/'tls.key', instance.root/'ca.crt')
            configure_postgres(pg, instance, config, check)
        private_write(config_path, config, replace=True); instance.start()
        initialized, recovery_nonce = initialize(instance, pg, check)
        instance.token, unseal = initialized['root_token'], initialized['keys_base64'][0]
        check('unsealed', instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
        if pg is not None:
            check('postgres_init_ack', instance.call('POST','sys/init/ack',{})[0] == 204)
        client = Client(instance.address, str(instance.root/'ca.crt'), instance.token, timeout=60)
        def call(method, path, body=None):
            result = client.request(method, '/v1/'+path, body); return result.status, result.body
        def capacity():
            status, body = call('GET','sys/internal/capacity')
            if status != 200: raise ScenarioFailure('capacity_unavailable')
            return body['data']
        def verify(dataset, phase):
            for index, key in enumerate(sorted(dataset.hashes)):
                status, body = call('GET',MOUNT+'/'+key)
                check(f'{phase}_{index}',dataset.matches(key,status,body))
            check('all_'+phase,True)
        check('mounted',call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}})[0] == 204)
        original, changed, ordinal = Dataset(), Dataset(), 0
        while original.logical_bytes < 24*MIB:
            key=f'bulk/{ordinal:04d}'; value=original.make_value(ordinal)
            check(f'write_{ordinal}',call('PUT',MOUNT+'/'+key,value)[0] == 204)
            original.remember(key,value);changed.remember(key,value);ordinal+=1
        check('other_owner_written',call('PUT','secret/data/native-control',{'data':{'value':'before'}})[0] == 200)
        check('record_format',capacity()['state_storage_format'] == 'heptabao-state-records-v5')
        verify(original,'before_save')
        archive=work/'native.snap'
        check('cli_save',cli(bao,instance,work,'save',archive) == 0)
        check('archive_above_20mib',20*MIB < archive.stat().st_size <= ARCHIVE_LIMIT)
        meta=inspect_archive(archive);check('archive_contract',True)
        observations.update(archive_bytes=archive.stat().st_size, archive_sha256=file_hash(archive),
                            state_bytes=meta['state_bytes'], logical_value_bytes=original.logical_bytes,
                            record_count=len(original.hashes), archive_members=meta['members'])
        value=changed.make_value(1000)
        check('replaced',call('PUT',MOUNT+'/bulk/0000',value)[0] == 204);changed.remember('bulk/0000',value)
        check('deleted',call('DELETE',MOUNT+'/bulk/0001')[0] == 204);changed.forget('bulk/0001')
        check('later_written',call('PUT',MOUNT+'/later',{'value':'later'})[0] == 204)
        check('owner_changed',call('PUT','secret/data/native-control',{'data':{'value':'after'}})[0] == 200)
        generation=capacity()['generation'];check('newer_generation',generation > meta['generation'])
        legacy = work/'legacy-unbound.snap';legacy_unbound_archive(archive,legacy)
        legacy_meta = inspect_archive(legacy,legacy_unbound=True)
        check('legacy_v1_outer_contract', legacy_meta['seal_identity'] is None
              and legacy_meta['state_sha256'] == meta['state_sha256'])
        check('legacy_v1_ordinary_rejected',cli(bao,instance,work,'restore',legacy,
              expected_error=400,expected_message=b'native snapshot v1 has no seal binding; restore is unsupported'))
        check('legacy_v1_ordinary_unchanged',capacity()['generation'] == generation)
        check('legacy_v1_force_rejected',cli(bao,instance,work,'restore',legacy,True,
              expected_error=400,expected_message=b'native snapshot v1 has no seal binding; restore is unsupported'))
        check('legacy_v1_force_unchanged',capacity()['generation'] == generation)
        tampered=work/'tampered.snap';tamper_sealed(archive,tampered)
        # This remains a valid gzip/tar/checksum archive; only AEAD sealed sums differ.
        check('tamper_outer_contract_valid',inspect_archive(tampered) == meta)
        check('sealed_tamper_rejected',cli(bao,instance,work,'restore',tampered,True,expected_error=400))
        check('sealed_tamper_unchanged',capacity()['generation'] == generation)
        truncated=work/'truncated.snap'
        with archive.open('rb') as source,new_file(truncated) as output:
            remaining=archive.stat().st_size//2
            while remaining:
                chunk=source.read(min(BLOCK,remaining));output.write(chunk);remaining-=len(chunk)
        check('truncation_rejected',cli(bao,instance,work,'restore',truncated,True,expected_error=400))
        check('truncation_unchanged',capacity()['generation'] == generation)
        check('oversize_rejected',raw_rejection(instance,f'Content-Length: {ARCHIVE_LIMIT+1}\r\n') == 413)
        check('oversize_unchanged',capacity()['generation'] == generation)
        check('unauthorized_before_body',raw_rejection(instance,f'Content-Length: {archive.stat().st_size}\r\n', 'invalid-native-fixture-token') == 403)
        with raw_socket(instance) as tls, archive.open('rb') as source:
            tls.sendall(header(instance,'POST',framing=f'Content-Length: {archive.stat().st_size}\r\n'))
            tls.sendall(source.read(BLOCK))
        check('upload_interrupted',True)
        check('upload_slot_released',wait_idle(instance))
        check('upload_unchanged',capacity()['generation'] == generation)
        check('save_after_interrupted_upload',cli(bao,instance,work,'save',work/'after-upload.snap') == 0)
        with raw_socket(instance) as tls:
            tls.sendall(header(instance,'GET',route='snapshot'))
            response=http.client.HTTPResponse(tls);response.begin()
            check('interrupted_download_started',response.status == 200 and response.getheader('Content-Type') == 'application/gzip')
            check('interrupted_download_prefix',response.read(2) == b'\x1f\x8b')
            response.close()
        check('download_interrupted',True)
        check('download_slot_released',wait_idle(instance))
        check('download_unchanged',capacity()['generation'] == generation)
        check('save_after_interrupted_download',cli(bao,instance,work,'save',work/'after-download.snap') == 0)
        verify(changed,'changed_retained')
        check('ordinary_rollback_restored',cli(bao,instance,work,'restore',archive) == 0)
        verify(original,'ordinary_restored')
        check('ordinary_other_owner_restored',call('GET','secret/data/native-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('ordinary_later_absent',call('GET',MOUNT+'/later')[0] == 404)
        check('cli_force_restore',cli(bao,instance,work,'restore',archive,True) == 0)
        verify(original,'restored')
        check('other_owner_restored',call('GET','secret/data/native-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('later_absent',call('GET',MOUNT+'/later')[0] == 404)
        check('chunked_restore',chunked_restore(instance,archive) == 200)
        verify(original,'chunked_restored')
        old_unseal, unseal = unseal, rekey_share(call, unseal, check)
        generation = capacity()['generation']; seal_hash = file_hash(instance.root/'data'/'seal.json')
        check('rekey_old_ordinary_rejected',cli(bao,instance,work,'restore',archive,expected_error=400,
              expected_message=b'native snapshot seal identity differs'))
        check('rekey_old_ordinary_unchanged',capacity()['generation'] == generation
              and file_hash(instance.root/'data'/'seal.json') == seal_hash)
        check('rekey_old_force_rejected',cli(bao,instance,work,'restore',archive,True,expected_error=400,
              expected_message=b'cross-seal native snapshot force restore is unsupported'))
        check('rekey_old_force_unchanged',capacity()['generation'] == generation
              and file_hash(instance.root/'data'/'seal.json') == seal_hash)
        verify(original,'rekey_rejected_retained')
        rekey_archive = work/'rekey.snap'
        check('rekey_new_save',cli(bao,instance,work,'save',rekey_archive) == 0)
        rekey_meta = inspect_archive(rekey_archive)
        check('rekey_new_binding',rekey_meta['seal_identity'] != meta['seal_identity'])
        check('rekey_changed',call('PUT',MOUNT+'/bulk/0000',{'value':'after-rekey'})[0] == 204)
        check('rekey_new_restore',cli(bao,instance,work,'restore',rekey_archive) == 0)
        verify(original,'rekey_restored')
        check('spool_clean',wait_idle(instance))
        instance.stop();instance.start()
        check('old_share_rejected',instance.call('POST','sys/unseal',{'key':old_unseal})[0] == 400)
        check('restart_unsealed',instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
        verify(original,'reopened')
        check('reopened_other_owner',call('GET','secret/data/native-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('reopened_later_absent',call('GET',MOUNT+'/later')[0] == 404)
        if pg is not None:
            check('postgres_no_local_artifact_fallback', postgres_metadata_only(instance))
            instance.stop(); pg.stop(); instance.start()
            check('postgres_unavailable_unseal_rejected', instance.call('POST','sys/unseal',{'key':unseal})[0] == 503)
            check('postgres_unavailable_no_local_artifacts', postgres_metadata_only(instance))
            instance.stop(); pg.start(); instance.start()
            check('postgres_recovered_unseal', instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
            verify(original,'postgres_recovered')
        instance.stop()
        samples=[instance.token.encode(),unseal.encode(),old_unseal.encode(),*[s.encode() for s in original.sample_prefixes+changed.sample_prefixes]]
        if pg is not None: samples += [pg.manager_password.encode(), recovery_nonce.encode()]
        files=[p for p in (instance.root/'data').rglob('*') if p.is_file() and not p.is_symlink()]
        files += [instance.root/'audit.jsonl',instance.root/'server.log',*work.glob('*.snap')]
        check('plaintext_absent',all(not contains_any(p,samples) for p in files if p.exists()))
        if pg is not None:
            remote = inspect_postgres_artifacts(pg, samples)
            check('postgres_single_authoritative_manifest', remote['manifest_count'] == 1)
            check('postgres_encrypted_artifacts', remote['chunk_count'] > 0)
            check('postgres_plaintext_absent', remote['plaintext_absent'])
            observations['postgres_durable'] = remote
        check('complete',True)
    finally:
        try:
            if instance is not None: instance.stop()
        finally:
            if pg is not None: pg.stop()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--postgres-bin',type=Path,help='Fresh PostgreSQL 17 durable storage; no local fallback')
    args=parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit):parser.error('full build commit required')
    binary,output=args.binary.resolve(strict=True),args.output.absolute()
    parent=private_parent(args.work_parent);admitted=admit_output(output)
    pg_bin=args.postgres_bin.resolve(strict=True) if args.postgres_bin is not None else None
    pg_before=postgres_identity(pg_bin) if pg_bin is not None else None
    bao=verify_inputs();bao_hash=file_hash(bao)
    before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-snapshot-cli-',dir=parent))
    checks,observations,failure=[],{},None
    try:run(binary,bao,work,checks,observations,pg_bin)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary);runner_unchanged=runner_hash==file_hash(Path(__file__))
    cli_unchanged=bao_hash==file_hash(bao)
    if before!=after or not runner_unchanged or not cli_unchanged:failure='source_binary_cli_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    pg_after=postgres_identity(pg_bin) if pg_bin is not None else None
    if pg_before!=pg_after:failure='postgres_binaries_changed'
    if not complete(checks,postgres=pg_bin is not None):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-cli.v1','status':'passed' if failure is None else 'failed',
        'durable_backend':'postgresql_17' if pg_bin is not None else 'files',
        'postgres_identity':pg_before,'postgres_binaries_unchanged':pg_before==pg_after,
        'postgres_restore_profile_covered':pg_bin is not None and failure is None,
        'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'official_cli_version':'2.6.2',
        'official_cli_sha256':bao_hash,'official_cli_unchanged':cli_unchanged,
        'retained_failure_work_dir':str(work) if failure else None,'native_archive_only':True,'native_archive_version':2,
        'same_seal_ordinary_rollback_covered':failure is None,
        'rekey_seal_mismatch_rejection_covered':failure is None,
        'legacy_v1_missing_binding_rejection_covered':failure is None,
        'historical_v1_aead_archive_covered':False,
        'official_cli_transport_covered':failure is None,'transfer_above_20mib_covered':failure is None,
        'ha_restore_covered':False,'cross_seal_force_covered':False,'openbao_state_interoperability':False,
        'physical_restore_crash_covered':False,'full_openbao_compatibility':False,
        'independent_qualification':False,'production_authority':False,'synthetic_only':True}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)

if __name__=='__main__':raise SystemExit(main())
