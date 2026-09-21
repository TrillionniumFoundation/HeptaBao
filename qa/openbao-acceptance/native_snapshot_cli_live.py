#!/usr/bin/env python3
"""Pinned OpenBao CLI transports candidate-native snapshots on a local TLS server.

Native HBB2 state is deliberately not an OpenBao state.bin. Force is tested only
with this instance's barrier. No HA restore or cross-seal compatibility claim.
All temporary files require an explicit private SSD/guest work parent.
"""
from __future__ import annotations
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
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
    'archive_contract', 'rollback_rejected', 'rollback_unchanged', 'sealed_tamper_rejected',
    'sealed_tamper_unchanged', 'truncation_rejected', 'truncation_unchanged',
    'oversize_rejected', 'oversize_unchanged', 'unauthorized_before_body',
    'upload_interrupted', 'upload_slot_released', 'upload_unchanged',
    'download_interrupted', 'download_slot_released', 'download_unchanged',
    'all_changed_retained', 'cli_force_restore', 'all_restored', 'other_owner_restored',
    'later_absent', 'chunked_restore', 'all_chunked_restored', 'restart_unsealed',
    'all_reopened', 'reopened_other_owner', 'reopened_later_absent', 'spool_clean',
    'plaintext_absent', 'complete'})


def complete(checks):
    if not isinstance(checks, list) or not checks: return False
    if any(not isinstance(r, dict) or set(r) != {'case', 'passed'} or r['passed'] is not True
           or not isinstance(r['case'], str) or not re.fullmatch(r'[a-z0-9_]{1,120}', r['case']) for r in checks):
        return False
    names = [r['case'] for r in checks]
    return len(names) == len(set(names)) and names[-1] == 'complete' and REQUIRED.issubset(names)


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


def inspect_archive(path):
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
    if (meta.get('format') != 'heptabao-native-snapshot-v1'
            or meta.get('state_format') != 'heptabao-encrypted-backup-v1/HBB2'
            or meta.get('state_bytes') != state_size or magic != b'HBB2'
            or small['SHA256SUMS'] != expected or not small['SHA256SUMS.sealed']):
        raise ValueError('archive_contract')
    return {'state_bytes':state_size, 'generation':meta['generation'], 'members':names}


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


def cli(binary, instance, work, command, path, force=False, expected_error=None):
    args = [str(binary), 'operator', 'raft', 'snapshot', command]
    if force: args.append('-force')
    args.append(str(path))
    # Never expose stdout/stderr, token environment, request bodies or paths in receipts.
    result = subprocess.run(args, env=cli_environment(instance, work), cwd=work,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=90)
    if expected_error is not None:
        # Inspect only the CLI's HTTP status diagnostic; never publish stderr.
        statuses = re.findall(rb'Code: ([0-9]{3})(?:[.\s]|$)', result.stderr)
        return result.returncode != 0 and len(result.stderr) <= 65536 and statuses == [str(expected_error).encode()]
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


def run(binary, bao, work, checks, observations):
    from kv1_record_scale_live import Dataset, MOUNT
    from remote_jwks_live import Instance
    instance = None
    def check(name, condition):
        checks.append({'case':name, 'passed':condition is True})
        if condition is not True: raise ScenarioFailure(name)
    try:
        instance = Instance(binary, work/'instance')
        config_path = instance.root/'server.json'; config = json.loads(config_path.read_text())
        config.update(lifecycle_interval_seconds=0, outbound_endpoints=[], timeout_seconds=60)
        private_write(config_path, config, replace=True); instance.start()
        status, initialized = instance.call('POST', 'sys/init', {'secret_shares':1,'secret_threshold':1})
        check('initialized', status == 200)
        instance.token, unseal = initialized['root_token'], initialized['keys_base64'][0]
        check('unsealed', instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
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
        check('rollback_rejected',cli(bao,instance,work,'restore',archive,expected_error=400))
        check('rollback_unchanged',capacity()['generation'] == generation)
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
        check('cli_force_restore',cli(bao,instance,work,'restore',archive,True) == 0)
        verify(original,'restored')
        check('other_owner_restored',call('GET','secret/data/native-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('later_absent',call('GET',MOUNT+'/later')[0] == 404)
        check('chunked_restore',chunked_restore(instance,archive) == 200)
        verify(original,'chunked_restored')
        check('spool_clean',wait_idle(instance))
        instance.stop();instance.start()
        check('restart_unsealed',instance.call('POST','sys/unseal',{'key':unseal})[0] == 200)
        verify(original,'reopened')
        check('reopened_other_owner',call('GET','secret/data/native-control')[1].get('data',{}).get('data') == {'value':'before'})
        check('reopened_later_absent',call('GET',MOUNT+'/later')[0] == 404)
        instance.stop()
        samples=[instance.token.encode(),unseal.encode(),*[s.encode() for s in original.sample_prefixes+changed.sample_prefixes]]
        files=[p for p in (instance.root/'data').rglob('*') if p.is_file() and not p.is_symlink()]
        files += [instance.root/'audit.jsonl',instance.root/'server.log',archive]
        check('plaintext_absent',all(not contains_any(p,samples) for p in files if p.exists()))
        check('complete',True)
    finally:
        if instance is not None: instance.stop()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit):parser.error('full build commit required')
    binary,output=args.binary.resolve(strict=True),args.output.absolute()
    parent=private_parent(args.work_parent);admitted=admit_output(output)
    bao=verify_inputs();bao_hash=file_hash(bao)
    before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-snapshot-cli-',dir=parent))
    checks,observations,failure=[],{},None
    try:run(binary,bao,work,checks,observations)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if r['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary);runner_unchanged=runner_hash==file_hash(Path(__file__))
    cli_unchanged=bao_hash==file_hash(bao)
    if before!=after or not runner_unchanged or not cli_unchanged:failure='source_binary_cli_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-cli.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'official_cli_version':'2.6.2',
        'official_cli_sha256':bao_hash,'official_cli_unchanged':cli_unchanged,
        'retained_failure_work_dir':str(work) if failure else None,'native_archive_only':True,
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
