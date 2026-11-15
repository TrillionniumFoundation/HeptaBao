#!/usr/bin/env python3
"""Owned real HTTPS corruption and SIGKILL recovery probe, separate from 1332 trial."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument('--helper', type=Path, required=True)
ap.add_argument('--helper-sha256', required=True)
ap.add_argument('--binary', type=Path, required=True)
ap.add_argument('--source-repo', type=Path, required=True)
ap.add_argument('--build-custody', type=Path, required=True)
ap.add_argument('--build-custody-sha256', required=True)
ap.add_argument('--frozen-test-manifest', type=Path, required=True)
ap.add_argument('--frozen-test-manifest-sha256', required=True)
ap.add_argument('--evidence', type=Path, required=True)
ap.add_argument('--port', type=int, default=31111)
args = ap.parse_args()
os.umask(0o077)
assert 1024 <= args.port <= 65535
assert hashlib.sha256(args.helper.read_bytes()).hexdigest() == args.helper_sha256
spec = importlib.util.spec_from_file_location('native_point_owned_helper', args.helper)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
provenance = helper.admit(args)
root = args.evidence.resolve()
assert root != args.source_repo.resolve() and args.source_repo.resolve() not in root.parents
root.mkdir(mode=0o700)
rows, processes, resource_cycles = [], [], []
process = sampler = server_log = None
token = unseal = None
failure = None
start_source = helper.git_state(args.source_repo)

def canonical(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

def check(condition, name, **details):
    rows.append(dict(case=name, passed=bool(condition), **details))
    if not condition:
        raise RuntimeError(name)

def request(name, method, path, body=None, expected=200, anonymous=False):
    headers = {'Content-Type': 'application/json'}
    if token and not anonymous:
        headers['X-Vault-Token'] = token
    req = urllib.request.Request('https://127.0.0.1:%d/v1/' % args.port + path,
                                 data=None if body is None else canonical(body), method=method, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, context=context, timeout=20) as response:
            status, data = response.status, response.read()
    except urllib.error.HTTPError as response:
        status, data = response.code, response.read()
    check(status == expected, name, status=status, expected=expected,
          elapsed_ms=int((time.monotonic()-started)*1000), response_bytes=len(data))
    parsed = json.loads(data) if data else None
    check(parsed is None or isinstance(parsed, dict), name+'-json')
    return parsed

def capacity(name):
    value = request(name, 'GET', 'sys/internal/capacity')['data']
    for field in ('native_kv2_payload_blocks_opened', 'native_kv2_payload_ciphertext_bytes_read',
                  'native_kv2_payload_plaintext_bytes_opened', 'native_kv2_payload_positioned_read_calls',
                  'native_kv2_payload_positioned_bytes_returned', 'native_kv2_payload_positioned_read_failures'):
        check(type(value.get(field)) is int and value[field] >= 0, name+'-'+field, observed=value.get(field))
    check(value.get('native_kv2_reader_format') == 2, name+'-reader-floor2')
    return value

def no_payload_io(value):
    return all(value['native_kv2_payload_'+field] == 0 for field in (
        'blocks_opened', 'ciphertext_bytes_read', 'plaintext_bytes_opened',
        'positioned_read_calls', 'positioned_bytes_returned', 'positioned_read_failures'))

def blobs():
    return {path for path in (root/'data').rglob('*.hbo')
            if stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size >= 256*1024}

def journals():
    return {str(p.relative_to(root/'data')): helper.file_sha(p)
            for p in (root/'data').rglob('journal.hbj')}

def start(cycle):
    global process, sampler, server_log
    check(helper.git_state(args.source_repo) == start_source, 'cycle%d-source-custody'%cycle)
    check(helper.file_sha(args.binary) == provenance['binary_sha256'], 'cycle%d-binary-custody'%cycle)
    server_log = (root/('server-%d.log'%cycle)).open('wb')
    process = subprocess.Popen([str(args.binary.resolve()), '--config', str(root/'server.json'),
                                '--fixture-native-v6-service'], cwd='/', stdout=server_log,
                               stderr=server_log, start_new_session=True)
    record = dict(cycle=cycle, pid=process.pid, started_unix_ns=time.time_ns())
    processes.append(record)
    sampler = helper.OwnedProcessResources(process, cycle, root/'data')
    sampler.start()
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        if not sampler.alive():
            raise RuntimeError('owned process exited before HTTPS readiness')
        req = urllib.request.Request('https://127.0.0.1:%d/v1/sys/health'%args.port)
        try:
            try:
                with urllib.request.urlopen(req, context=context, timeout=1) as response:
                    status, data = response.status, response.read()
            except urllib.error.HTTPError as response:
                status, data = response.code, response.read()
            health = json.loads(data)
            check(status == (501 if cycle == 1 else 503) and health['sealed'] is True,
                  'cycle%d-sealed-HTTPS-readiness'%cycle, status=status)
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError('owned HTTPS readiness timed out')

def stop(sig=signal.SIGTERM):
    global process, sampler, server_log
    if process is None:
        return
    sampler.capture('before-owned-stop')
    with sampler.ownership_lock:
        check(process.poll() is None, 'cycle%d-owned-child-alive-before-stop'%processes[-1]['cycle'])
        process.send_signal(sig)
        process.wait(timeout=20)
        record=processes[-1]
        record.update(stop_signal=signal.Signals(sig).name, exit_code=process.returncode,
                      actual_process_closed=process.poll() is not None, closed_unix_ns=time.time_ns())
        check(process.returncode == -signal.SIGKILL if sig == signal.SIGKILL
              else process.returncode in (0,-signal.SIGTERM), 'cycle%d-actual-stop-exit'%record['cycle'],
              exit_code=process.returncode)
    sampler.stop()
    resource_cycles.append(sampler.summary())
    process = sampler = None
    server_log.close(); server_log=None

try:
    conf=root/'certificate.conf'
    conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n')
    with (root/'certificate-generation.log').open('wb') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(conf),
                        '-keyout',str(root/'server.key'),'-out',str(root/'server.crt')],check=True,stdout=log,stderr=log)
    context=ssl.create_default_context(cafile=str(root/'server.crt'))
    config=dict(listen='127.0.0.1:%d'%args.port,data_dir=str(root/'data'),audit_file=str(root/'audit.private.jsonl'),
                tls_cert_file=str(root/'server.crt'),tls_key_file=str(root/'server.key'),lifecycle_interval_seconds=0,max_connections=8)
    (root/'server.json').write_bytes(canonical(config))
    check('timeout_seconds' not in config, 'original15s-server-budget-no-override')
    start(1)
    initialized=request('initialize','POST','sys/init',dict(secret_shares=1,secret_threshold=1),anonymous=True)
    token,unseal=initialized['root_token'],initialized['keys_base64'][0]
    (root/'credentials.private.json').write_bytes(canonical(dict(root_token=token,unseal_key=unseal)))
    request('unseal-v5','POST','sys/unseal',dict(key=unseal),anonymous=True)
    request('mount-kv2','POST','sys/mounts/secret',dict(type='kv',options=dict(version='2')),expected=204)
    source_value=dict(value='bound-source-survives-target-corruption')
    request('source-preflight','POST','secret/data/source',dict(data=source_value))
    request('activate-floor2','POST','sys/internal/native-v6/activate',{},expected=204)
    pre=capacity('before-target')
    old=blobs()
    target_value=dict(payload=hashlib.shake_256(b'point-negative-owned-target').hexdigest(400000),version=1)
    request('target-write','POST','secret/data/target',dict(data=target_value,options=dict(cas=0)))
    added=blobs()-old
    check(len(added)>=3,'actual-new-target-ciphertext-blocks',new_full_ciphertext_blocks=len(added))
    chosen=sorted(added)[0]
    check(chosen.resolve().is_relative_to((root/'data').resolve()),'corruption-owned-target-only')
    expected_sha=hashlib.sha256(canonical(target_value)).hexdigest()
    read=request('initial-target-read','GET','secret/data/target?version=1')['data']['data']
    check(hashlib.sha256(canonical(read)).hexdigest()==expected_sha,'initial-target-exact-json')
    stop(signal.SIGKILL)
    start(2)
    request('SIGKILL-cold-unseal','POST','sys/unseal',dict(key=unseal),anonymous=True)
    cold=capacity('SIGKILL-cold-capacity')
    check(no_payload_io(cold),
          'SIGKILL-cold-no-payload-read-or-open')
    read=request('SIGKILL-cold-target-read','GET','secret/data/target?version=1')['data']['data']
    check(hashlib.sha256(canonical(read)).hexdigest()==expected_sha,'SIGKILL-cold-target-exact-json')
    stop()
    original=chosen.read_bytes(); original_sha=hashlib.sha256(original).hexdigest()
    (root/'original-ciphertext.private').write_bytes(original)
    damaged=bytearray(original); damaged[len(damaged)//2]^=1
    with chosen.open('r+b') as stream:
        stream.write(damaged); stream.flush(); os.fsync(stream.fileno())
    check(helper.file_sha(chosen)!=original_sha,'actual-referenced-ciphertext-body-corrupted')
    start(3)
    request('corrupt-cold-unseal','POST','sys/unseal',dict(key=unseal),anonymous=True)
    pre=capacity('corrupt-before-get')
    check(no_payload_io(pre),
          'corrupt-cold-metadata-open-does-not-pretend-payload-authentication')
    journal_before=journals(); check(bool(journal_before),'actual-journal-generation-proxy-present')
    error=request('corrupt-selected-GET','GET','secret/data/target?version=1',expected=503)
    check(not error.get('data') and not error.get('auth') and not error.get('wrap_info'),
          'corrupt-selected-GET-no-partial-secret-or-authority')
    post=capacity('corrupt-after-get')
    check(post['native_kv2_payload_ciphertext_bytes_read']>pre['native_kv2_payload_ciphertext_bytes_read']
          and post['native_kv2_payload_positioned_read_calls']>pre['native_kv2_payload_positioned_read_calls']
          and post['native_kv2_payload_positioned_bytes_returned']>pre['native_kv2_payload_positioned_bytes_returned'],
          'corrupt-selected-GET-records-real-ciphertext-read')
    check(post['native_kv2_payload_blocks_opened']>=pre['native_kv2_payload_blocks_opened'],
          'corrupt-selected-GET-success-only-open-counter')
    check(journals()==journal_before,'corrupt-selected-GET-no-durable-journal-advance')
    metadata=request('corrupt-target-metadata','GET','secret/metadata/target')['data']
    check(metadata['current_version']==1,'corrupt-selected-GET-no-logical-generation-advance')
    read=request('unrelated-source-after-corruption','GET','secret/data/source')['data']['data']
    check(read==source_value,'unrelated-source-exact-after-selected-corruption')
    stop()
    with chosen.open('r+b') as stream:
        stream.write(original); stream.flush(); os.fsync(stream.fileno())
    check(helper.file_sha(chosen)==original_sha,'owned-original-ciphertext-restored-exactly')
    start(4)
    request('restored-cold-unseal','POST','sys/unseal',dict(key=unseal),anonymous=True)
    cold=capacity('restored-cold-capacity')
    check(no_payload_io(cold),'restored-cold-no-payload-io')
    read=request('restored-selected-GET','GET','secret/data/target?version=1')['data']['data']
    check(hashlib.sha256(canonical(read)).hexdigest()==expected_sha,'restored-selected-GET-exact-json')
    stop()
except Exception as error:
    failure=str(error) if isinstance(error,RuntimeError) else type(error).__name__
finally:
    if process is not None:
        try:
            stop()
        except Exception as error:
            failure=failure or ('owned-cleanup-'+type(error).__name__)
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=10)
            if sampler is not None:
                sampler.stop()
            if server_log is not None:
                server_log.close()
    after=helper.git_state(args.source_repo)
    complete=(failure is None and len(processes)==4 and len(resource_cycles)==4
              and all(p.get('actual_process_closed') for p in processes)
              and after==start_source and all(row['passed'] for row in rows))
    receipt=dict(schema='heptabao.point-negative-https.v1',passed=complete,failure=failure,
                 provenance=provenance,source_before=start_source,source_after=after,
                 helper_sha256=helper.file_sha(args.helper),runner_sha256=helper.file_sha(Path(__file__)),
                 actual_real_https=True,original_server_budget_seconds=15,server_budget_changed=False,
                 actual_sigkill_cold_recovery=complete,actual_selected_corruption_negative=complete,
                 actor_late_expiry_qualified=False,unknown_commit_qualified=False,
                 full_replacement_qualified=False,executed_cases=len(rows),passed_cases=sum(r['passed'] for r in rows),
                 cases=rows,processes=processes,resource_cycles=resource_cycles,
                 resource_scope='observed-owned-FD-RSS-samples; not an absolute resource bound',
                 private_fixture_retained=True)
    (root/'receipt.json').write_text(json.dumps(receipt,indent=2))
    print(json.dumps(dict(passed=complete,failure=failure,executed_cases=len(rows),receipt=str(root/'receipt.json'))))
raise SystemExit(0 if complete else 1)
