#!/usr/bin/env python3
"""Independent original-byte and launch/native audit; no target or author module is executed."""
from pathlib import Path
import base64
import hashlib
import json
import stat

HERE = Path(__file__).resolve().parent
FILES = json.loads((HERE / 'base-input.json').read_text())
checks = []
JOB = '1a1ad5ffad0-fc05-599a'

def ck(name, value):
    if not value:
        raise AssertionError(name)
    checks.append(name)

def raw(path):
    return FILES[path].encode('utf-8')

def obj(path):
    return json.loads(FILES[path])

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pin(data):
    return {'bytes': len(data), 'sha256': sha(data), 'blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}

def unwrap(path, native_path):
    sdk = obj(path)
    ck(path + ' original success flag', sdk.get('isError') is False)
    ck(path + ' one original text', len(sdk['content']) == 1 and sdk['content'][0]['type'] == 'text')
    text = sdk['content'][0]['text']
    ck(path + ' native byte exact', text.encode() == raw(native_path))
    return json.loads(text)

journal = obj('reference/recovery-journal.public.json')
for path, blob in journal['known_blobs'].items():
    ck('journal leaf ' + path, pin(raw(path))['blob'] == blob)
request = obj('launch/request.original.json')
go = obj('reference/GO.original.json')
intent = obj('launch/execution-intent.public.json')
ck('exact root-authorized request', request == go['request'] == intent['request_value'])
rp = pin(raw('launch/request.original.json'))
ck('request pinned in root GO', all(go['exact_request'][k] == rp[k] for k in rp))
ck('request pinned in external intent', all(intent['request'][k] == rp[k] for k in rp))
ck('intent original once/no old UNKNOWN erasure', intent['one_original_submit_only'] is True and intent['old_relay_unknown_preserved'] is True)
ack = unwrap('launch/ack.original.sdk.json', 'launch/ack.original.json')
job = ack['job']
ck('actual same job', job['id'] == JOB)
for key in ('host', 'executable', 'args', 'cwd', 'idempotency_key'):
    ck('ACK typed field ' + key, job[key] == request[key])
ck('ACK empty env', job['env_keys'] == [])
ck('ACK successful original launch', job['launch_state'] == 'launched' and job['launch_error'] is None and ack['launch']['ok'] is True and ack['launch']['backend'] == 'systemd' and ack['reused'] is False)
# Canonical bytes are recovered original evidence, not a guessed deployed API.
canonical_raw = raw('launch/typed-request-canonical.original.json')
canonical = json.loads(canonical_raw)
ck('original typed digest exact', sha(canonical_raw) == job['request_digest'] == go['typed_request_sha256'] == intent['typed_request_sha256'])
ck('lossless native fingerprint', str(job['request_fingerprint']) == go['expected_native_fingerprint_decimal'] == intent['expected_native_fingerprint_decimal'])
for key in ('host', 'executable', 'args', 'cwd', 'timeout_seconds'):
    ck('original canonical typed field ' + key, canonical[key] == request[key])
ck('original canonical absent optionals remain null/empty', canonical['env'] == {} and all(canonical[k] is None for k in ('cpu_quota_percent', 'memory_max_bytes', 'nice', 'stdin')))
ck('parser error and correction preserved', obj('launch/first-parser-failure.public.json')['Runtime_replayed'] is False and obj('launch/parser-correction.public.json')['actual_job_id'] == JOB)

natives = {}
for label in ('authority0', 'authority1', 'streams0', 'result-info', 'result-body0', 'summary-info', 'summary-body0', 'summary-body1'):
    pp = 'observations/' + label + '/payload.original.json'
    np = 'observations/' + label + '/native.original.json'
    payload = obj(pp)
    ck(label + ' native payload complete', payload['resultType'] == 'complete')
    natives[label] = unwrap(pp, np)
ck('earlier running state kept distinct', natives['authority0']['state'] == 'running' and natives['authority0']['job_id'] == JOB)
auth = natives['authority1']
ck('terminal authority belongs to same job', auth['job_id'] == JOB)
ck('known terminal0 full durable confirmed', auth['exit_code'] == 0 and auth['state'] == 'succeeded' and auth['output_complete'] is True and auth['output_durable'] is True and auth['terminal_publication_confirmed'] is True)
ck('terminal no timeout/cancel/automatic retry', all(auth[k] is False for k in ('timed_out', 'cancelled', 'automatic_retry')))
streams = natives['streams0']
ck('whole streams same job', streams['job_id'] == JOB)
for name in ('stdout', 'stderr'):
    r = streams[name]
    data = bytes.fromhex(r['bytes_hex'])
    ck(name + ' original bytes/text exact', data == r['text'].encode() == raw('actual/' + name + '.original.txt'))
    ck(name + ' complete original cursor', r['offset'] == 0 and r['next_offset'] == r['size'] == len(data) and r['eof'] is True)
    ck(name + ' agrees terminal log counts/closure', auth['log_bytes'][name]['seen'] == auth['log_bytes'][name]['stored'] == len(data) and auth['log_errors'][name] is None and auth['log_synced'][name] is True and auth['log_truncated'][name] is False)
stdout = json.loads(raw('actual/stdout.original.txt'))
result_raw = raw('actual/result.public.json')
ck('stdout result content address', stdout['bytes'] == len(result_raw) and stdout['sha256'] == sha(result_raw))

infos = {}
for label in ('result', 'summary'):
    info = natives[label + '-info']
    ck(label + ' fixed public path', info['path'] == next(r['path'] for r in go['bounded_original_observation']['public_files'] if r['id'] == label))
    v = info['version'].split(':')
    ck(label + ' five-part exact decimal version', len(v) == 5 and all(x.isdecimal() for x in v) and int(v[2]) == info['size'])
    m = info['metadata']
    ck(label + ' actual uid/gid/mode/single-link', m['uid'] == m['gid'] == 1000 and m['link_count'] == 1 and m['mode'] == info['mode'] == 0o600)
    full9 = [v[0], v[1], str(m['uid']), str(m['gid']), str(stat.S_IFREG | info['mode']), str(m['link_count']), str(info['size']), v[3], v[4]]
    infos[label] = {'path': info['path'], 'bytes': info['size'], 'sha256': info['sha256'], 'version': info['version'], 'full9_decimal': full9}

def body(label, info, expected_offset, expected_limit):
    n = natives[label]
    data = base64.b64decode(n['data_base64'], validate=True)
    ck(label + ' fixed version/path/size', n['version'] == info['version'] and n['path'] == info['path'] and n['size'] == info['bytes'])
    ck(label + ' original offset/limit boundary', n['offset'] == expected_offset and len(data) == expected_limit and n['next_offset'] == expected_offset + expected_limit)
    ck(label + ' exact EOF', n['eof'] is (n['next_offset'] == info['bytes']))
    ck(label + ' chunk SHA', sha(data) == n['chunk_sha256'])
    return data

r = body('result-body0', infos['result'], 0, 1124)
ck('whole result original bytes/info SHA', r == result_raw and len(r) == infos['result']['bytes'] and sha(r) == infos['result']['sha256'])
s0 = body('summary-body0', infos['summary'], 0, 65536)
s1 = body('summary-body1', infos['summary'], 65536, 25390)
summary = s0 + s1
ck('whole summary two original chunks/info SHA', summary == raw('actual/summary.public.json') and len(summary) == infos['summary']['bytes'] == 90926 and sha(summary) == infos['summary']['sha256'])
result = json.loads(result_raw)
ck('result names exact complete summary bytes/SHA', result['summary_bytes'] == len(summary) and result['summary_sha256'] == sha(summary))
ck('two public bodies within original bound', len(result_raw) + len(summary) <= go['bounded_original_observation']['maximum_public_body_bytes_combined'])

out = {'schema': 'heptabao.x230-full34-independent-original-base-peer.v1', 'status': 'PASS_AVAILABLE_LAUNCH_AND_NATIVE_BYTES_OBSERVER_CHAIN_PENDING',
       'job_id': JOB, 'checks_count': len(checks), 'checks': checks, 'inputs_count': len(FILES),
       'launch': pin(raw('launch/ack.original.sdk.json')), 'authority': pin(raw('observations/authority1/native.original.json')),
       'result': pin(result_raw), 'summary': pin(summary), 'actual_infos': infos,
       'body_bytes': len(result_raw) + len(summary), 'body_chunks': 3,
       'unverified_original_observer_links': 'At this phase the original immutable operation-page chains and missing early call references are pending; original native bytes alone do not close those observer chains.',
       'Runtime_calls': 0, 'author_verifier_executed': False, 'product_cases_executed': 0,
       'product_semantics_reviewed': False, 'no_new_business_dispatch': True}
(HERE / 'base-result.public.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out, sort_keys=True))
