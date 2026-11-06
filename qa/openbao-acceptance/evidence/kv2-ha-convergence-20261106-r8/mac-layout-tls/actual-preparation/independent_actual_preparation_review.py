"""Local independent review of already recovered originals; no remote action.

Private native digests are compared in memory and never emitted. No private-key
content is read. This does not start a service or validate an actual TLS socket.
"""
from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path('/tmp/heptabao-formal-kv2-layout-tls-20261106-r1')
ACTUAL = ROOT / 'actual-preparation'
STAGE = ROOT / 'stage-r2'
PRIVATE = Path('/tmp/heptabao-formal-kv2-bootstrap-20261106-r1/private-runtime')


def body(path):
    item = json.loads(path.read_text())
    while isinstance(item, dict):
        if item.get('operation') and 'result' in item:
            item = item['result']
            continue
        if isinstance(item.get('structuredContent'), dict):
            return item['structuredContent']
        if 'content' in item:
            return json.loads('\n'.join(x['text'] for x in item['content'] if x.get('type') == 'text'))
        break
    return item


def mode(info):
    value = info['mode']
    assert type(value) in (int, str)
    return value if type(value) is int else int(value, 8)


def matches(info, pin):
    version = [int(x) for x in info['version'].split(':')]
    metadata = info['metadata']
    return (version == [pin['dev'], pin['inode'], pin['bytes'], pin['mtime_ns'], pin['ctime_ns']]
            and metadata['uid'] == pin['uid'] and metadata['gid'] == pin['gid']
            and metadata['link_count'] == pin['nlink'] and mode(info) == pin['mode'])


terminal = body(STAGE / 'preparation-terminal.native.json')
streams = body(STAGE / 'preparation-streams.native.json')
final = json.loads(streams['stdout']['text'])
result_raw = (ACTUAL / 'result.public.json').read_bytes()
result = json.loads(result_raw)
assert terminal['job_id'] == '1a1b2643b65-fc05-7dde' and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
assert all(terminal[k] is False for k in ('timed_out', 'cancelled', 'automatic_retry'))
stdout = streams['stdout']['text'].encode()
assert streams['stdout']['eof'] and streams['stdout']['offset'] == 0
assert streams['stdout']['next_offset'] == len(stdout) == 3951
assert streams['stderr']['eof'] and streams['stderr']['text'] == '' and streams['stderr']['size'] == 0
assert result['status'] == final['status'] == 'prepared_not_started'
assert result['preparation_complete'] is final['preparation_complete'] is True
assert final['primary_failure_code'] is None and final['cleanup_failure_codes'] == []
assert final['deadline_fired'] is False and final['interrupted_signal'] is None
assert final['owned_directory_handles'] == final['owned_directory_handles_closed'] == 23
assert final['owned_file_handles_opened'] == final['owned_file_handles_closed'] == 35
assert final['created_layout_directories'] == 19 and final['child_processes_created'] == 0
extra = set(final) - set(result)
assert not (set(result) - set(final)) and all(final[k] == v for k, v in result.items())
for role, name in [('server', 'heptabao-server'), ('seed', 'heptabao-seed')]:
    info = body(ACTUAL / (name + '-file-info.native.json'))
    assert info['size'] == result['copied_artifacts'][role]['bytes']
    assert info['sha256'] == result['copied_artifacts'][role]['sha256']
    assert info['metadata']['uid'] == 501 and info['metadata']['gid'] == 20
    assert info['metadata']['link_count'] == 1 and mode(info) == 0o700

ca = x509.load_pem_x509_certificate((ACTUAL / 'ca.crt').read_bytes())
leaf = x509.load_pem_x509_certificate((ACTUAL / 'server.crt').read_bytes())
for cert in (ca, leaf):
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(ca=True, path_length=0)
assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(ca=False, path_length=None)
assert list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]
san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert [str(x) for x in san.get_values_for_type(x509.IPAddress)] == ['127.0.0.1']
assert san.get_values_for_type(x509.DNSName) == ['localhost'] and len(san) == 2
now = datetime.datetime.fromisoformat(result['tls']['generated_at_utc'])
assert ca.not_valid_after_utc - now == datetime.timedelta(days=3650)
assert leaf.not_valid_after_utc - now == datetime.timedelta(days=365)
assert ca.not_valid_before_utc == leaf.not_valid_before_utc == now - datetime.timedelta(seconds=300)
assert ca.public_key().curve.name == leaf.public_key().curve.name == 'secp256r1'
assert ca.public_key().public_numbers() != leaf.public_key().public_numbers()
for role, name in [('ca_certificate', 'ca.crt'), ('server_certificate', 'server.crt')]:
    raw = (ACTUAL / name).read_bytes()
    assert {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} == result['public_certificates'][role]

# Existing private evidence contains metadata/digests, not private-key bytes.
closure_raw = (PRIVATE / 'layout-tls.private.json').read_bytes()
closure = json.loads(closure_raw)
closure_native = body(PRIVATE / 'preparation-closure-file-info.native.json')
assert closure_native['size'] == len(closure_raw)
assert closure_native['sha256'] == hashlib.sha256(closure_raw).hexdigest()
assert matches(closure_native, result['private_record_identity'])
for role, name in [('ca_private_key', 'issuer-key-file-info.native.json'), ('server_private_key', 'server-key-file-info.native.json')]:
    info, pin = body(PRIVATE / name), closure['files'][role]
    assert matches(info, pin['identity']) and info['sha256'] == pin['sha256'] and info['size'] == pin['bytes']
    assert pin['identity']['uid'] == 501 and pin['identity']['gid'] == 20
    assert pin['identity']['mode'] == 0o600 and pin['identity']['nlink'] == 1
    assert info['metadata']['xattr_names'] == []
    assert info['metadata']['acl_sha256'] == hashlib.sha256(b'').hexdigest()
spec = importlib.util.spec_from_file_location('frozen_layout_review', STAGE / 'public-stage-inputs/bootstrap_layout.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
rendered = renderer.render(closure['layout'])
assert renderer.config_bytes(rendered) == (ACTUAL / 'server.json').read_bytes()
assert renderer.plist_bytes(rendered) == (ACTUAL / 'org.heptabao.kv2.plist').read_bytes()
assert closure['initial_empty_data_binding']['scope'] == 'before_init_only_not_a_permanent_initialized_inode'
report = {
    'schema': 'heptabao.independent-actual-layout-tls-review.v1', 'reviewer': 'host_evidence',
    'job_id': terminal['job_id'], 'status': 'prepared_not_started',
    'original_terminal_zero_complete_durable': True,
    'public_result_bytes': len(result_raw), 'public_result_sha256': hashlib.sha256(result_raw).hexdigest(),
    'final_stdout_bytes': len(stdout), 'final_stdout_sha256': hashlib.sha256(stdout).hexdigest(),
    'public_and_final_common_fields_exact': True, 'final_only_fields': sorted(extra),
    'created_directories': 19, 'all_original_directory_handles_retired': 23,
    'all_original_file_handles_retired': 35, 'child_process_count': 0,
    'normal_binary_copies_full_native_hash_and_metadata_verified': 2,
    'actual_public_certificates_rehashed': 2, 'actual_ca_and_leaf_signature_verified': True,
    'actual_P256_SHA256_SAN_EKU_and_exact_lifetimes_verified': True,
    'actual_config_and_uninstalled_plist_equal_frozen_renderer': True,
    'private_closure_native_identity_version_content_exact': True,
    'tls_private_keys_independent_native_metadata_and_private_pin_equal': 2,
    'private_key_bytes_read_by_this_review': False, 'private_key_or_config_content_hash_in_report': False,
    'private_keys_single_link_0600_fixed_uid_gid': True,
    'native_private_key_acl_empty_and_no_xattr_names': True,
    'initial_data_identity_is_before_init_only': True,
    'remote_jobs_or_product_actions_performed_by_this_review': False,
    'formal_kv2_qualified': False, 'actual_service_or_tls_endpoint_qualified': False,
    'cross_host_share_custody_verified': False,
}
raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
path = ACTUAL / 'HOST_EVIDENCE_ACTUAL_PREPARATION_REVIEW.public.json'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps({'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                  'private_content_hashes_suppressed': True}, sort_keys=True))
