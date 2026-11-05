#!/usr/bin/env python3
"""Package a fixed public source/schema review; never execute its controllers."""
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

WORKSPACE = Path('/workspace/scratch/d1dc83a5698d')
SOURCE_ROOT = WORKSPACE / 'formal_kv2_restore_prepare'
OUTPUT = SOURCE_ROOT / 'schema-evidence-archive-20261105-r1'
REVIEW_NAME = 'candidate-transition-review-20261105-r2.public.json'
REVIEW_SHA = '3b0420bdc396f65df6a1693f886c8b486c307d55352a08b54a9c867c262f65cb'
ROOT_REVIEW_NAME = 'root-schema-review-20261105-r2.public.json'
ROOT_REVIEW_SHA = 'd68efbbd92840efcb238e13f98b06e4970b9e6284b2c511aa0b081a418229b88'
INVENTORY_NAME = 'r10-admission-draft-r1/inventory-control-qa-r1/result.public.json'
INVENTORY_SHA = '69ecb74e9f3137bd20081f78ff68c98e4e8abc783cb4e30021590d36d6c8f642'
MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
RULES = [
    ('private_key_pem', r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    ('assigned_root_or_client_token', r'(?i)"(?:root_token|client_token)"\s*:\s*"[^"\s]{8,}"'),
    ('assigned_unseal_key_array', r'(?i)"(?:unseal_keys|unseal_keys_b64|unseal_keys_hex|recovery_keys|recovery_keys_b64|recovery_keys_hex)"\s*:\s*\[\s*"[A-Za-z0-9+/=_-]{16,}"'),
    ('vault_live_token_format', r'\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{16,}'),
]


def need(value, label):
    if not value:
        raise RuntimeError(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    def constant(_):
        raise RuntimeError('nonfinite_json_value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_original(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         'original_path_not_canonical')
    path.relative_to(SOURCE_ROOT)
    need(stat.S_ISREG(path.lstat().st_mode), 'original_not_regular')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= MAX_FILE, 'original_file_type_size_or_links')
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= MAX_FILE, 'original_read_size_cap')
            chunks.append(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        need(stamp(before) == stamp(after) == stamp(path.lstat()) and
             len(raw) == before.st_size, 'original_changed_while_reading')
        return raw, stamp(after)
    finally:
        os.close(fd)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def assert_draft(raw, name):
    values = [node.value for node in ast.parse(raw).body
              if isinstance(node, ast.Assign) and any(
                  isinstance(target, ast.Name) and target.id == 'DRAFT_ONLY'
                  for target in node.targets)]
    need(len(values) == 1 and isinstance(values[0], ast.Constant)
         and values[0].value is True, 'entry_not_closed:' + name)


def main():
    need(OUTPUT.is_dir() and OUTPUT.resolve() == OUTPUT, 'output_directory')
    review_raw, _ = read_original(SOURCE_ROOT / REVIEW_NAME)
    need(digest(review_raw) == REVIEW_SHA, 'original_review_digest')
    review = strict_json(review_raw)
    need(review['member_count'] == len(review['files']) == 48 and
         review['qualification_entries_remain_draft'] is True and
         review['actual_new_candidate_admissions'] == 0 and
         review['actual_observer_cohort_admissions'] == 0 and
         review['actual_formal_recovery_stages'] == 0, 'review_scope')
    members = [dict(row, category='fixed_48_review_member') for row in review['files']]
    members.extend([
        {'path': str(SOURCE_ROOT / REVIEW_NAME), 'sha256': REVIEW_SHA,
         'bytes': len(review_raw), 'category': 'original_48_member_index'},
        {'path': str(SOURCE_ROOT / ROOT_REVIEW_NAME), 'sha256': ROOT_REVIEW_SHA,
         'bytes': 3496, 'category': 'independent_root_source_schema_review'},
        {'path': str(SOURCE_ROOT / INVENTORY_NAME), 'sha256': INVENTORY_SHA,
         'bytes': 2389, 'category': 'original_inventory_model_control_result'},
    ])
    need(len({row['path'] for row in members}) == len(members) == 51,
         'exact_allowlist_without_duplicates')
    payloads, original_stamps, rows = {}, {}, []
    for row in members:
        path = Path(row['path'])
        relative = path.relative_to(SOURCE_ROOT).as_posix()
        need(not any(part in ('private-run', 'model', 'payloads', 'target', '.cargo')
                     for part in Path(relative).parts), 'forbidden_directory')
        need(relative.endswith(('.py', '.diff', '.md', '.public.json')),
             'non_public_suffix')
        raw, identity = read_original(path)
        need(len(raw) == row['bytes'] and digest(raw) == row['sha256'],
             'allowlisted_original_digest:' + relative)
        text = raw.decode('utf-8')
        for label, pattern in RULES:
            need(re.search(pattern, text) is None,
                 'potential_sensitive_value:' + relative + ':' + label)
        if relative.endswith('.json'):
            strict_json(raw)
        name = 'formal_kv2_restore_prepare/' + relative
        payloads[name], original_stamps[row['path']] = raw, identity
        rows.append({**row, 'archive_path': name})
    need(sum(len(raw) for raw in payloads.values()) <= MAX_TOTAL, 'total_byte_cap')
    root_review = strict_json(payloads['formal_kv2_restore_prepare/' + ROOT_REVIEW_NAME])
    need(root_review['reviewed_manifest']['sha256'] == REVIEW_SHA and
         root_review['reviewed_manifest']['members_verified'] == 48 and
         root_review['permission_to_enable_live_product_entries'] is False and
         root_review['actual_candidate_admissions'] == 0 and
         root_review['formal_dr25_executions'] == 0, 'root_review_scope')
    for entry in root_review['closed_entries']:
        name = 'formal_kv2_restore_prepare/' + Path(entry['path']).relative_to(SOURCE_ROOT).as_posix()
        need(digest(payloads[name]) == entry['sha256'], 'closed_entry_original_digest')
        assert_draft(payloads[name], name)
    inventory = strict_json(payloads['formal_kv2_restore_prepare/' + INVENTORY_NAME])
    need(inventory['required'] == inventory['passed'] == len(inventory['checks']) == 9 and
         inventory['status'] == 'passed' and
         inventory['actual_positive_executor_binding_tested'] is False and
         inventory['observer_qualification'] is False and inventory['products_started'] == 0,
         'inventory_model_control_scope')
    manifest = {
        'schema': 'heptabao.draft-schema-review-public-archive.v1',
        'status': 'public_control_sources_and_review_only',
        'original_member_index_sha256': REVIEW_SHA,
        'independent_root_review_sha256': ROOT_REVIEW_SHA,
        'member_count': len(rows), 'member_bytes': sum(row['bytes'] for row in rows),
        'members': sorted(rows, key=lambda row: row['archive_path']),
        'archive_policy': {
            'selection': 'Exactly the 48 pinned originals, their original index, independent root review, and the original inventory9 result; no recursive collection.',
            'regular_files_only': True, 'no_symlinks_or_hardlinks': True,
            'format': 'USTAR', 'gzip_mtime': 0, 'gzip_filename': '',
            'canonical_tar_mode': '0600', 'canonical_uid_gid_mtime': 0,
            'sensitive_rules': [{'name': name, 'regex': pattern} for name, pattern in RULES],
            'sensitive_rules_origin': {
                'path': str(WORKSPACE / 'r5_pocket_evidence_prepare/pack_r5_public_evidence.py'),
                'sha256': '7e06b11d7f0f403d9aad1e0086dae47d55b3604d55f5af75ea129b276bbdd556',
                'scope': 'The same four patterns; no new product or semantic control tests.'},
            'sensitive_matches': [], 'universal_secret_absence_claimed': False,
            'referenced_paths_are_not_automatically_collected': True,
            'generated_model_payload_directories_included': False,
            'private_keys_credentials_snapshots_binaries_included': False,
        },
        'scope': {
            'entrypoints_remain_draft': True,
            'actual_thirteen_origin_positive_admission': False,
            'actual_new_candidate_admissions': 0,
            'actual_observer_executor_admissions': 0,
            'formal_recovery_25_executions': 0,
            'inventory_control_is_model_only': True,
            'source_lock_control_is_actual_receipt_shape_with_modeled_lock_inputs': True,
            'initial_source_lock_harness_failure_preserved': True,
            'this_archive_runs_tests': False, 'this_archive_starts_products': False,
            'product_or_existing_results_modified': False,
            'formal_kv2_qualified': False, 'physical_ha_qualified': False,
            'authbus_qualified': False, 'replacement_qualified': False,
        },
    }
    manifest_raw = canonical(manifest)
    all_payloads = {**payloads, 'MANIFEST.public.json': manifest_raw}
    def assemble():
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=6) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, raw in sorted(all_payloads.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = len(raw), 0o600
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ''
                    archive.addfile(item, io.BytesIO(raw))
        return stream.getvalue()
    archive_raw = assemble()
    need(archive_raw == assemble(), 'deterministic_archive_bytes')
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:gz') as archive:
        entries = archive.getmembers()
        need(len(entries) == len(all_payloads) == 52 and
             [entry.name for entry in entries] == sorted(all_payloads), 'archive_exact_inventory')
        for entry in entries:
            need(entry.isfile() and not entry.pax_headers and entry.mode == 0o600 and
                 entry.uid == entry.gid == entry.mtime == 0 and not entry.uname and not entry.gname,
                 'archive_noncanonical_entry')
            need(archive.extractfile(entry).read() == all_payloads[entry.name],
                 'archive_roundtrip_original_bytes')
    for row in rows:
        raw, identity = read_original(row['path'])
        need(identity == original_stamps[row['path']] and digest(raw) == row['sha256'] and
             len(raw) == row['bytes'], 'original_changed_after_archive')
    manifest_path = OUTPUT / 'MANIFEST.public.json'
    archive_path = OUTPUT / 'draft-admission-and-recovery-schema-review.tar.gz'
    write_new(manifest_path, manifest_raw)
    write_new(archive_path, archive_raw)
    need(manifest_path.read_bytes() == manifest_raw and archive_path.read_bytes() == archive_raw,
         'durable_output_readback')
    receipt = {
        'schema': 'heptabao.draft-schema-review-public-archive-receipt.v1',
        'status': 'archived', 'source_members': len(rows),
        'tar_members_including_manifest': len(all_payloads),
        'original_48_members_preserved': True,
        'original_members_unchanged_after_archive': True,
        'every_member_readback_verified': True,
        'deterministic_archive_bytes_verified': True,
        'sensitive_pattern_matches': 0,
        'new_product_or_semantic_control_tests_run': False,
        'new_products_started': False,
        'all_four_entrypoints_still_draft': True,
        'actual_thirteen_origin_positive_admission': False,
        'formal_recovery_25_executions': 0,
        'replacement_qualified': False,
        'archive': {'path': str(archive_path), 'sha256': digest(archive_raw), 'bytes': len(archive_raw)},
        'manifest': {'path': str(manifest_path), 'sha256': digest(manifest_raw), 'bytes': len(manifest_raw)},
        'archiver': {'path': str(Path(__file__).resolve()),
                     'sha256': digest(Path(__file__).read_bytes())},
    }
    receipt_path = OUTPUT / 'result.public.json'
    receipt_raw = canonical(receipt)
    write_new(receipt_path, receipt_raw)
    directory_fd = os.open(OUTPUT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(json.dumps({'status': 'archived', 'result': str(receipt_path),
                      'result_sha256': digest(receipt_raw), 'archive': receipt['archive'],
                      'manifest': receipt['manifest'], 'tar_members': 52}), flush=True)


if __name__ == '__main__':
    main()
