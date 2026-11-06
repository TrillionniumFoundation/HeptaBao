"""Pure construction of the two explicitly admitted source launch bindings.

No file/process/network I/O occurs here. A binding is a private expectation,
not evidence that init, descriptor custody, launchd, or TLS actually succeeded.
The caller must hold the original FDs and retain the corresponding real action.
"""
from copy import deepcopy
from pathlib import PurePosixPath
import re
import stat

SERVICE = '/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1'
KEY_ROOT = '/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/service-authority-current-20261106-r1'
FILE_FIELDS = {'dev', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns', 'file_type'}
DIR_FIELDS = {'path', 'dev', 'inode', 'uid', 'gid', 'mode'}
BINDING_FIELDS = {'schema', 'state', 'manager', 'roots', 'files', 'data_pin', 'seal_file', 'normal_config'}
GUARD_BYTES = 18573
GUARD_SHA256 = '2884f17e6629e7f5bebcce067e100e8402c73bc3f709e13cd411a32bf52f88b3'


class RefusedBinding(ValueError):
    pass


def need(value, code):
    if not value:
        raise RefusedBinding(code)


def path(value):
    need(type(value) is str and 1 < len(value) <= 4096 and value.startswith('/')
         and not value.endswith('/') and str(PurePosixPath(value)) == value
         and all(part not in ('', '.', '..') for part in value[1:].split('/'))
         and all(32 <= ord(c) < 127 for c in value), 'canonical_binding_path')
    return value


def directory(value, *, expected_path, private=True):
    need(type(value) is dict and DIR_FIELDS <= set(value), 'directory_binding_fields')
    result = {key: value[key] for key in DIR_FIELDS}
    need(path(result['path']) == expected_path
         and all(type(result[key]) is int for key in DIR_FIELDS - {'path'}),
         'exact_directory_role_path_and_integer_identity')
    need(result['dev'] >= 0 and result['inode'] > 0, 'directory_device_inode')
    if private:
        need(result['uid'] == 501 and result['gid'] == 20 and result['mode'] == 0o700,
             'private_directory_owner_and_mode')
    return result


def file_pin(value, *, expected_path=None, private=True):
    need(type(value) is dict and {'path', 'bytes', 'sha256', 'identity'} <= set(value),
         'file_binding_fields')
    identity = value['identity']
    need(type(identity) is dict and FILE_FIELDS <= set(identity), 'complete_file_identity')
    identity = {key: identity[key] for key in FILE_FIELDS}
    need(all(type(v) is int for v in identity.values()) and identity['file_type'] == stat.S_IFREG
         and identity['nlink'] == 1 and identity['inode'] > 0 and identity['dev'] >= 0,
         'regular_original_file_identity')
    need(type(value['bytes']) is int and 0 < value['bytes'] == identity['bytes']
         and type(value['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', value['sha256']),
         'complete_file_content_binding')
    location = path(value['path'])
    need(expected_path is None or location == expected_path, 'exact_file_role_path')
    need(not identity['mode'] & 0o022, 'file_not_group_or_world_writable')
    if private:
        need(identity['uid'] == 501 and identity['gid'] == 20 and identity['mode'] in (0o600, 0o700),
             'private_file_owner_and_mode')
    return {'path': location, 'bytes': value['bytes'], 'sha256': value['sha256'], 'identity': identity}


def build_initial_binding(preparation_private, guard_copied_file_pin, volume_pins):
    prep = preparation_private
    need(type(prep) is dict and prep.get('schema') == 'heptabao.normal-kv2-layout-tls.private.v1'
         and prep.get('status') == 'prepared_not_started', 'actual_preparation_shape_required')
    need(all(prep.get(k) is False for k in ('service_started', 'root_token_or_unseal_share_created',
         'initialization_nonce_created', 'cross_host_share_custody_verified', 'formal_kv2_qualified')),
         'preparation_does_not_grant_service_or_key_custody')
    need(prep['source_bindings']['commit'] == '4bde9aee03fcd27c59e13607e529b1cee594b249'
         and prep['source_bindings']['tree'] == 'f08493a23f8ea0637073651231865ea9607b790e',
         'actual_normal_product_source')
    need(type(volume_pins) is dict and set(volume_pins) == {'t5', 'internal'}, 'two_actual_volume_pins')
    roots = {
        'service': directory(prep['roots']['service'], expected_path=SERVICE),
        'key': directory(prep['roots']['key'], expected_path=KEY_ROOT),
        'admissions': directory(prep['directories']['authority_manager-admissions'],
                                expected_path=KEY_ROOT + '/manager-admissions'),
        't5': directory(volume_pins['t5'], expected_path='/Volumes/T5', private=False),
        'internal': directory(volume_pins['internal'], expected_path='/System/Volumes/Data', private=False),
    }
    need(roots['service']['dev'] == roots['t5']['dev'] and roots['key']['dev'] == roots['internal']['dev']
         and roots['service']['dev'] != roots['key']['dev'], 'actual_data_key_filesystems_distinct')
    roles = {'server': ('server', SERVICE + '/runtime/heptabao-server'),
             'config': ('server_config', SERVICE + '/config/server.json'),
             'ca_certificate': ('ca_certificate', SERVICE + '/tls/ca.crt'),
             'server_certificate': ('server_certificate', SERVICE + '/tls/server.crt'),
             'server_private_key': ('server_private_key', KEY_ROOT + '/tls/server.key')}
    files = {role: file_pin(prep['files'][source], expected_path=expected)
             for role, (source, expected) in roles.items()}
    files['guard'] = file_pin(guard_copied_file_pin, expected_path=SERVICE + '/manager/launch_guard.py')
    need(files['guard']['bytes'] == GUARD_BYTES and files['guard']['sha256'] == GUARD_SHA256,
         'reviewed_guard_copied_exactly')
    files['python'] = file_pin(prep['source_bindings']['python'], private=False)
    need(files['python']['bytes'] == 34640 and files['python']['sha256'] ==
         'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13', 'qualified_python_content')
    need(files['server']['bytes'] == 92359328 and files['server']['sha256'] ==
         '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
         and files['server']['identity']['mode'] == 0o700, 'qualified_normal_server_copy')
    data = directory(prep['directories']['service_data'], expected_path=SERVICE + '/data')
    need(data == directory(prep['initial_empty_data_binding']['identity'], expected_path=SERVICE + '/data')
         and prep['initial_empty_data_binding']['scope'] == 'before_init_only_not_a_permanent_initialized_inode',
         'initial_empty_binding_scope_only')
    config = deepcopy(prep['rendered']['server_config'])
    need(config == {'ui': False, 'disable_unauthed_rekey_endpoints': True, 'listen': '127.0.0.1:18240',
         'data_dir': SERVICE + '/data', 'storage': {'native_v6_file': {'path': SERVICE + '/data'}},
         'audit_file': SERVICE + '/audit/audit.jsonl', 'tls_cert_file': files['server_certificate']['path'],
         'tls_key_file': files['server_private_key']['path'], 'tls_min_version': 'tls12', 'tls_max_version': 'tls13',
         'max_connections': 16, 'timeout_seconds': 15, 'outbound_endpoints': []}, 'exact_normal_file_configuration')
    return {'schema': 'heptabao.normal-kv2-launch-binding.private.v1', 'state': 'initial_empty',
            'manager': {'domain': 'gui/501', 'label': 'org.heptabao.kv2', 'uid': 501, 'gid': 20},
            'roots': roots, 'files': files, 'data_pin': data, 'seal_file': None, 'normal_config': config}


def build_initialized_binding(initial, new_data_pin, seal_file_pin):
    need(type(initial) is dict and set(initial) == BINDING_FIELDS
         and initial['schema'] == 'heptabao.normal-kv2-launch-binding.private.v1'
         and initial['state'] == 'initial_empty' and initial['seal_file'] is None,
         'single_initial_to_initialized_transition')
    before = directory(initial['data_pin'], expected_path=SERVICE + '/data')
    after = directory(new_data_pin, expected_path=SERVICE + '/data')
    need(before['dev'] == after['dev'] and before['inode'] != after['inode'],
         'actual_init_published_new_data_directory')
    seal = file_pin(seal_file_pin, expected_path=SERVICE + '/data/seal.json')
    need(seal['identity']['dev'] == after['dev'] and seal['identity']['mode'] == 0o600
         and seal['bytes'] <= 16384, 'original_initialized_seal_file')
    result = deepcopy(initial)
    result.update(state='initialized', data_pin=after, seal_file=seal)
    return result
