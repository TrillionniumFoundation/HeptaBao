#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import stat
import sys
import time
import types
from pathlib import Path

HERE = Path(__file__).absolute().parent
SCHEMA = 'heptabao.authbus.real-gateway-kv-canary.r1'
SMOKE_SHA = 'ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971'
OWNED_SHA = '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'
KNOWN_BINARIES = {
    'r10': '7f1f030720123900c2d58dfd0f59825a06c8ee5bd6beec424f65c77f0ae075a3',
    'r11': 'c97421b30a3915f823ec74a5955631d96750c530b310b2e656ec73f43ab07c11',
}

def read_public(path, expected_sha, cap=65536):
    if not re.fullmatch('[0-9a-f]{64}', expected_sha or ''):
        raise RuntimeError('controller_expected_sha')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
            raise RuntimeError('controller_public_file_shape')
        raw = bytearray()
        while len(raw) <= cap:
            part = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        ident = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if ident(before) != ident(after) or len(raw) != before.st_size:
            raise RuntimeError('controller_public_file_changed')
        raw = bytes(raw)
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise RuntimeError('controller_public_file_sha')
        return raw
    finally:
        os.close(fd)

def load_public(path, expected_sha, name):
    raw = read_public(path, expected_sha)
    module = types.ModuleType(name)
    module.__file__ = str(Path(path).absolute())
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module

def private_write(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            size = os.write(fd, view)
            if size <= 0:
                raise RuntimeError('controller_private_write')
            view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)

def stream_copy_pinned_binary(source, target, expected_sha, budget, need):
    """Copy a <= 1 GiB regular binary using <= 1 MiB buffers and retained dirfds."""
    source, target = Path(source), Path(target)
    maximum = 1 << 30
    chunk_size = 1 << 20
    need(re.fullmatch('[0-9a-f]{64}', expected_sha or '') is not None,
         'binary_expected_sha_shape')
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def directory_identity(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)

    def file_identity(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    def close_chain(chain):
        for row in reversed(chain):
            os.close(row[0])

    def open_parent(path):
        need(path.is_absolute() and '..' not in path.parts and path.name not in ('', '.', '..'),
             'binary_absolute_nofollow_path')
        chain = []
        try:
            fd = os.open('/', dir_flags)
            chain.append((fd, None, None, directory_identity(os.fstat(fd))))
            for name in path.parts[1:-1]:
                budget.left()
                parent = chain[-1][0]
                child = os.open(name, dir_flags, dir_fd=parent)
                try:
                    child_stat = os.fstat(child)
                    need(stat.S_ISDIR(child_stat.st_mode), 'binary_parent_not_directory')
                    child_identity = directory_identity(child_stat)
                except BaseException:
                    os.close(child)
                    raise
                chain.append((child, parent, name, child_identity))
            return chain, chain[-1][0], path.name
        except BaseException:
            close_chain(chain)
            raise

    def recheck_chain(chain):
        for fd, parent, name, original in chain:
            budget.left()
            need(directory_identity(os.fstat(fd)) == original, 'binary_parent_descriptor_changed')
            linked = os.stat('/', follow_symlinks=False) if parent is None else os.stat(
                name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(linked.st_mode) and directory_identity(linked) == original,
                 'binary_parent_path_changed')

    def recheck_file(fd, parent, name, original, code):
        budget.left()
        need(file_identity(os.fstat(fd)) == original, code)
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(linked.st_mode) and file_identity(linked) == original, code)

    source_chain = target_chain = []
    source_fd = target_fd = None
    try:
        source_chain, source_parent, source_name = open_parent(source)
        target_chain, target_parent, target_name = open_parent(target)
        target_parent_stat = os.fstat(target_parent)
        need(target_parent_stat.st_uid == os.geteuid()
             and stat.S_IMODE(target_parent_stat.st_mode) == 0o700,
             'binary_target_parent_not_private_owner_directory')
        source_fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=source_parent)
        source_stat = os.fstat(source_fd)
        need(stat.S_ISREG(source_stat.st_mode) and 0 < source_stat.st_size <= maximum,
             'binary_source_regular_size_bound')
        source_identity = file_identity(source_stat)
        recheck_chain(source_chain)
        recheck_chain(target_chain)
        recheck_file(source_fd, source_parent, source_name, source_identity,
                     'binary_source_initial_path_binding')
        target_fd = os.open(target_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o700, dir_fd=target_parent)
        os.fchmod(target_fd, 0o700)
        copied = 0
        source_hash = hashlib.sha256()
        while True:
            budget.left()
            chunk = os.read(source_fd, chunk_size)
            if not chunk:
                break
            copied += len(chunk)
            need(copied <= source_stat.st_size and copied <= maximum, 'binary_source_grew_during_copy')
            source_hash.update(chunk)
            view = memoryview(chunk)
            while view:
                budget.left()
                written = os.write(target_fd, view)
                need(written > 0, 'binary_copy_short_write')
                view = view[written:]
        need(copied == source_stat.st_size, 'binary_source_bytecount')
        source_digest = source_hash.hexdigest()
        need(hmac.compare_digest(source_digest, expected_sha), 'binary_source_sha_mismatch')
        recheck_file(source_fd, source_parent, source_name, source_identity, 'binary_source_changed_after_copy')
        budget.left()
        os.fsync(target_fd)
        os.fsync(target_parent)
        budget.left()
        target_stat = os.fstat(target_fd)
        need(stat.S_ISREG(target_stat.st_mode) and target_stat.st_uid == os.geteuid()
             and target_stat.st_nlink == 1 and stat.S_IMODE(target_stat.st_mode) == 0o700
             and target_stat.st_size == copied, 'binary_target_shape_after_fsync')
        target_identity = file_identity(target_stat)
        recheck_file(target_fd, target_parent, target_name, target_identity,
                     'binary_target_path_after_fsync')
        os.lseek(target_fd, 0, os.SEEK_SET)
        verified = 0
        target_hash = hashlib.sha256()
        view = chunk = None
        while True:
            budget.left()
            chunk = os.read(target_fd, chunk_size)
            if not chunk:
                break
            verified += len(chunk)
            need(verified <= copied, 'binary_target_grew_during_readback')
            target_hash.update(chunk)
        target_digest = target_hash.hexdigest()
        need(verified == copied and hmac.compare_digest(target_digest, expected_sha),
             'binary_target_readback_mismatch')
        recheck_file(target_fd, target_parent, target_name, target_identity,
                     'binary_target_changed_during_readback')
        recheck_file(source_fd, source_parent, source_name, source_identity,
                     'binary_source_changed_during_readback')
        recheck_chain(source_chain)
        recheck_chain(target_chain)
        budget.left()
        return {
            'bytes': copied, 'maximumBytes': maximum, 'maximumReadChunkBytes': chunk_size,
            'sourceSha256': source_digest, 'targetReadbackSha256': target_digest,
            'sourceDescriptorAndPathStable': True, 'targetDescriptorAndPathStable': True,
            'allParentDirectoryBindingsStable': True,
            'sourceBeforeAfterFstatMatched': True, 'targetReadbackBeforeAfterFstatMatched': True,
            'targetFileAndParentFsyncCompleted': True, 'targetMode': '0o700',
            'targetOwnerUid': target_stat.st_uid, 'targetNlink': target_stat.st_nlink,
        }
    finally:
        for fd in (target_fd, source_fd):
            if fd is not None:
                os.close(fd)
        close_chain(target_chain)
        close_chain(source_chain)

def run(args):
    deadline_ns = time.monotonic_ns() + 330_000_000_000
    report = {
        'schema': SCHEMA, 'ok': False, 'host': args.host, 'phase': 'public-code-binding',
        'candidateLabel': args.candidate_label, 'candidateBinarySha256': args.binary_sha256,
        'productionCutoverQualified': False, 'productionClientRestartQualified': False,
        'productionServiceRollbackQualified': False, 'productionOpenClawBackendConfigured': False,
        'productionGatewayRestartRequested': False, 'originalSdkSecretResolverChanged': False,
        'pairingOrApprovalMutationRequested': False, 'cacheMetadataRepairPerformed': False,
        'privateMaterialExported': False, 'consumerReceipts': [],
    }
    W = P = I = ctx = scope_wrapper = diagnostic = owner = native = api = None
    work_created = False
    workflow_finished = False
    work = Path(args.work_root)
    private_values = []
    native_pids = []
    try:
        read_public(Path(__file__).absolute(), args.controller_sha256)
        worker_path = HERE / 'gateway_heptabao_consumer_r1.py'
        worker_raw = read_public(worker_path, args.worker_sha256)
        W = load_public(worker_path, args.worker_sha256, '_gateway_kv_consumer_controller_r1')
        P, I, scope_wrapper, binding_code = W.load_contracts(args.host, args.pocket4_wrapper_sha256)
        need = I.need
        need(KNOWN_BINARIES.get(args.candidate_label) == args.binary_sha256, 'controller_candidate_release_binding')
        budget = I.B.Budget((deadline_ns - time.monotonic_ns()) / 1e9)
        ctx = I.Context(args.host, budget)
        report['phase'] = 'trusted-source-and-existing-device'
        ctx.load_source(report)
        need(work.is_absolute() and work.parent == ctx.home and '..' not in work.parts
             and re.fullmatch(r'heptabao-authbus-gateway-kv-r1-[A-Za-z0-9_.-]+', work.name) is not None,
             'controller_fresh_work_root_binding')
        inspected_file = ctx.anchor(Path(args.inspection_receipt), private=False, cap=32768)
        need(I.sha(inspected_file.raw) == args.inspection_sha256, 'controller_inspection_sha')
        inspected = I.parse_json(inspected_file.raw)
        need(isinstance(inspected, dict) and inspected.get('schema') == I.SCHEMA
             and inspected.get('host') == args.host and inspected.get('ok') is True
             and inspected.get('existingTokenReusableForNormalCli') is True
             and inspected.get('readInputsAndFileIdentitiesUnchanged') is True, 'controller_inspection_qualification')
        if scope_wrapper is not None:
            diagnostic = scope_wrapper.verify_diagnostic(I, budget)
            need(inspected.get('scopeDiagnosticReceiptSha256') == binding_code['scopeDiagnosticReceiptSha256']
                 and inspected.get('scopeBindingCodeSha256') == binding_code['scopeBindingCodeSha256'],
                 'controller_scope_diagnostic_binding')
        initial_device_report = {}
        initial_device = I.inspect_devices(ctx, initial_device_report)
        initial_binding = initial_device['binding']
        need(initial_binding == inspected.get('binding')
             and initial_device_report.get('existingTokenReusableForNormalCli') is True,
             'controller_initial_device_binding')
        listener_before = I.B.listener_binding(budget)
        ctx.recheck()
        P.release_mutable_snapshots(ctx, initial_device)
        os.umask(0o077)
        work.mkdir(mode=0o700, parents=False, exist_ok=False)
        work_created = True
        report['workRoot'] = str(work)
        report['controllerSha256'] = args.controller_sha256
        report['workerSha256'] = args.worker_sha256
        report['scopeBinding'] = binding_code
        report['publicHelperSha256'] = {'smoke.py': SMOKE_SHA, 'owned_process.py': OWNED_SHA}
        report['phase'] = 'pinned-binary-stream-copy'
        binary_copy = work / 'heptabao-server'
        report['binaryCopyProof'] = stream_copy_pinned_binary(
            Path(args.binary), binary_copy, args.binary_sha256, budget, need)
        O = W.load_public(Path(args.owned_helper), OWNED_SHA, 'owned_process')
        S = W.load_public(Path(args.smoke_helper), SMOKE_SHA, '_gateway_kv_smoke_r1')
        need(S.owned_process is O, 'controller_owned_helper_import_binding')
        owner = O.Owner(work, deadline_ns=deadline_ns, profile='authbus_gateway_kv_r1')
        with O.activated(owner):
            try:
                report['phase'] = 'private-native-fixture'
                fixture = work / 'fixture'
                native = S.Instance(binary_copy, fixture)
                config_file = ctx.anchor(fixture / 'server.json', private=True, cap=32768)
                ca_file = ctx.anchor(fixture / 'ca.crt', private=False, cap=65536)
                cert_file = ctx.anchor(fixture / 'tls.crt', private=False, cap=65536)
                config = I.parse_json(config_file.raw)
                need(config.get('listen') == '127.0.0.1:' + str(native.port)
                     and Path(config.get('data_dir', '')) == fixture / 'data'
                     and Path(config.get('tls_cert_file', '')) == fixture / 'tls.crt',
                     'controller_fixture_configuration')
                leaf_der = ssl.PEM_cert_to_DER_cert(cert_file.raw.decode('ascii'))
                leaf_sha = hashlib.sha256(leaf_der).hexdigest()
                api = W.PinnedApi(native.address, ca_file.raw, leaf_sha, budget)
                report['candidateCaCertificateSha256'] = I.sha(ca_file.raw)
                report['candidateTlsLeafDerSha256'] = leaf_sha
                report['fixtureConfigSha256'] = I.sha(config_file.raw)

                def start_native():
                    need(native.process is None, 'controller_native_already_running')
                    number = len(native_pids) + 1
                    native.log = open(fixture / ('server-' + str(number) + '.log'), 'xb')
                    native.process = O.popen(
                        [str(binary_copy), '--fixture-native-v6-service', '--config', str(fixture / 'server.json')],
                        stdout=native.log, stderr=native.log, close_fds=True,
                        label='gateway.native.' + str(number), action='KILL', stop_timeout=5,
                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                    native_pids.append(native.process.pid)
                    startup_end = min(time.monotonic() + 10, time.monotonic() + owner.remaining())
                    while time.monotonic() < startup_end:
                        budget.left()
                        need(native.process.poll() is None, 'controller_native_exited_before_health')
                        try:
                            status, _ = api.call('GET', 'sys/health')
                            if status in (200, 501, 503):
                                return
                        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
                            pass
                        time.sleep(min(0.05, budget.left()))
                    need(False, 'controller_native_health_timeout')

                def expect_call(status_expected, method, path, value=None, token=None, code='controller_api_status'):
                    status, data = api.call(method, path, value, token)
                    need(status == status_expected, code)
                    return data

                start_native()
                initialized = expect_call(200, 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1},
                                          code='controller_init')
                root_token = I.token_text(initialized.get('root_token'))
                keys = initialized.get('keys_base64')
                need(isinstance(keys, list) and len(keys) == 1, 'controller_unseal_key_shape')
                unseal_key = I.token_text(keys[0])
                ctx.private_values.extend([root_token, unseal_key])
                private_values.extend([root_token, unseal_key])
                private_write(work / 'bootstrap.private.json', W.canonical(initialized))
                unsealed = expect_call(200, 'POST', 'sys/unseal', {'key': unseal_key}, code='controller_unseal')
                need(unsealed.get('sealed') is False, 'controller_unseal_state')
                expect_call(204, 'POST', 'sys/mounts/secret', {'type': 'kv', 'options': {'version': '2'}}, root_token,
                            'controller_kv2_mount')
                expect_call(204, 'POST', 'sys/internal/native-v6/activate', {}, root_token, 'controller_native_activate')
                capacity = expect_call(200, 'GET', 'sys/internal/capacity', token=root_token, code='controller_native_capacity')
                need(isinstance(capacity.get('data'), dict) and capacity['data'].get('native_kv2_reader_format') == 2,
                     'controller_native_reader_format')
                expect_call(204, 'POST', 'sys/auth/approle', {'type': 'approle'}, root_token, 'controller_approle_enable')
                kv_path = 'secret/data/gateway-canary/source'
                common = '\n'.join([
                    'path "auth/token/lookup-self" { capabilities = ["read"] }',
                    'path "auth/token/renew-self" { capabilities = ["update"] }',
                    'path "auth/token/revoke-self" { capabilities = ["update"] }',
                ])
                roles = {}
                for kind, capabilities in (('reader', '["read"]'), ('writer', '["create", "update", "read"]')):
                    role_name = 'gateway-canary-' + kind
                    policy = 'path "' + kv_path + '" { capabilities = ' + capabilities + ' }\n' + common
                    expect_call(204, 'PUT', 'sys/policies/acl/' + role_name, {'policy': policy}, root_token,
                                'controller_policy_create')
                    expect_call(204, 'POST', 'auth/approle/role/' + role_name,
                                {'token_policies': [role_name], 'token_ttl': '300s', 'token_max_ttl': '600s',
                                 'secret_id_num_uses': 0, 'secret_id_ttl': '600s', 'bind_secret_id': True,
                                 'token_no_default_policy': True}, root_token, 'controller_role_create')
                    role_info = expect_call(200, 'GET', 'auth/approle/role/' + role_name + '/role-id',
                                            token=root_token, code='controller_role_id')
                    secret_info = expect_call(200, 'POST', 'auth/approle/role/' + role_name + '/secret-id', {},
                                              root_token, 'controller_secret_id')
                    need(isinstance(role_info.get('data'), dict) and isinstance(secret_info.get('data'), dict),
                         'controller_role_credential_shape')
                    role_id = I.token_text(role_info['data'].get('role_id'))
                    secret_id = I.token_text(secret_info['data'].get('secret_id'))
                    ctx.private_values.extend([role_id, secret_id])
                    roles[kind] = {'name': role_name, 'role_id': role_id, 'secret_id': secret_id}
                    private_write(work / (kind + '-role.private.json'), W.canonical(roles[kind]))
                writer_login = expect_call(200, 'POST', 'auth/approle/login',
                                          {k: roles['writer'][k] for k in ('role_id', 'secret_id')},
                                          code='controller_writer_login')
                need(isinstance(writer_login.get('auth'), dict), 'controller_writer_auth_shape')
                writer_bearer = I.token_text(writer_login['auth'].get('client_token'))
                ctx.private_values.append(writer_bearer)
                private_write(work / 'writer-bearer.private.json', W.canonical({'token': writer_bearer}))
                expect_call(403, 'GET', 'secret/data/gateway-canary/denied', token=writer_bearer,
                            code='controller_writer_policy_boundary')

                def publish(token, cas, expected_version):
                    result = expect_call(200, 'POST', kv_path,
                                         {'data': {'token': token}, 'options': {'cas': cas}}, writer_bearer,
                                         'controller_writer_kv_publication')
                    need(isinstance(result.get('data'), dict)
                         and result['data'].get('version') == expected_version, 'controller_writer_kv_version')

                seen_consumer_pids = set()
                verified_worker_program = '__file__ = ' + repr(str(worker_path)) + '\n' + worker_raw.decode('utf-8')

                def consume(phase, expected_version, accepted, read_version=0):
                    need(owner.remaining() > 35, 'controller_consumer_cleanup_reserve')
                    report['phase'] = 'consumer-' + phase
                    request = {
                        'schema': W.REQUEST_SCHEMA, 'host': args.host, 'deadlineMonotonicNs': deadline_ns,
                        'candidateAddress': native.address, 'candidateCaPath': str(fixture / 'ca.crt'),
                        'candidateLeafSha256': leaf_sha, 'workRoot': str(work),
                        'roleId': roles['reader']['role_id'], 'secretId': roles['reader']['secret_id'],
                        'kvPath': kv_path, 'expectedVersion': expected_version, 'readVersion': read_version,
                        'expectAccepted': accepted, 'inspectionReceiptPath': str(Path(args.inspection_receipt).absolute()),
                        'inspectionReceiptSha256': args.inspection_sha256,
                        'pocket4WrapperSha256': args.pocket4_wrapper_sha256, 'phase': phase,
                    }
                    completed = O.run(
                        ['/usr/bin/python3', '-I', '-c', verified_worker_program, '--consumer'],
                        label='gateway.consumer.' + phase, check=False, input=W.canonical(request),
                        capture_output=True, timeout=30, cwd=str(HERE),
                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True)
                    need(len(completed.stdout) <= 131072 and len(completed.stderr) <= 16384,
                         'controller_consumer_output_bound')
                    need(not completed.stderr, 'controller_consumer_stderr_not_empty')
                    result = W.strict_json(completed.stdout)
                    need(isinstance(result, dict) and result.get('schema') == W.WORKER_SCHEMA,
                         'controller_consumer_receipt_shape')
                    private_write(work / ('consumer-' + phase + '.public.json'), W.canonical(result) + b'\n')
                    report['consumerReceipts'].append(result)
                    need(completed.returncode == 0 and result.get('ok') is True, 'controller_consumer_failed')
                    need(result.get('host') == args.host and result.get('phase') == phase
                         and result.get('candidateBackendUsed') is True
                         and result.get('backendVersion') == expected_version
                         and result.get('backendCredentialMatchesTrustedSource') is accepted
                         and result.get('realConsumerProtectedReadQualified') is accepted
                         and result.get('backendWrongCredentialRejected') is (not accepted),
                         'controller_consumer_actual_backend_binding')
                    need(result.get('sourceAndExistingDeviceBinding') == initial_binding
                         and result.get('productionGatewayListenerUnchanged') is True
                         and result.get('existingDeviceTokenAndApprovalGrantUnchanged') is True
                         and result.get('candidateTlsLeafPinnedBeforeSendingCredentials') is True
                         and result.get('readerWriteDenied') is True
                         and result.get('readerBearerRevoked') is True
                         and result.get('revokedBearerReadDenied') is True, 'controller_consumer_security_evidence')
                    pid = result.get('pid')
                    need(type(pid) is int and pid > 1 and pid not in seen_consumer_pids,
                         'controller_consumer_new_process_identity')
                    seen_consumer_pids.add(pid)
                    need(result.get('backendCredentialSha256') == I.sha((ctx.token if accepted else wrong).encode('ascii')),
                         'controller_consumer_credential_digest')

                report['phase'] = 'writer-v1'
                publish(ctx.token, 0, 1)
                wrong = secrets.token_hex(24)
                while hmac.compare_digest(wrong, ctx.token) or hmac.compare_digest(wrong, initial_device['cached_token']):
                    wrong = secrets.token_hex(24)
                ctx.private_values.append(wrong)
                consume('initial', 1, True)
                consume('fresh-client', 1, True)
                report['phase'] = 'fixture-cold-restart'
                need(native.process is not None and native.process.poll() is None, 'controller_cold_restart_original_handle')
                native.stop()
                start_native()
                unsealed = expect_call(200, 'POST', 'sys/unseal', {'key': unseal_key}, code='controller_cold_unseal')
                need(unsealed.get('sealed') is False, 'controller_cold_unseal_state')
                consume('cold-restart', 1, True)
                report['phase'] = 'writer-v2-negative'
                publish(wrong, 1, 2)
                consume('negative-v2', 2, False)
                consume('rollback-v1', 1, True, read_version=1)
                report['phase'] = 'writer-v3-restore'
                publish(ctx.token, 2, 3)
                consume('restored-v3', 3, True)
                report['phase'] = 'temporary-approle-revocation'
                expect_call(204, 'POST', 'auth/token/revoke-self', {}, writer_bearer, 'controller_writer_revoke')
                expect_call(403, 'GET', kv_path, token=writer_bearer, code='controller_writer_revocation_enforced')
                for kind in ('reader', 'writer'):
                    role = roles[kind]
                    expect_call(204, 'POST', 'auth/approle/role/' + role['name'] + '/secret-id/destroy',
                                {'secret_id': role['secret_id']}, root_token, 'controller_secret_id_destroy')
                    expect_call(400, 'POST', 'auth/approle/login',
                                {k: role[k] for k in ('role_id', 'secret_id')}, code='controller_destroyed_secret_id_rejected')
                report['phase'] = 'source-and-gateway-final-binding'
                final_device_report = {}
                final_device = I.inspect_devices(ctx, final_device_report)
                need(final_device['binding'] == initial_binding
                     and final_device_report.get('existingTokenReusableForNormalCli') is True,
                     'controller_final_source_or_device_changed')
                ctx.recheck()
                if diagnostic is not None:
                    diagnostic.recheck()
                need(I.B.listener_binding(budget) == listener_before, 'controller_production_gateway_listener_changed')
                need(len(native_pids) == 2 and native_pids[0] != native_pids[1]
                     and len(seen_consumer_pids) == 6, 'controller_expected_process_counts')
                report.update({
                    'actualTrustedGatewayCredentialPublishedByWriterAppRole': True,
                    'actualConsumerReadsThroughReaderAppRole': 5,
                    'actualWrongBackendCredentialRejected': 1,
                    'newConsumerProcessRestartQualified': True,
                    'isolatedFixtureColdRestartQualified': True,
                    'credentialVersionRollbackQualified': True,
                    'currentCredentialRestoredAsVersion3': True,
                    'writerBearerRevokedAndDenied': True,
                    'bothRoleSecretIdsDestroyedAndRejected': True,
                    'bootstrapRootAndRecoveryMaterialRetainedOwnerOnly': True,
                    'sourceConfigSecretIdentityAndCacheUnchanged': True,
                    'existingDeviceTokenAndApprovalGrantUnchanged': True,
                    'productionGatewayListenerUnchanged': True,
                    'workerExecutedFromFrozenVerifiedPublicBytes': True,
                    'everyConsumerRunWaitedForExit': True,
                    'nativeFixtureOriginalPids': list(native_pids),
                    'consumerRecordedPids': sorted(seen_consumer_pids),
                    'sourceAndExistingDeviceBinding': initial_binding,
                    'candidateTlsLeafPinnedBeforeSendingCredentials': api.peer_pin_checked_before_credentials,
                    'fixtureApiCalls': api.calls,
                })
                workflow_finished = True
            finally:
                if native is not None and native.process is not None:
                    native.stop()
        need(workflow_finished and owner.receipt.get('passed_process_method') is True,
             'controller_original_process_method_failed')
        report['ownedProcessReceipt'] = owner.receipt
        report['ownedProcessReceiptCanonicalSha256'] = I.sha(W.canonical(owner.receipt))
        report['ownedProcessMethodPassed'] = True
        report['allOwnedFixtureAndConsumerProcessesRetired'] = True
        report['phase'] = 'complete'
        report['completedAtUnixMs'] = int(time.time() * 1000)
        report['ok'] = True
    except BaseException as exc:
        report['error'] = str(exc) if I is not None and isinstance(exc, I.Refused) else 'controller_failure'
        report['exceptionClass'] = type(exc).__name__
        if owner is not None and isinstance(getattr(owner, 'receipt', None), dict):
            report['ownedProcessMethodPassed'] = owner.receipt.get('passed_process_method') is True
            report['ownedProcessReceipt'] = owner.receipt
    finally:
        if diagnostic is not None:
            diagnostic.close()
        if ctx is not None:
            try:
                I.public_guard(report, ctx.private_values + private_values)
            except BaseException:
                report = {'schema': SCHEMA, 'host': args.host, 'ok': False,
                          'error': 'controller_public_redaction_guard', 'privateMaterialExported': False,
                          'productionCutoverQualified': False}
            ctx.close()
        if work_created:
            try:
                private_write(work / 'public-receipt.json',
                              json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n')
            except BaseException:
                report['ok'] = False
                report['receiptWriteFailed'] = True
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', choices=('rog', 'pocket4'), required=True)
    parser.add_argument('--work-root', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--candidate-label', choices=('r10', 'r11'), required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--smoke-helper', required=True)
    parser.add_argument('--owned-helper', required=True)
    parser.add_argument('--inspection-receipt', required=True)
    parser.add_argument('--inspection-sha256', required=True)
    parser.add_argument('--worker-sha256', required=True)
    parser.add_argument('--controller-sha256', required=True)
    parser.add_argument('--pocket4-wrapper-sha256')
    args = parser.parse_args()
    report = run(args)
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
    return 0 if report.get('ok') is True else 2

if __name__ == '__main__':
    raise SystemExit(main())
