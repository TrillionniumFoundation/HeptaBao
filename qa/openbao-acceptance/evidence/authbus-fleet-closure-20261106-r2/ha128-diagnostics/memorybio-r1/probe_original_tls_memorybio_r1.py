#!/usr/bin/env python3
"""Inspect the failed HA fixture's TLS identity with no network or children.

This uses Python/OpenSSL at both ends. It cannot qualify Rust TLS, LAN access,
the HA workload, a credential source, production cutover or the old failed run.
The one pre-existing synthetic private key is read only by SSL load_cert_chain;
its bytes and digest are never read into or published by this Python program.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import ssl
import stat
import sys
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
WORK = BASE / 'native-ha-official-history-4bde9-authbus-r1'
NODE = WORK / 'node-1'
CA = WORK / 'ca.crt'
LEAF = NODE / 'tls.crt'
KEY = NODE / 'tls.key'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PUBLIC_PINS = {
    CA: (1192, '90031a0f48ad7c8d5d603ce9c517ca61fd8ca57d12ddd67608f0d7c1fddbb34b'),
    LEAF: (1277, '2e3938207ae080055ded642675a1d2053a3b9c4be80d08ed60690c45d57d1215'),
    PYTHON: (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
}
NAMES = ('192.168.0.13', 'node-1.heptabao.synthetic')


class Refused(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def identity(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def check_deadline(until):
    need(time.monotonic() < until, 'memorybio_total_deadline')


def safe_error(error, phase):
    out = {'type': type(error).__name__, 'phase': phase}
    if isinstance(error, Refused):
        out['code'] = str(error)
    if isinstance(error, ssl.SSLError):
        reason = getattr(error, 'reason', None)
        if isinstance(reason, str) and re.fullmatch(r'[A-Z0-9_]{1,96}', reason):
            out['sslReason'] = reason
        code = getattr(error, 'verify_code', None)
        if type(code) is int:
            out['verifyCode'] = code
    if isinstance(error, OSError) and type(error.errno) is int:
        out['errno'] = error.errno
    return out


def memorybio_case(client_context, server_context, server_name, expected_der, until):
    """Two in-memory TLS peers; no socket or fd is created by this function."""
    check_deadline(until)
    need(client_context.verify_mode == ssl.CERT_REQUIRED and client_context.check_hostname,
         'original_strict_client_context_required')
    row = {'serverName': server_name, 'passed': False,
           'clientVerifyFlags': int(client_context.verify_flags),
           'clientCheckHostname': client_context.check_hostname,
           'clientCertificateRequired': client_context.verify_mode == ssl.CERT_REQUIRED,
           'networkOpened': False, 'rustTlsExercised': False}
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_side=False,
                                     server_hostname=server_name)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    total = 0
    phase = 'handshake'

    def transfer():
        nonlocal total
        check_deadline(until)
        moved = 0
        for outgoing, incoming in ((client_out, server_in), (server_out, client_in)):
            while outgoing.pending:
                check_deadline(until)
                chunk = outgoing.read(min(outgoing.pending, 65536))
                total += len(chunk)
                need(total <= 262144, 'memorybio_ciphertext_bound')
                incoming.write(chunk)
                moved += len(chunk)
        return moved

    try:
        done = [False, False]
        for iteration in range(64):
            check_deadline(until)
            for i, peer in enumerate((client, server)):
                if done[i]:
                    continue
                phase = 'client_handshake' if i == 0 else 'server_handshake'
                try:
                    peer.do_handshake()
                    done[i] = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            moved = transfer()
            if all(done):
                break
            need(moved > 0, 'memorybio_handshake_no_progress')
        need(all(done), 'memorybio_handshake_iteration_bound')
        phase = 'peer_leaf_verification'
        need(client.getpeercert(binary_form=True) == expected_der,
             'original_leaf_der_mismatch')
        phase = 'bounded_application_record_round_trip'
        request = b'heptabao-synthetic-memorybio-request'
        response = b'heptabao-synthetic-memorybio-response'
        need(client.write(request) == len(request), 'complete_memorybio_request_write')
        transfer()
        need(server.read(1024) == request, 'complete_memorybio_request_read')
        need(server.write(response) == len(response), 'complete_memorybio_response_write')
        transfer()
        need(client.read(1024) == response, 'complete_memorybio_response_read')
        row.update(passed=True, handshakeCompleted=True,
                   peerLeafMatchesOriginal=True, applicationRecordRoundTrip=True,
                   tlsVersion=client.version(), selectedAlpn=client.selected_alpn_protocol(),
                   handshakeIterations=iteration + 1)
    except BaseException as error:
        row['error'] = safe_error(error, phase)
    finally:
        row['ciphertextBytes'] = total
        # These are memory objects, not OS handles or a network transport.
        del client, server, client_in, client_out, server_in, server_out
    return row


def run():
    started = time.monotonic()
    until = started + 10
    report = {
        'schema': 'heptabao.ha-original-fixture-memorybio-probe.r1', 'ok': False,
        'originalFailedJob': '1a1b29efcd8-fc05-7ef9',
        'originalFailureReclassified': False, 'networkOpened': False,
        'childProcesses': 0, 'serviceActions': 0, 'productExecuted': False,
        'credentialDatabaseContentsRead': False, 'privateKeyValuePublished': False,
        'privateKeyDigestPublished': False, 'rustTlsQualified': False,
        'lanQualified': False, 'haQualified': False, 'productionChanged': False,
        'cases': [],
    }
    files = []
    directories = []
    phase = 'source_admission'
    try:
        need(sys.platform == 'darwin' and platform.machine() == 'arm64'
             and os.getuid() == 501 and Path(sys.executable) == PYTHON,
             'exact_mac_interpreter_and_account')
        for path in (BASE, WORK, NODE):
            check_deadline(until)
            info = path.lstat()
            need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
                 and info.st_uid == 501 and not info.st_mode & 0o022,
                 'fixed_owned_fixture_directory')
            if path in (WORK, NODE):
                need(stat.S_IMODE(info.st_mode) == 0o700, 'private_owned_fixture_directory')
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directories.append((path, fd, identity(info)))
            need(identity(os.fstat(fd)) == identity(info), 'same_held_fixture_directory')
        public = {}
        for path, (size, expected_sha) in PUBLIC_PINS.items():
            check_deadline(until)
            info = path.lstat()
            need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
                 and info.st_nlink == 1 and info.st_uid in (0, 501)
                 and not info.st_mode & 0o022 and info.st_size == size,
                 'exact_public_tls_input_metadata')
            if path in (CA, LEAF):
                need(info.st_uid == 501 and stat.S_IMODE(info.st_mode) == 0o600,
                     'private_mode_public_fixture_cert')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            files.append((path, fd, identity(info)))
            need(identity(os.fstat(fd)) == identity(info), 'same_held_public_input')
            raw = bytearray()
            while len(raw) <= size:
                check_deadline(until)
                part = os.read(fd, min(65536, size + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
                need(len(raw) <= size, 'bounded_public_tls_input_read')
            need(len(raw) == size and hashlib.sha256(raw).hexdigest() == expected_sha,
                 'exact_public_tls_input_pin')
            need(identity(os.fstat(fd)) == identity(path.lstat()) == identity(info),
                 'stable_public_tls_input')
            public[path] = bytes(raw)
        key_info = KEY.lstat()
        need(KEY.resolve(strict=True) == KEY and stat.S_ISREG(key_info.st_mode)
             and key_info.st_nlink == 1 and key_info.st_uid == 501
             and stat.S_IMODE(key_info.st_mode) == 0o600
             and 0 < key_info.st_size <= 16384, 'private_synthetic_key_metadata')
        key_fd = os.open(KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        files.append((KEY, key_fd, identity(key_info)))
        need(identity(os.fstat(key_fd)) == identity(key_info), 'same_held_synthetic_key')
        phase = 'ssl_load_existing_synthetic_identity'
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile=str(LEAF), keyfile=str(KEY))
        server_context.set_alpn_protocols(['h2', 'http/1.1'])
        expected_der = ssl.PEM_cert_to_DER_cert(public[LEAF].decode('ascii'))
        for server_name in NAMES:
            check_deadline(until)
            client_context = ssl.create_default_context(cafile=str(CA))
            report['cases'].append(memorybio_case(
                client_context, server_context, server_name, expected_der, until))
        phase = 'final_input_custody'
        for path, fd, original in files:
            need(identity(os.fstat(fd)) == identity(path.lstat()) == original,
                 'original_tls_input_identity_changed')
        for path, fd, original in directories:
            need(identity(os.fstat(fd)) == identity(path.lstat()) == original,
                 'original_fixture_directory_identity_changed')
        report.update(publicInputPins={str(p): {'bytes': size, 'sha256': sha}
                                      for p, (size, sha) in PUBLIC_PINS.items()},
                      publicAndPrivateInputIdentitiesUnchanged=True,
                      existingSyntheticKeyPrivate0600=True,
                      privateKeyContentsReadOnlyBySsl=True,
                      opensslVersion=ssl.OPENSSL_VERSION,
                      originalStrictClientContextPreserved=True)
        report['ok'] = (len(report['cases']) == 2
                        and all(row['passed'] is True for row in report['cases']))
    except BaseException as error:
        report['error'] = safe_error(error, phase)
    finally:
        unchanged = True
        for path, fd, original in files + directories:
            try:
                current_same = identity(os.fstat(fd)) == identity(path.lstat()) == original
                unchanged = current_same and unchanged
            except OSError:
                unchanged = False
        report['allReturnedInputIdentitiesUnchangedAtClose'] = unchanged
        report['ok'] = report['ok'] and unchanged
        closed = 0
        for path, fd, original in reversed(files + directories):
            try:
                os.close(fd)
                closed += 1
            except OSError:
                report['ok'] = False
        report['returnedDescriptorCount'] = len(files) + len(directories)
        report['allReturnedDescriptorsClosed'] = closed == len(files) + len(directories)
        report['elapsedSeconds'] = time.monotonic() - started
        report['ok'] = report['ok'] and report['allReturnedDescriptorsClosed']
        print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(run())
