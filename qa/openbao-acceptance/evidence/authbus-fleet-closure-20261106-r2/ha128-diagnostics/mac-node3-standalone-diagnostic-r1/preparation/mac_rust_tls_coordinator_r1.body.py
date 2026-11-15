#!/usr/bin/env python3
"""One credential-free new Rust listener diagnostic, never a HA retry.

The same fixed IP, port, public certificate and client code are observed from
the Mac SSH worker and main coordinator. TCP, strict TLS and the original health GET have
separate 1.5 second budgets. All error details are closed public classifications.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shlex
import socket
import ssl
import subprocess
import sys
import time

WORKER_SOURCE = ''  # ASSEMBLED_REVIEWED_WORKER
namespace = {'__name__': 'reviewed_rust_tls_worker_definitions'}
exec(compile(WORKER_SOURCE, '<reviewed-worker-definitions>', 'exec'), namespace)
need, deadline, safe_error = (namespace[n] for n in ('need', 'deadline', 'safe_error'))
file_pin, owned_directory = (namespace[n] for n in ('file_pin', 'owned_directory'))
load_originals, write_new, verify_records = (namespace[n] for n in ('load_originals', 'write_new', 'verify_records'))
health_case = namespace['health_case']
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OLD = BASE / 'native-ha-4bde9-authbus-node-r2'
ROOT = BASE / 'ha128-mac-rust-tls-control-20261106-r1'
QA = BASE / 'ha-qa-af91-preparation-20261106-r1/source/qa/openbao-acceptance'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
SSH = Path('/usr/bin/ssh')
BASE_PIN = (77824, '2c87ffbcee09fc7706e7ac59c73ac851ac8313ce18a962255a26ad54e90d089e')
TOOL_PINS = {
    PYTHON: (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    SSH: (1584576, '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3'),
}
IP, PORT = '192.168.0.8', 31040


def transport_case(kind, context, expected_der):
    start = time.monotonic()
    until = start + 1.5
    row = {'stage': kind, 'passed': False, 'budgetSeconds': 1.5,
           'authenticationSent': False, 'applicationBytesSent': 0}
    tcp = tls = None
    phase = 'tcp_connect'
    try:
        tcp = socket.create_connection((IP, PORT), timeout=max(0.001, until - time.monotonic()))
        row['tcpConnected'] = True
        need(tcp.getpeername()[0:2] == (IP, PORT), 'exact_declared_peer')
        if kind == 'strict_tls':
            phase = 'tls_handshake'
            need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
                 'strict_original_client_context')
            deadline(until)
            tcp.settimeout(until - time.monotonic())
            tls = context.wrap_socket(tcp, server_hostname=IP)
            need(tls.getpeercert(binary_form=True) == expected_der, 'original_leaf_der_mismatch')
            row.update(tlsVersion=tls.version(), selectedAlpn=tls.selected_alpn_protocol(),
                       sameLeafDer=True, verifyFlags=int(context.verify_flags))
        deadline(until)
        row['passed'] = True
    except BaseException as error:
        row['error'] = {**safe_error(error), 'phase': phase}
    finally:
        if tls is not None:
            tls.close()
        if tcp is not None:
            tcp.close()
        row['socketsClosed'] = (tls is None or tls.fileno() == -1) and (tcp is None or tcp.fileno() == -1)
        row['elapsedSeconds'] = time.monotonic() - start
    return row


def wait_ready(child, until, buffers):
    with selectors.DefaultSelector() as selector:
        for name, pipe in (('stdout', child.stdout), ('stderr', child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while True:
            deadline(until)
            for key, _ in selector.select(min(0.2, until - time.monotonic())):
                part = os.read(key.fileobj.fileno(), 16384)
                if not part:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(part)
                need(len(buffers[key.data]) <= 262144, 'bounded_original_ssh_stream')
            lines = buffers['stdout'].split(b'\n')
            for line in lines[:-1]:
                row = json.loads(line)
                need(set(row) == {'phase', 'data'} and isinstance(row['data'], dict), 'exact_worker_protocol')
                if row['phase'] == 'ready':
                    need(row['data'].get('newUninitializedFixture') is True
                         and row['data'].get('controlBudgetSeconds') == 15
                         and type(row['data'].get('pid')) is int and row['data']['pid'] > 1,
                         'owned_worker_ready_protocol')
                    return row['data']
                need(row['phase'] != 'final', 'worker_finished_without_ready')
            need(child.poll() is None, 'original_ssh_exited_before_ready')


def run():
    start = time.monotonic()
    until = start + 100
    report = {'schema': 'heptabao.ha-rust-tls-lan-diagnostic-coordinator.r1', 'ok': False,
              'originalHaJob': '1a1b322abe3-fc05-80b8', 'originalFailureReclassified': False,
              'credentialsUsed': False, 'initializationSubmitted': False, 'mutationRequests': 0,
              'productionChanged': False, 'haQualified': False, 'candidateFullyQualified': False,
              'remoteClosureUnknown': True, 'macCases': []}
    created = False
    child = owner = None
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    finished_sent = False
    records = {}
    try:
        need(sys.platform == 'darwin' and platform.machine() == 'arm64' and os.getuid() == 501
             and Path(sys.executable) == PYTHON, 'actual_mac_interpreter_and_account')
        owned_directory(BASE)
        owned_directory(OLD, private=True)
        need(not ROOT.exists() and not ROOT.is_symlink(), 'new_coordinator_root_absent')
        base, custody, records = load_originals(QA, BASE_PIN, until)
        pins = {**TOOL_PINS, OLD / 'ca.crt': namespace['CA_PIN'], OLD / 'tls.crt': namespace['LEAF_PIN']}
        leaf = None
        for path, pin in pins.items():
            identity, raw = file_pin(path, pin, until, contents=path.name == 'tls.crt')
            records[path] = (pin, identity)
            if path.name == 'tls.crt':
                leaf = raw
        expected_der = ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))
        context = ssl.create_default_context(cafile=str(OLD / 'ca.crt'))
        ROOT.mkdir(mode=0o700, exist_ok=False)
        created = True
        write_new(ROOT / 'worker.source.py', WORKER_SOURCE.encode())
        encoded = base64.b64encode(WORKER_SOURCE.encode()).decode('ascii')
        remote_code = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<fixed-diagnostic-worker>','exec'))"
        argv = [str(SSH), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', 'hepta-mac-local',
                str(PYTHON), '-I', '-S', '-B', '-c', shlex.quote(remote_code)]
        try:
            with custody.activated() as current_owner:
                owner = current_owner
                try:
                    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                                             start_new_session=True)
                    report['workerReady'] = wait_ready(child, min(until, time.monotonic() + 60), buffers)
                    for kind in ('tcp_only', 'strict_tls'):
                        report['macCases'].append(transport_case(kind, context, expected_der))
                    node = base.Node(3, 'hepta-mac-local', IP, str(namespace['ROOT']), PORT, 31041)
                    report['macCases'].append(health_case(base, context, node))
                    need(os.write(child.stdin.fileno(), b'finish\n') == 7, 'complete_parent_finish_command')
                    finished_sent = True
                finally:
                    if child is not None:
                        if child.stdin is not None:
                            child.stdin.close()
                            child.stdin = None
                        try:
                            out, error = child.communicate(timeout=max(0.001, min(25, until - time.monotonic())))
                            buffers['stdout'].extend(out)
                            buffers['stderr'].extend(error)
                        except subprocess.TimeoutExpired:
                            child.terminate()
                            try:
                                out, error = child.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                child.kill()
                                out, error = child.communicate(timeout=5)
                            buffers['stdout'].extend(out)
                            buffers['stderr'].extend(error)
                            raise
        finally:
            if child is not None:
                for pipe in (child.stdin, child.stdout, child.stderr):
                    if pipe is not None and not pipe.closed:
                        pipe.close()
        report['sshProcessCustody'] = owner.assert_retired()
        need(len(buffers['stdout']) <= 262144 and len(buffers['stderr']) <= 262144, 'bounded_complete_ssh_streams')
        rows = [json.loads(line) for line in buffers['stdout'].splitlines()]
        need(len(rows) == 2 and [r.get('phase') for r in rows] == ['ready', 'final'], 'complete_worker_protocol')
        worker = rows[1]['data']
        report['workerFinal'] = worker
        report['remoteClosureUnknown'] = worker.get('remoteClosureUnknown') is not False
        need(finished_sent and child.returncode == 0 and not buffers['stderr'] and worker.get('ok') is True
             and not report['remoteClosureUnknown'], 'known_original_worker_completion')
        need(report['sshProcessCustody']['original_count'] == 1
             and report['sshProcessCustody']['passed_process_custody'], 'exact_original_ssh_custody')
        verify_records(records, until)
        report.update(ok=True, diagnosticComplete=True, sourceInputsUnchanged=True,
                      allFourHealthAndTransportStagesPassed=worker['selfHealth']['passed']
                          and all(row['passed'] for row in report['macCases']))
    except BaseException as error:
        report['error'] = safe_error(error)
    finally:
        if owner is not None:
            report['sshProcessCustody'] = owner.receipt()
        # An admission failure can emit only a final row. Preserve its known
        # child closure even when wait_ready raised; incomplete output stays unknown.
        try:
            need(0 < len(buffers['stdout']) <= 262144, 'bounded_worker_final')
            final_rows = [json.loads(line) for line in buffers['stdout'].splitlines()]
            need([r.get('phase') for r in final_rows] in (['final'], ['ready', 'final']),
                 'complete_worker_final_order')
            final = final_rows[-1]['data']
            need(final.get('schema') == 'heptabao.ha-rust-tls-diagnostic-worker.r1'
                 and type(final.get('remoteClosureUnknown')) is bool, 'worker_final_scope')
            report['workerFinal'] = final
            report['remoteClosureUnknown'] = final['remoteClosureUnknown']
        except BaseException:
            report['workerFinalIncompleteOrInvalid'] = True
        report['sshStreamsClosed'] = child is None or all(
            pipe is None or pipe.closed for pipe in (child.stdin, child.stdout, child.stderr))
        report['sshStdoutBytes'] = len(buffers['stdout'])
        report['sshStderrBytes'] = len(buffers['stderr'])
        report['finishCommandSent'] = finished_sent
        report['elapsedSeconds'] = time.monotonic() - start
        report['ok'] = report['ok'] and report['sshStreamsClosed']
        if created:
            write_new(ROOT / 'ssh.stdout.original.jsonl', bytes(buffers['stdout']))
            write_new(ROOT / 'ssh.stderr.private.bin', bytes(buffers['stderr']))
            write_new(ROOT / 'result.public.json', (json.dumps(report, sort_keys=True) + '\n').encode())
        print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(run())
