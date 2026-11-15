#!/usr/bin/env python3
"""One credential-free new Rust listener diagnostic, never a HA retry.

The same fixed IP, port, public certificate and client code are observed from
X230 and Mac. TCP, strict TLS and the original unauthenticated health GET have
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

WORKER_SOURCE = '#!/usr/bin/env python3\n"""One new, uninitialized normal Rust listener; only unauthenticated health GET.\n\nThe parent owns the SSH stream. This worker owns the original Rust child via\nthe unchanged, source-pinned process-custody module. No old fixture is started,\ninitialized, repaired, removed or otherwise changed.\n"""\nimport hashlib\nimport importlib.util\nimport json\nimport os\nfrom pathlib import Path\nimport platform\nimport re\nimport select\nimport signal\nimport socket\nimport ssl\nimport stat\nimport subprocess\nimport sys\nimport time\nimport types\nimport urllib.error\n\nROOT = Path(\'/home/qian/heptabao-native-ha-4bde9-authbus-tls-diagnostic-20261106-r2\')\nOLD = Path(\'/home/qian/heptabao-native-ha-4bde9-authbus-20261106-r1\')\nQUALIFIED = Path(\'/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1\')\nQA = QUALIFIED / \'source-4bde9/qa/openbao-acceptance\'\nBIN = QUALIFIED / \'artifacts/heptabao-server\'\nIP, PORT = \'192.168.0.13\', 31040\nCA_PIN = (1192, \'90031a0f48ad7c8d5d603ce9c517ca61fd8ca57d12ddd67608f0d7c1fddbb34b\')\nLEAF_PIN = (1277, \'2e3938207ae080055ded642675a1d2053a3b9c4be80d08ed60690c45d57d1215\')\nBIN_PIN = (110799168, \'85c1e21771cc1110e6442ba06cbda31db5ba7040d15f8b5c1930aa6fa40c5e5c\')\nCOMMON_PINS = {\n    \'fixture_mounts\': (1560, \'55075ee436c22816a176dfb06cec387df37fdadd581c16acc07dabc837ba85b5\'),\n    \'owned_process\': (28442, \'0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0\'),\n    \'kv2_dr_process_custody\': (26131, \'669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008\'),\n}\nLINUX_BASE_PIN = (77805, \'0e7362d3e579f8a13d63ad1573745fb8cda71aeba75f40288db3927204e408de\')\n\n\nclass Refused(RuntimeError):\n    pass\n\n\ndef need(value, label):\n    if not value:\n        raise Refused(label)\n\n\ndef ident(info):\n    return tuple(getattr(info, k) for k in (\'st_dev\', \'st_ino\', \'st_uid\', \'st_gid\',\n                 \'st_mode\', \'st_nlink\', \'st_size\', \'st_mtime_ns\', \'st_ctime_ns\'))\n\n\ndef deadline(until):\n    need(time.monotonic() < until, \'diagnostic_total_deadline\')\n\n\ndef file_pin(path, pin, until, *, contents=False):\n    deadline(until)\n    info = path.lstat()\n    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)\n         and info.st_nlink == 1 and info.st_uid in (0, os.getuid())\n         and not info.st_mode & 0o022 and info.st_size == pin[0], \'fixed_owned_public_input\')\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    try:\n        need(ident(os.fstat(fd)) == ident(info), \'same_open_public_input\')\n        digest, count, raw = hashlib.sha256(), 0, bytearray()\n        while True:\n            deadline(until)\n            part = os.read(fd, min(1048576, pin[0] + 1 - count))\n            if not part:\n                break\n            count += len(part)\n            need(count <= pin[0], \'public_input_read_bound\')\n            digest.update(part)\n            if contents:\n                raw.extend(part)\n        need(count == pin[0] and digest.hexdigest() == pin[1]\n             and ident(os.fstat(fd)) == ident(path.lstat()) == ident(info), \'public_input_pin_or_identity_changed\')\n        return ident(info), bytes(raw)\n    finally:\n        os.close(fd)\n\n\ndef owned_directory(path, *, private=False):\n    s = path.lstat()\n    need(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode)\n         and s.st_uid == os.getuid() and not s.st_mode & 0o022, \'owned_canonical_directory\')\n    need(not private or stat.S_IMODE(s.st_mode) == 0o700, \'private_directory_0700\')\n    return ident(s)\n\n\ndef key_metadata(path):\n    s = path.lstat()\n    need(path.resolve(strict=True) == path and stat.S_ISREG(s.st_mode)\n         and s.st_nlink == 1 and s.st_uid == os.getuid()\n         and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 16384,\n         \'existing_synthetic_key_private_0600\')\n    return ident(s)\n\n\ndef write_new(path, data):\n    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n    try:\n        with os.fdopen(fd, \'wb\', closefd=False) as out:\n            out.write(data)\n            out.flush()\n            os.fsync(out.fileno())\n    finally:\n        os.close(fd)\n\n\ndef load_originals(qa, base_pin, until):\n    pins = {**COMMON_PINS, \'ha_multihost_live\': base_pin}\n    records, modules = {}, {}\n    for name, pin in pins.items():\n        path = qa / (name + \'.py\')\n        identity, raw = file_pin(path, pin, until, contents=True)\n        need(name not in sys.modules, \'original_module_not_preimported\')\n        module = types.ModuleType(name)\n        module.__file__ = str(path)\n        sys.modules[name] = module\n        exec(compile(raw, str(path), \'exec\'), module.__dict__)\n        records[path] = (pin, identity)\n        modules[name] = module\n    return modules[\'ha_multihost_live\'], modules[\'kv2_dr_process_custody\'], records\n\n\ndef safe_error(error):\n    out = {\'type\': type(error).__name__}\n    if isinstance(error, Refused):\n        out[\'code\'] = str(error)\n    for value, prefix in ((error, \'\'), (getattr(error, \'reason\', None), \'reason\')):\n        if value is None:\n            continue\n        if prefix:\n            out[\'reasonType\'] = type(value).__name__\n        if isinstance(value, OSError) and type(value.errno) is int:\n            out[prefix + \'Errno\' if prefix else \'errno\'] = value.errno\n        if isinstance(value, ssl.SSLError):\n            reason = getattr(value, \'reason\', None)\n            if isinstance(reason, str) and re.fullmatch(r\'[A-Z0-9_]{1,96}\', reason):\n                out[prefix + \'SslReason\' if prefix else \'sslReason\'] = reason\n            code = getattr(value, \'verify_code\', None)\n            if type(code) is int:\n                out[prefix + \'VerifyCode\' if prefix else \'verifyCode\'] = code\n    return out\n\n\ndef health_case(base, context, node):\n    start = time.monotonic()\n    row = {\'stage\': \'original_urllib_health\', \'passed\': False, \'method\': \'GET\',\n           \'route\': \'/v1/sys/health\', \'authenticationSent\': False, \'budgetSeconds\': 1.5}\n    try:\n        status, body = base.api(context, node, \'GET\', \'sys/health\', timeout=1.5)\n        row.update(httpStatus=status, initialized=body.get(\'initialized\') if type(body.get(\'initialized\')) is bool else None,\n                   sealed=body.get(\'sealed\') if type(body.get(\'sealed\')) is bool else None)\n        row[\'passed\'] = status == 501 and time.monotonic() - start <= 1.5\n    except BaseException as error:\n        row[\'error\'] = safe_error(error)\n    row[\'elapsedSeconds\'] = time.monotonic() - start\n    return row\n\n\ndef verify_records(records, until):\n    for path, (pin, identity) in records.items():\n        now, _ = file_pin(path, pin, until)\n        need(now == identity, \'public_input_final_identity_changed\')\n\n\ndef emit(phase, data):\n    print(json.dumps({\'phase\': phase, \'data\': data}, sort_keys=True, separators=(\',\', \':\')), flush=True)\n\n\ndef run_worker():\n    start = time.monotonic()\n    until = start + 85\n    report = {\'schema\': \'heptabao.ha-rust-tls-diagnostic-worker.r1\', \'ok\': False,\n              \'oldFixtureRestarted\': False, \'initializationSubmitted\': False,\n              \'mutationRequests\': 0, \'credentialsUsed\': False, \'keyDigestPublished\': False,\n              \'productionChanged\': False, \'haQualified\': False, \'remoteClosureUnknown\': True}\n    created = False\n    child = owner = log = None\n    records = {}\n    key_before = None\n    try:\n        need(sys.platform == \'linux\' and os.getuid() == 1000\n             and platform.node() == \'qian-ThinkPad-X230\', \'actual_x230_account\')\n        owned_directory(ROOT.parent)\n        owned_directory(OLD, private=True)\n        owned_directory(QUALIFIED, private=True)\n        need(not ROOT.exists() and not ROOT.is_symlink(), \'new_diagnostic_root_absent\')\n        base, custody, records = load_originals(QA, LINUX_BASE_PIN, until)\n        for path, pin in ((BIN, BIN_PIN), (OLD / \'ca.crt\', CA_PIN), (OLD / \'tls.crt\', LEAF_PIN)):\n            identity, _ = file_pin(path, pin, until)\n            records[path] = (pin, identity)\n        need(stat.S_IMODE(BIN.stat().st_mode) == 0o700, \'qualified_normal_binary_mode\')\n        key_before = key_metadata(OLD / \'tls.key\')\n        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as preflight:\n            preflight.bind((IP, PORT))\n        ROOT.mkdir(mode=0o700, exist_ok=False)\n        created = True\n        config = {\'listen\': f\'{IP}:{PORT}\', \'data_dir\': str(ROOT / \'state\'),\n                  \'audit_file\': str(ROOT / \'audit.jsonl\'),\n                  \'tls_cert_file\': str(OLD / \'tls.crt\'), \'tls_key_file\': str(OLD / \'tls.key\'),\n                  \'max_connections\': 64, \'timeout_seconds\': 15, \'rate_limit_per_second\': 2000,\n                  \'rate_limit_burst\': 4000, \'rate_limit_entries\': 512, \'lifecycle_interval_seconds\': 1}\n        write_new(ROOT / \'server.json\', (json.dumps(config, sort_keys=True) + \'\\n\').encode())\n        log_fd = os.open(ROOT / \'process.log\', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n        log = os.fdopen(log_fd, \'wb\')\n        node = base.Node(1, \'x230\', IP, str(ROOT), PORT, 31041)\n        context = ssl.create_default_context(cafile=str(OLD / \'ca.crt\'))\n        try:\n            with custody.activated() as current_owner:\n                owner = current_owner\n                try:\n                    child = subprocess.Popen([str(BIN), \'--config\', str(ROOT / \'server.json\')],\n                                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,\n                                             close_fds=True, start_new_session=True)\n                    ready_until = time.monotonic() + 45\n                    ready = b\'HeptaBao single-node TLS listener ready at 192.168.0.13:31040\\n\'\n                    while True:\n                        deadline(min(until, ready_until))\n                        need(child.poll() is None, \'owned_rust_listener_exited_before_ready\')\n                        with (ROOT / \'process.log\').open(\'rb\') as observation:\n                            raw = observation.read(65537)\n                        need(len(raw) <= 65536, \'bounded_owned_rust_log\')\n                        if ready in raw:\n                            break\n                        time.sleep(0.025)\n                    need(os.readlink(\'/proc/\' + str(child.pid) + \'/exe\') == str(BIN), \'actual_owned_rust_executable\')\n                    report[\'listenerPid\'] = child.pid\n                    report[\'selfHealth\'] = health_case(base, context, node)\n                    need(child.poll() is None, \'owned_rust_alive_after_self_probe\')\n                    report[\'aliveBeforeParentProbe\'] = True\n                    emit(\'ready\', {\'pid\': child.pid, \'selfHealth\': report[\'selfHealth\'],\n                                   \'controlBudgetSeconds\': 15, \'newUninitializedFixture\': True})\n                    readable, _, _ = select.select([sys.stdin], [], [], min(15, until - time.monotonic()))\n                    need(bool(readable), \'parent_control_deadline\')\n                    command = os.read(sys.stdin.fileno(), 16)\n                    need(command == b\'finish\\n\', \'exact_parent_finish_command\')\n                    need(child.poll() is None, \'owned_rust_alive_after_parent_probe\')\n                    report[\'aliveAfterParentProbe\'] = True\n                finally:\n                    if child is not None and child.poll() is None:\n                        child.terminate()\n                        try:\n                            child.wait(timeout=5)\n                        except subprocess.TimeoutExpired:\n                            child.kill()\n                            child.wait(timeout=5)\n        finally:\n            if log is not None:\n                log.close()\n                report[\'logStreamClosed\'] = log.closed\n        report[\'processCustody\'] = owner.assert_retired()\n        need(report[\'processCustody\'][\'original_count\'] == 1\n             and report[\'processCustody\'][\'passed_process_custody\'], \'exact_original_rust_custody\')\n        need(key_metadata(OLD / \'tls.key\') == key_before, \'original_synthetic_key_identity_changed\')\n        verify_records(records, until)\n        report.update(remoteClosureUnknown=False, allInputsUnchanged=True,\n                      originalSyntheticKeyIdentityUnchanged=True, originalRustChildRetired=True,\n                      diagnosticComplete=True, ok=True)\n    except BaseException as error:\n        report[\'error\'] = safe_error(error)\n    finally:\n        if log is not None and not log.closed:\n            log.close()\n        if owner is not None:\n            report[\'processCustody\'] = owner.receipt()\n            report[\'remoteClosureUnknown\'] = not (\n                owner.finished and all(row.get(\'original_wait_completed\') is True\n                and row.get(\'no_live_members_before_reap\') is True for row in owner.rows))\n        else:\n            report[\'remoteClosureUnknown\'] = False\n            report[\'rustChildStarted\'] = False\n        report[\'elapsedSeconds\'] = time.monotonic() - start\n        report[\'logStreamClosed\'] = log is None or log.closed\n        if key_before is not None:\n            try:\n                report[\'originalSyntheticKeyIdentityUnchanged\'] = key_metadata(OLD / \'tls.key\') == key_before\n            except BaseException:\n                report[\'originalSyntheticKeyIdentityUnchanged\'] = False\n        report[\'ok\'] = (report[\'ok\'] and not report[\'remoteClosureUnknown\'] and report[\'logStreamClosed\']\n                        and report.get(\'originalSyntheticKeyIdentityUnchanged\') is True)\n        if created:\n            write_new(ROOT / \'result.public.json\', (json.dumps(report, sort_keys=True) + \'\\n\').encode())\n        emit(\'final\', report)\n    return 0 if report[\'ok\'] else 1\n\n\nif __name__ == \'__main__\':\n    raise SystemExit(run_worker())\n'
namespace = {'__name__': 'reviewed_rust_tls_worker_definitions'}
exec(compile(WORKER_SOURCE, '<reviewed-worker-definitions>', 'exec'), namespace)
need, deadline, safe_error = (namespace[n] for n in ('need', 'deadline', 'safe_error'))
file_pin, owned_directory = (namespace[n] for n in ('file_pin', 'owned_directory'))
load_originals, write_new, verify_records = (namespace[n] for n in ('load_originals', 'write_new', 'verify_records'))
health_case = namespace['health_case']
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OLD = BASE / 'native-ha-official-history-4bde9-authbus-r1'
ROOT = BASE / 'ha128-rust-tls-lan-diagnostic-20261106-r2'
QA = BASE / 'ha-qa-af91-preparation-20261106-r1/source/qa/openbao-acceptance'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
SSH = Path('/usr/bin/ssh')
BASE_PIN = (77824, '2c87ffbcee09fc7706e7ac59c73ac851ac8313ce18a962255a26ad54e90d089e')
TOOL_PINS = {
    PYTHON: (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    SSH: (1584576, '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3'),
}
IP, PORT = '192.168.0.13', 31040


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
              'originalHaJob': '1a1b29efcd8-fc05-7ef9', 'originalFailureReclassified': False,
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
        pins = {**TOOL_PINS, OLD / 'ca.crt': namespace['CA_PIN'], OLD / 'node-1/tls.crt': namespace['LEAF_PIN']}
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
                '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', 'x230',
                '/usr/bin/python3', '-I', '-S', '-B', '-c', shlex.quote(remote_code)]
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
                    node = base.Node(1, 'x230', IP, str(namespace['ROOT']), PORT, 31041)
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
