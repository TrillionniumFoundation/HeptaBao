#!/usr/bin/env python3
"""One bounded read-only production inventory and same-parent gateway binding.

No gateway request, SDK import, provider call, credential row read, service
mutation or production write. The only writer is a new private QA directory.
"""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

START = time.monotonic()
UNTIL = START + 45
ROOT = Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r2')
QUAL = Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2')
LIVE = Path('/Users/qianqi/.openclaw')
CALLER_HOME = Path('/Users/qianqi')
CONFIG = LIVE / 'openclaw.json'
GATEWAY_ENV = CALLER_HOME / '.config/openclaw/gateway.env'
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
VM_STAT = '/usr/bin/vm_stat'
AGENTS = ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')
REMOTE_PINS = {
    'authbus_current_auth_wal.py': 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
    'mac_guarded_current_capture_r3.py': '606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
    'mac_registry_readonly_wal_r1.py': '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
    'kv2_dr_process_custody.py': '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
    'owned_process.py': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0',
}
NATIVE_PINS = {
    PYTHON: 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13',
    '/usr/bin/sandbox-exec': 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
    VM_STAT: '0127fec1de1d99c7f0b0cf185fec048c7fe92d1f1b2ad380882c583f0c921df7',
    '/bin/launchctl': 'b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7',
    '/bin/ps': '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c',
}
# PAYLOAD_PLACEHOLDER

codes, fds = set(), []
owner = child = observer = commands = None
created = False
report = {
    'schema': 'heptabao.current-production-source-inventory-launch.public.r2', 'ok': False,
    'credentialRowsRead': 0, 'sdkImported': False, 'gatewayRpcCalls': 0,
    'providerCalls': 0, 'serviceMutations': 0, 'productionWrites': 0,
    'productionCutover': False, 'productionRollbackQualified': False,
    'fullConsumerCoverageProven': False, 'runningPluginMemoryFlagsProven': False,
    'sharedSeconds': 45, 'supervisorSeconds': 70, 'automaticRetry': False,
}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def remaining(cap=45):
    value = UNTIL - time.monotonic()
    need(value > 0, 'inventory_parent_original_absolute_deadline')
    return min(value, cap)


def full9(value):
    return [str(getattr(value, name)) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def opened(path, flags, mode=0o600):
    remaining()
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    fds.append(row)
    return row


def close(row):
    if row['closeAttempts']:
        return
    row['closeAttempts'] = 1
    os.close(row['fd'])
    row['closed'] = True


def read(path, cap, *, private_file=False):
    row = opened(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid in (0, 501) and not stat.S_IMODE(before.st_mode) & 0o022
             and 0 <= before.st_size <= cap, 'inventory_parent_regular_bounded_input')
        if private_file:
            need(before.st_uid == 501 and before.st_gid == 20
                 and stat.S_IMODE(before.st_mode) == 0o600,
                 'inventory_parent_owned_private_output_custody')
        raw = bytearray()
        while len(raw) <= before.st_size:
            remaining()
            part = os.read(row['fd'], min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and full9(before) == full9(os.fstat(row['fd']))
             == full9(Path(path).lstat()), 'inventory_parent_complete_stable_input')
        return bytes(raw)
    finally:
        close(row)


def private_write(name, raw):
    # The observer can only create fixed basenames in the owned output dir.
    need(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9.-]{0,127}', name)
         and '/' not in name and '..' not in name, 'inventory_private_fixed_output_basename')
    need(isinstance(raw, bytes) and len(raw) <= 4 * 1048576, 'inventory_private_output_byte_bound')
    write(ROOT / 'output' / name, raw)


def write(path, raw):
    need(path.is_relative_to(ROOT) and isinstance(raw, bytes) and len(raw) <= 4 * 1048576,
         'inventory_owned_create_only_output')
    row = opened(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        view = memoryview(raw)
        while view:
            remaining()
            count = os.write(row['fd'], view)
            need(count > 0, 'inventory_private_write_progress')
            view = view[count:]
        os.fsync(row['fd'])
    finally:
        close(row)
    directory = opened(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory['fd'])
    finally:
        close(directory)


def source_fence():
    for name, pin in REMOTE_PINS.items():
        need(sha(read(QUAL / 'qa' / name, 131072)) == pin,
             'inventory_original_qualified_source_unchanged')
    for path, pin in NATIVE_PINS.items():
        need(sha(read(Path(path), 2 * 1048576)) == pin, 'inventory_native_runtime_unchanged')
    if created:
        for name, pin in PAYLOAD['sourcePins'].items():
            need(sha(read(ROOT / 'code' / name, 131072)) == pin,
                 'inventory_new_staged_source_unchanged')


def original_authority(value, job):
    need(value['job_id'] == job and value['state'] == 'succeeded' and value['exit_code'] == 0
         and all(value[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(value[k] is False for k in ('timed_out', 'cancelled', 'automatic_retry')),
         'inventory_original_qualification_authority')


def pure_definitions(name, expected_names, expected_ast_sha, namespace):
    raw = read(ROOT / 'code' / name, 131072)
    need(sha(raw) == PAYLOAD['sourcePins'][name], 'inventory_exact_parser_whole_source')
    parsed = ast.parse(raw)
    nodes = [node for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name in expected_names]
    need({node.name for node in nodes} == set(expected_names)
         and len(nodes) == len(expected_names), 'inventory_exact_pure_definition_set')
    module = ast.Module(body=nodes, type_ignores=[])
    need(sha(ast.dump(module, include_attributes=False, show_empty=True).encode()) == expected_ast_sha,
         'inventory_exact_qualified_pure_definition_ast')
    exec(compile(module, name, 'exec'), namespace)
    return namespace


def memory_observation():
    row, out, err = commands.run('current-memory-vm-stat', [VM_STAT],
        until=min(UNTIL, time.monotonic() + 3), maximum=32768)
    private_write('memory-observation.stdout.private', out)
    private_write('memory-observation.stderr.private', err)
    need(row.get('outcomeUnknown') is False and type(row.get('exitCode')) is int
         and row['exitCode'] == 0 and not err,
         'inventory_original_memory_observation_closed_known_zero')
    lines = out.decode('ascii', 'strict').splitlines()
    header = re.fullmatch(r'Mach Virtual Memory Statistics: \(page size of ([0-9]{1,6}) bytes\)', lines[0] if lines else '')
    need(header is not None, 'inventory_actual_vm_page_size_header')
    page_size = int(header.group(1))
    need(page_size in (4096, 16384, 65536), 'inventory_bounded_observed_page_size')
    names = {'Pages free': 'free', 'Pages active': 'active', 'Pages inactive': 'inactive',
             'Pages speculative': 'speculative', 'Pages wired down': 'wired',
             'Pages occupied by compressor': 'compressor'}
    pages = {}
    for line in lines[1:]:
        match = re.fullmatch(r'([^:]{1,64}):\s+([0-9]{1,20})\.', line.strip())
        need(match is not None, 'inventory_complete_numeric_vm_stat_line')
        if match.group(1) in names:
            key = names[match.group(1)]
            need(key not in pages, 'inventory_unique_vm_stat_field')
            pages[key] = int(match.group(2))
    need(set(pages) == set(names.values())
         and all(0 <= value * page_size <= 34359738368 for value in pages.values()),
         'inventory_bounded_current_memory_pages')
    return {'method': 'one_pinned_original_vm_stat', 'pageSize': page_size,
            'observedPages': pages, 'currentlyFreeBytes': pages['free'] * page_size,
            'physicalMemoryPreviouslyObservedBytes': 34359738368,
            'inactivePagesCountedAsGuaranteedAvailable': False,
            'totalPhysicalMemoryCountedAsAvailable': False,
            'productionMemoryBudgetAdmitted': False,
            'observationIsDiscreteNotAReservation': True}


def safe_command_rows():
    if commands is None:
        return []
    result = []
    for row in commands.rows:
        value = row.get('public')
        if value is None:
            result.append({'label': row['label'], 'outcomeUnknown': True})
        else:
            result.append({key: value[key] for key in (
                'label', 'pid', 'exitCode', 'completeBeforeDeadline', 'cleanup',
                'stdoutBytes', 'stderrBytes', 'streamsClosed', 'outcomeUnknown')})
    return result


def close_streams():
    if child is not None:
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except BaseException:
                    report['originalChildStreamCloseUnknown'] = True


def named_generation_verifier(packet):
    need(isinstance(packet, dict) and packet.get('schema') == 'heptabao.current-production-source-inventory.private.r1',
         'inventory_private_packet_schema')
    sources = packet['closedSourceGenerations']
    parents = packet['closedParentGenerations']
    metadata = packet['discoveredMetadataIdentitiesAndAbsences']
    need(isinstance(sources, list) and len(sources) == 7
         and isinstance(parents, dict) and len(parents) <= 256
         and isinstance(metadata, dict) and len(metadata) <= 2048,
         'inventory_bounded_private_generation_collections')
    allowed_outside = {str(path) for path in (GATEWAY_ENV, *GATEWAY_ENV.parents)}

    def inspect(path, expected):
        remaining()
        need(isinstance(path, str) and path == os.path.normpath(path) and path.startswith('/')
             and (Path(path).is_relative_to(LIVE) or path in allowed_outside),
             'inventory_exact_current_generation_metadata_scope')
        if expected is not None:
            need(isinstance(expected, list) and len(expected) == 9
                 and all(isinstance(value, str) and re.fullmatch(r'[0-9]{1,24}', value) for value in expected),
                 'inventory_exact_private_generation_full9')
        try:
            actual = full9(Path(path).lstat())
        except FileNotFoundError:
            actual = None
        need(actual == expected, 'inventory_same_parent_source_namespace_unchanged')

    def verify():
        for record in sources:
            need(set(record) == {'sourceIdentities', 'sourceAbsences'}
                 and isinstance(record['sourceIdentities'], dict) and len(record['sourceIdentities']) <= 64
                 and isinstance(record['sourceAbsences'], list) and len(record['sourceAbsences']) <= 64,
                 'inventory_bounded_original_source_record')
            for path, expected in record['sourceIdentities'].items():
                inspect(path, expected)
            for path in record['sourceAbsences']:
                inspect(path, None)
        for path, expected in parents.items():
            inspect(path, expected)
        for path, expected in metadata.items():
            inspect(path, expected)
    return verify


try:
    os.umask(0o077)
    sys.dont_write_bytecode = True
    need(sys.platform == 'darwin' and os.getuid() == 501
         and os.path.realpath(sys.executable) == PYTHON, 'inventory_actual_mac_python')
    original_authority(PAYLOAD['custodyQualificationAuthority'], '1a1b141ef40-fc05-7750')
    proof = read(QUAL / 'result.public.json', 65536)
    need(len(proof) == 58701 and sha(proof) == '67cb6bb6804c7285f13f373f6af607405ada39ab734423bf328ffe27915cee4e',
         'inventory_original_custody_qualification_bytes')
    value = json.loads(proof)
    need(value['ok'] and value['allCasesMatched'] and value['allOwnedClosed']
         and value['custody']['passed_process_custody'] and value['custody']['original_count'] == 18,
         'inventory_original_complete_custody18')
    original_authority(json.loads(PAYLOAD['registryAuthority']), '1a1aaaaa6cd-fc05-45dd')
    need(len(PAYLOAD['registryAuthority'].encode()) == 733
         and sha(PAYLOAD['registryAuthority'].encode()) == 'b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f',
         'inventory_original_registry_authority_bytes')
    registry_proof = PAYLOAD['registryProof'].encode()
    need(len(registry_proof) == 62662 and sha(registry_proof) == '7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82',
         'inventory_original_registry_qualification_bytes')
    source_fence()
    home = CALLER_HOME.lstat()
    need(stat.S_ISDIR(home.st_mode) and home.st_uid == 501
         and not stat.S_IMODE(home.st_mode) & 0o022, 'inventory_owned_home_parent')
    ROOT.mkdir(mode=0o700, exist_ok=False)
    for name in ('code', 'output'):
        (ROOT / name).mkdir(mode=0o700, exist_ok=False)
    # Complete all directory creation before holding the real HOME/plist chain.
    for name, source in PAYLOAD['sources'].items():
        need(re.fullmatch(r'[a-z][a-z0-9_]+\.py', name) is not None
             and sha(source.encode()) == PAYLOAD['sourcePins'][name],
             'inventory_exact_new_source_payload')
        compile(source, name, 'exec')
        write(ROOT / 'code' / name, source.encode())
    write(ROOT / 'code/registry-proof.public.json', registry_proof)
    write(ROOT / 'protected-read', b'synthetic protected read probe\n')
    write(ROOT / 'protected-write', b'synthetic protected write probe\n')
    paths = {ROOT, LIVE, LIVE / 'agents', LIVE / 'authbus', CONFIG, LIVE / '.env', GATEWAY_ENV}
    paths.update(ROOT.parents)
    paths.update(GATEWAY_ENV.parents)
    for agent in AGENTS:
        directory = LIVE / 'agents' / agent / 'agent'
        for name in ('openclaw-agent.sqlite', 'openclaw-agent.sqlite-wal', 'openclaw-agent.sqlite-shm',
                     'openclaw-agent.sqlite-journal', 'auth-profiles.json', 'auth-state.json', 'auth.json'):
            path = directory / name
            paths.add(path)
            paths.update(path.parents)
    for suffix in ('', '-wal', '-shm', '-journal'):
        path = Path(str(LIVE / 'state/openclaw.sqlite') + suffix)
        paths.add(path)
        paths.update(path.parents)
    for name in ('applied-profiles.json', 'publish-baseline.json', 'bad-refresh-quarantine.json',
                 'refresh-backoff.json', 'lease-epochs.json', 'status.json'):
        paths.add(LIVE / 'authbus' / name)
    lines = ['(version 1)', '(deny default)', '(allow process*)', '(allow signal (target children))',
             '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)']
    for path in ('/System', '/usr', '/bin', '/sbin', '/Library', '/private/etc', '/opt/homebrew', '/dev/fd'):
        lines.append('(allow file-read* (subpath ' + json.dumps(path) + '))')
    for path in (ROOT / 'code', ROOT / 'output', QUAL / 'qa'):
        lines.append('(allow file-read* (subpath ' + json.dumps(str(path)) + '))')
    for path in sorted(paths, key=str):
        lines.append('(allow file-read* (literal ' + json.dumps(str(path)) + '))')
    for path in ('/dev/null', '/dev/random', '/dev/urandom'):
        lines.append('(allow file-read* (literal ' + json.dumps(path) + '))')
    lines += ['(allow file-write* (subpath ' + json.dumps(str(ROOT / 'output')) + '))',
              '(allow file-write* (literal "/dev/null"))']
    write(ROOT / 'inventory.sb', ('\n'.join(lines) + '\n').encode())
    created = True
    source_fence()
    sys.path[:0] = [str(ROOT / 'code'), str(QUAL / 'qa')]
    from mac_owned_commands_r1 import Commands, Signals
    import mac_current_gateway_observation_r2 as gateway
    import kv2_dr_process_custody as custody
    signals = Signals()
    signals.install()
    commands = Commands(signals)
    parser = pure_definitions('mac_owned_launchd_r3.py',
        ('ManagerRefused', 'need', 'parse_print', 'missing_service'),
        '8fbb583beab2a49321543b86cb9b76136f6913f0e5382cda2b27a185067cab41', {'re': re})
    native = pure_definitions('mac_native_process_observer_r1.py',
        ('ObservationRefused', 'require', 'BsdInfo', 'ProcessReader'),
        '5dc4cf9b32a7fa45f4ae1fb0619a9d203d5adb20c0e84ed473915e429e45a642',
        {'ctypes': ctypes, 'sys': sys, 'Path': Path})
    report['memoryObservation'] = memory_observation()
    observer = gateway.CurrentGatewayObservation(commands=commands, reader=native['ProcessReader'](),
        parse_print=parser['parse_print'], until=UNTIL, runtime_fence=source_fence,
        private_write=private_write)
    observer.begin()
    # Retained-command helpers above and below never overlap the separate
    # original Python-child custody context.
    with custody.activated() as owner:
        child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(ROOT / 'inventory.sb'),
            PYTHON, '-I', '-S', '-B', str(ROOT / 'code/capture_current_database_inventory_r2.py'), repr(UNTIL)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(ROOT), env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(CALLER_HOME),
                               'LANG': 'C', 'LC_ALL': 'C'})
        out, err = child.communicate(timeout=remaining())
        close_streams()
        need(len(out) <= 262144 and len(err) <= 65536, 'inventory_original_child_stream_bounds')
        private_write('inventory.stdout.public.json', out)
        private_write('inventory.stderr.private', err)
        report['inventoryOriginalChild'] = {'exitCode': child.returncode,
            'stdoutBytes': len(out), 'stderrBytes': len(err), 'streamsClosed': True}
        need(child.returncode == 0 and not err, 'inventory_original_child_known_zero')
        observation = json.loads(out)
        report['inventory'] = observation
        need(observation['ok'] and observation['allOwnedResourcesClosed']
             and observation['kernelReadWriteAndNetworkRefusalsObserved']
             and observation['closeThenNamedGenerationVerified']
             and len(observation['databaseObservations']) == 6,
             'inventory_complete_six_readonly_database_observations')
    report['custody'] = owner.receipt()
    need(report['custody']['passed_process_custody'] and report['custody']['original_count'] == 1,
         'inventory_original_python_child_fully_closed')
    packet = json.loads(read(ROOT / 'output/inventory.private.json', 4 * 1048576, private_file=True))
    raw_config = read(ROOT / 'output/configuration.original.private.json', 1048576, private_file=True)
    need(sha(raw_config) == packet['configurationSha256'], 'inventory_original_private_config_copy')
    verify_names = named_generation_verifier(packet)
    verify_names()
    config_identity = packet['configurationGeneration']['sourceIdentities'][str(CONFIG)]
    observer.bind_configuration(raw_config, config_identity, verify_names)
    _, report['gatewayObservation'] = observer.finish()
    source_fence()
    verify_names()
    remaining()
    report.update(ok=True, allSourcePinsUnchanged=True,
                  gatewayAndInventoryObservedInOneOriginalParent=True,
                  observationsAreDiscreteNotAContinuousLock=True,
                  privateCurrentSourceInventoryPublished=True)
except BaseException as error:
    allowed_types = ('RuntimeError', 'ValueError', 'TypeError', 'OSError', 'PermissionError',
                     'FileNotFoundError', 'TimeoutError', 'ObservationRefused', 'ManagerRefused',
                     'CommandRefused', 'Refusal', 'KeyboardInterrupt')
    report['errorType'] = type(error).__name__ if type(error).__name__ in allowed_types else 'OtherError'
    report['errorCode'] = str(error) if str(error) in codes else 'current_source_inventory_refused'
finally:
    close_streams()
    if observer is not None:
        report['gatewayObservation'] = observer.close()
    if owner is not None:
        report['custody'] = owner.receipt()
    for row in reversed(fds):
        if row['closeAttempts']:
            continue
        try:
            close(row)
        except BaseException:
            pass
    report['parentDescriptors'] = [{key: row[key] for key in ('closeAttempts', 'closed')} for row in fds]
    report['allParentDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in fds)
    report['originalCommands'] = safe_command_rows()
    if commands is not None:
        closure = commands.public()
        report['allOriginalCommandsClosed'] = closure['allOwnedCommandsStopped']
        report['unknownCommandCount'] = closure['unknownCommandCount']
    else:
        report['allOriginalCommandsClosed'] = True
        report['unknownCommandCount'] = 0
    report['createdPrivateRoot'] = created
    report['elapsedSeconds'] = time.monotonic() - START
    if (report.get('originalChildStreamCloseUnknown') or not report['allParentDescriptorsClosedOnce'] or not report['allOriginalCommandsClosed']
            or report['unknownCommandCount'] or observer is not None
            and not report['gatewayObservation']['descriptors']['allOwnedDescriptorsClosedOnce']
            or time.monotonic() >= UNTIL):
        report['ok'] = False
    print(json.dumps(report, sort_keys=True, separators=(',', ':')), flush=True)
raise SystemExit(0 if report['ok'] else 1)
