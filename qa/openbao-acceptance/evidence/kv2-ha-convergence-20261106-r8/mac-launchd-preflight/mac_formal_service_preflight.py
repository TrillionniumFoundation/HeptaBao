#!/usr/bin/env python3
"""One bounded read-only query of three exact launchd labels and fixed metadata."""
import time
ENTRY = time.monotonic()
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
PARENT = ROOT / 'control'
OUT = PARENT / 'formal-kv2-service-admission-preflight-r1'
QA = ROOT / 'source-dr25-a2577-r2/qa/openbao-acceptance'
LABEL = 'org.heptabao.kv2'
LAUNCH_AGENTS = Path('/Users/qianqi/Library/LaunchAgents')
PRODUCTION = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
CURRENT_BASE = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1')
METADATA_PATHS = {
    'launch_agents_parent': LAUNCH_AGENTS,
    'candidate_user_plist': LAUNCH_AGENTS / (LABEL + '.plist'),
    'existing_production_root': PRODUCTION,
    'proposed_new_native_root': PRODUCTION / 'formal-kv2-current-20261106-r1',
    'current_internal_base': CURRENT_BASE,
}
COMMANDS = (
    ('gui_disabled', 'gui/501', ['print-disabled', 'gui/501']),
    ('user_disabled', 'user/501', ['print-disabled', 'user/501']),
    ('gui_label', 'gui/501', ['print', 'gui/501/' + LABEL]),
    ('user_label', 'user/501', ['print', 'user/501/' + LABEL]),
    ('system_label', 'system', ['print', 'system/' + LABEL]),
)
HELPERS = {
    'kv2_dr_process_custody.py': (26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
    'owned_process.py': (28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
}
END = ENTRY + 52
TOTAL_END = ENTRY + 60
FIRED = INTERRUPTED = PROTECTED = FINISHING = False
CUSTODY = OWNER = CONTROL = None
DIRECTORIES = []
READS = []
BEFORE = {}
PRIVATE = {'schema': 'heptabao.mac-exact-launchd-service-preflight.private.v1'}
PUBLIC = {
    'schema': 'heptabao.mac-exact-launchd-service-preflight.public.v1',
    'status': 'failed', 'observation_complete': False,
    'candidate_label': LABEL, 'exact_domains': ['gui/501', 'user/501', 'system'],
    'requested_query_count': 5, 'work_seconds': 52, 'runtime_seconds': 60,
    'per_command_maximum_seconds': 5, 'automatic_retry': False,
    'all_mac_domains_scanned': False, 'full_host_service_inventory_qualified': False,
    'continuous_label_or_port_exclusivity_claimed': False,
    'port_18240_observed_or_reserved': False,
    'launchctl_bootstrap_or_bootout_called': False, 'service_started_or_stopped': False,
    'manager_configuration_written': False, 'business_source_opened': False,
    'old_tls_keys_or_configuration_opened': False, 'sudo_called': False,
    'provider_or_j3160_called': False, 'product_or_sdk_executed': False,
    'credential_values_or_private_command_output_published': False,
    'prior_current_base_historical_identity_claimed': False,
    'formal_kv2_qualified': False, 'ha_qualified': False, 'authbus_qualified': False,
    'traffic_cutover_performed': False, 'old_assets_removed': False,
    'durable_completion_authority': 'original_runtime_terminal_and_final_stdout_with_60_second_cap',
}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def check():
    need(not FIRED and not INTERRUPTED and time.monotonic() < END, 'original_preflight_deadline')


def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    owner = getattr(CUSTODY, '_ACTIVE', None) if CUSTODY is not None else None
    if owner is not None:
        owner._interrupt(signum, frame)
    elif not PROTECTED and not FINISHING:
        raise Interrupted()


def directory_identity(path, fd=None):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'canonical_observed_directory')
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode), 'observed_directory_required')
    identity = [value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)]
    if fd is not None:
        held = os.fstat(fd)
        need(stat.S_ISDIR(held.st_mode)
             and identity == [held.st_dev, held.st_ino, held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)],
             'observed_directory_original_handle')
    return identity


def hold_directory(path, *, private=False):
    global PROTECTED
    path = Path(path)
    pin = directory_identity(path)
    if private:
        need(pin[2] == 501 and pin[4] == 0o700, 'owned_private_control_directory')
    for row in DIRECTORIES:
        if row['path'] == path:
            need(row['identity'] == pin == directory_identity(path, row['fd']), 'retained_directory_identity')
            return row
    previous = PROTECTED
    PROTECTED = True
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(pin == directory_identity(path, fd), 'directory_open_identity_race')
        row = {'path': path, 'identity': pin, 'fd': fd}
        DIRECTORIES.append(row)
        fd = None
        return row
    finally:
        if fd is not None:
            os.close(fd)
        PROTECTED = previous


def directories_unchanged():
    for row in DIRECTORIES:
        need(row['identity'] == directory_identity(row['path'], row['fd']), 'original_directory_identity_changed')


def create_output():
    global CONTROL, PROTECTED
    parent = hold_directory(PARENT, private=True)
    try:
        OUT.lstat()
    except FileNotFoundError:
        pass
    else:
        raise Refused('new_preflight_root_must_be_absent')
    PROTECTED = True
    try:
        os.mkdir(OUT.name, 0o700, dir_fd=parent['fd'])
        os.fsync(parent['fd'])
        CONTROL = hold_directory(OUT, private=True)
    finally:
        PROTECTED = False
    directories_unchanged()


def private_new(name, raw):
    need(CONTROL is not None and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', name), 'fixed_owned_output_name')
    directories_unchanged()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=CONTROL['fd'])
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        info = os.fstat(fd)
        after = os.stat(name, dir_fd=CONTROL['fd'], follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw)
             and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'owned_output_file_identity')
    finally:
        os.close(fd)
    os.fsync(CONTROL['fd'])
    directories_unchanged()


def read_tool(path, *, expected=None, maximum=32 * 1024 * 1024):
    check()
    path = Path(path)
    need(path.resolve(strict=True) == path, 'canonical_fixed_tool')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_uid in (0, 501) and first.st_nlink == 1
             and not (stat.S_IMODE(first.st_mode) & 0o022) and 0 <= first.st_size <= maximum,
             'bounded_fixed_tool_custody')
        blocks, count, digest = [], 0, hashlib.sha256()
        while True:
            check()
            block = os.read(fd, 65536)
            if not block:
                break
            blocks.append(block)
            count += len(block)
            need(count <= maximum, 'fixed_tool_byte_bound')
            digest.update(block)
        def identity(st):
            return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_nlink,
                    st.st_size, st.st_mtime_ns, st.st_ctime_ns]
        need(identity(first) == identity(os.fstat(fd)) == identity(path.lstat()) and count == first.st_size,
             'fixed_tool_changed_during_read')
        pin = (count, digest.hexdigest())
        need(expected is None or pin == expected, 'fixed_tool_bytes')
        READS.append((path, pin, identity(first)))
        return b''.join(blocks), pin
    finally:
        os.close(fd)


def observe(path):
    check()
    path = Path(path)
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {'exists': False}
    mode = st.st_mode
    kind = 'directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else 'other'
    result = {'exists': True, 'kind': kind, 'canonical': path.resolve(strict=True) == path,
              'dev': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
              'mode': stat.S_IMODE(mode), 'nlink': st.st_nlink}
    if kind != 'directory':
        result.update(bytes=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)
    return result


def classify(role, domain, returncode, stdout, stderr):
    row = {'role': role, 'domain': domain, 'exit_code': returncode,
           'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr)}
    body = (stdout + b'\n' + stderr).decode('utf-8', errors='strict')
    if role.endswith('_disabled'):
        if returncode == 0:
            row.update(outcome='domain_available', domain_exists=True)
            matches = re.findall(r'"' + re.escape(LABEL) + r'"\s*=>\s*(true|false)', body)
            need(len(matches) <= 1, 'candidate_disabled_entry_not_ambiguous')
            row['candidate_explicit_disabled_override'] = None if not matches else matches[0] == 'true'
        elif 'Could not find domain' in body or 'No such process' in body:
            row.update(outcome='domain_unavailable', domain_exists=False)
        else:
            row.update(outcome='unresolved_query_failure', domain_exists=None)
    else:
        row['label'] = LABEL
        if returncode == 0:
            row.update(outcome='label_present', label_present=True)
            pids = re.findall(r'(?m)^\s*pid = ([0-9]+)\s*$', body)
            row['observed_pid'] = int(pids[0]) if len(pids) == 1 else None
        elif 'Could not find service' in body and ('"' + LABEL + '"') in body:
            row.update(outcome='label_absent_in_exact_domain_query', label_present=False)
        elif 'Could not find domain' in body:
            row.update(outcome='domain_unavailable_for_exact_label_query', label_present=None)
        else:
            row.update(outcome='unresolved_query_failure', label_present=None)
    return row


def safe_custody(receipt):
    children = []
    for index, child in enumerate(receipt.get('children', [])):
        row = {key: child.get(key) for key in ('pid', 'exec_admitted', 'returncode', 'original_wait_completed',
                                              'original_wait_count', 'no_live_members_before_reap')}
        row.update(index=index, gaps_count=len(child.get('gaps', [])),
                   birth={key: child.get('birth', {}).get(key) for key in ('pid', 'ppid', 'pgid', 'sid', 'uid', 'state')})
        for name in ('members_at_leader_exit', 'members_before_original_reap'):
            row[name] = [{key: member.get(key) for key in ('pid', 'ppid', 'pgid', 'sid', 'uid', 'state')}
                         for member in child.get(name, [])]
        children.append(row)
    return {'original_count': receipt.get('original_count'), 'finished': receipt.get('finished'),
            'passed_process_custody': receipt.get('passed_process_custody'), 'failed': receipt.get('failed'),
            'interrupted': receipt.get('interrupted'), 'children': children,
            'escaped_session_containment_claim': False}


def run():
    global CUSTODY, OWNER
    need(sys.platform == 'darwin' and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3)
         and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1, 'fixed_mac_isolated_python')
    read_tool(Path(sys.executable).resolve(strict=True), expected=(34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'))
    for name, pin in HELPERS.items():
        read_tool(QA / name, expected=pin)
    sys.path.insert(0, str(QA))
    CUSTODY = importlib.import_module('kv2_dr_process_custody')
    need(Path(CUSTODY.__file__).resolve(strict=True) == QA / 'kv2_dr_process_custody.py', 'fixed_custody_import')
    _, command_pin = read_tool(Path('/bin/launchctl'))
    PUBLIC['observed_launchctl_tool_bytes'] = command_pin[0]
    PUBLIC['observed_launchctl_tool_sha256'] = command_pin[1]
    create_output()
    for role, path in METADATA_PATHS.items():
        BEFORE[role] = observe(path)
        if BEFORE[role].get('kind') == 'directory' and BEFORE[role]['canonical']:
            hold_directory(path)
    PRIVATE['fixed_metadata_paths'] = {role: str(path) for role, path in METADATA_PATHS.items()}
    rows = []
    with CUSTODY.activated() as owner:
        OWNER = owner
        for index, (role, domain, args) in enumerate(COMMANDS):
            check()
            result = subprocess.run(['/bin/launchctl', *args], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=OUT,
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'},
                                    timeout=min(5.0, max(0.001, END - time.monotonic())), check=False)
            private_new(f'query-{index}.stdout.private', result.stdout)
            private_new(f'query-{index}.stderr.private', result.stderr)
            need(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024,
                 'launchctl_output_bound_hit')
            row = classify(role, domain, result.returncode, result.stdout, result.stderr)
            row['index'] = index
            rows.append(row)
        owner.assert_retired()
    receipt = OWNER.receipt()
    need(receipt['original_count'] == len(receipt['children']) == len(rows) == 5
         and receipt['finished'] is True and receipt['passed_process_custody'] is True
         and receipt['failed'] is False and receipt['interrupted'] is False, 'five_original_queries_retired')
    for index, child in enumerate(receipt['children']):
        need(child['exec_admitted'] is True and child['original_wait_completed'] is True
             and child['original_wait_count'] == 1 and child['no_live_members_before_reap'] is True
             and child['gaps'] == [] and child['returncode'] == rows[index]['exit_code'], 'each_original_query_retired')
    PUBLIC['queries'] = rows
    PUBLIC['observed_query_count'] = len(rows)
    for role, path in METADATA_PATHS.items():
        need(observe(path) == BEFORE[role], 'fixed_metadata_changed_during_queries')
    PUBLIC['metadata'] = BEFORE
    PUBLIC['fixed_metadata_unchanged_during_observation'] = True
    for path, pin, identity in list(READS):
        _, current = read_tool(path, expected=pin)
        need(current == pin and READS[-1][2] == identity, 'fixed_tools_changed_during_observation')
    directories_unchanged()
    need(all(row['outcome'] != 'unresolved_query_failure' for row in rows), 'unresolved_exact_launchctl_observation')
    disabled = {row['domain']: row for row in rows[:2]}
    labels = {row['domain']: row for row in rows[2:]}
    domain_gate = all(disabled[name]['domain_exists'] is True for name in ('gui/501', 'user/501'))
    disabled_gate = all(disabled[name].get('candidate_explicit_disabled_override') is not True
                        for name in ('gui/501', 'user/501'))
    label_gate = all(labels[name]['label_present'] is False for name in ('gui/501', 'user/501', 'system'))
    launch_parent = BEFORE['launch_agents_parent']
    launch_parent_gate = (launch_parent.get('kind') == 'directory' and launch_parent['canonical']
                          and launch_parent['uid'] == 501 and not (launch_parent['mode'] & 0o022)
                          and (launch_parent['mode'] & 0o300) == 0o300)
    root_gate = all(BEFORE[name].get('kind') == 'directory' and BEFORE[name]['canonical']
                    and BEFORE[name]['uid'] == 501 and BEFORE[name]['mode'] == 0o700
                    for name in ('existing_production_root', 'current_internal_base'))
    absent_gate = (BEFORE['candidate_user_plist']['exists'] is False
                   and BEFORE['proposed_new_native_root']['exists'] is False)
    PUBLIC.update(status='observed', observation_complete=True,
                  gui_and_user_domains_available=domain_gate,
                  candidate_explicit_gui_or_user_disable_override_absent=disabled_gate,
                  all_three_exact_label_queries_observed_absent=label_gate,
                  owned_launch_agents_parent_acceptable=bool(launch_parent_gate),
                  existing_private_data_parents_acceptable=root_gate,
                  candidate_plist_and_native_root_both_absent=absent_gate,
                  point_in_time_user_manager_preflight_clear=bool(domain_gate and disabled_gate and label_gate and launch_parent_gate and root_gate and absent_gate))
    check()


def main():
    global FINISHING, CONTROL
    signals = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    old_handlers = {number: signal.getsignal(number) for number in signals}
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    old_umask = os.umask(0o077)
    code, armed, primary, cleanup = 1, False, None, []
    try:
        need(old_timer == (0.0, 0.0), 'ambient_timer_refused')
        for number in signals:
            signal.signal(number, interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, END - time.monotonic()))
        armed = True
        run()
        code = 0
    except BaseException as error:
        value = str(error) if isinstance(error, Refused) else type(error).__name__
        primary = value if re.fullmatch(r'[A-Za-z0-9_]{1,100}', value) else 'private_preflight_failure'
        PUBLIC.update(status='failed', observation_complete=False)
    finally:
        FINISHING = True
        try:
            if OWNER is not None:
                OWNER.finish()
                receipt = OWNER.receipt()
                PRIVATE['owned_process_custody'] = receipt
                PUBLIC['owned_launchctl_process_custody'] = safe_custody(receipt)
                need(receipt['finished'] is True and receipt['passed_process_custody'] is True
                     and receipt['failed'] is False, 'original_process_cleanup_incomplete')
        except BaseException as error:
            cleanup.append('original_process_cleanup_incomplete')
            code = 1
        try:
            directories_unchanged()
            PUBLIC['original_directory_paths_and_handles_preserved'] = True
        except BaseException:
            cleanup.append('original_directory_identity_changed')
            code = 1
        elapsed = time.monotonic() - ENTRY
        if FIRED or INTERRUPTED or elapsed >= 52:
            cleanup.append('original_work_deadline_or_interrupt')
            code = 1
        if code:
            PUBLIC.update(status='failed', observation_complete=False)
        PUBLIC.update(primary_failure_code=primary, cleanup_failure_codes=list(cleanup),
                      deadline_fired=FIRED, interrupted=INTERRUPTED,
                      elapsed_observation_before_receipt_publication_seconds=elapsed,
                      partial_owned_observation_retained=bool(code), owned_directory_handle_count=len(DIRECTORIES))
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if CONTROL is not None:
            try:
                PRIVATE['public_before_receipt'] = dict(PUBLIC)
                private_new('observation.private.json', (json.dumps(PRIVATE, sort_keys=True, indent=2) + '\n').encode())
                private_new('result.public.json', (json.dumps(PUBLIC, sort_keys=True, indent=2) + '\n').encode())
            except BaseException:
                cleanup.append('owned_receipt_publication_failed')
                code = 1
        closed = 0
        for row in reversed(DIRECTORIES):
            try:
                os.close(row['fd'])
                closed += 1
            except OSError:
                cleanup.append('original_directory_handle_close_failed')
                code = 1
        CONTROL = None
        PUBLIC['owned_directory_handles_closed'] = closed
        PUBLIC['all_owned_directory_handles_retired'] = closed == len(DIRECTORIES)
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        if armed:
            signal.setitimer(signal.ITIMER_REAL, *old_timer)
        os.umask(old_umask)
        if FIRED or INTERRUPTED or time.monotonic() >= TOTAL_END:
            cleanup.append('original_total_deadline_or_final_interrupt')
            code = 1
        PUBLIC['cleanup_failure_codes'] = cleanup
        if code:
            PUBLIC.update(status='failed', observation_complete=False)
        print(json.dumps(PUBLIC, sort_keys=True, separators=(',', ':')), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
