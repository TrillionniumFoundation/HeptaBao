#!/usr/bin/env python3
"""SOURCE ONLY. Fixed metadata and permission observation, no service or file-body action."""
from __future__ import annotations
import json, os, signal, stat, sys, time

PATHS = json.loads("{\"alias\":\"/opt/homebrew/bin/python3\",\"regular\":\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14\",\"wrapper\":\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/qa/mac_current_server_owner_r1.py\",\"workingDirectory\":\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1\",\"stdout\":\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/launchd/server-initial.stdout.private\",\"stderr\":\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/launchd/server-initial.stderr.private\"}")
DIRS = json.loads("[\"/\",\"/opt\",\"/Volumes\",\"/opt/homebrew\",\"/Volumes/T5\",\"/opt/homebrew/bin\",\"/opt/homebrew/Cellar\",\"/Volumes/T5/hepta-vnext-recovery-20261013\",\"/opt/homebrew/Cellar/python@3.14\",\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1\",\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/launchd\",\"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/qa\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14\",\"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin\"]")
REGULAR_IDENTITY = tuple(["16777233","587518380","501","80","33261","1","34640","1793798038915516382","1793798038915695047"])
ANCHOR_OBJECTS = json.loads("{\"/\":[\"16777233\",\"2\",\"0\",\"0\",\"16877\"],\"/Volumes\":[\"16777233\",\"18336\",\"0\",\"0\",\"16877\"],\"/Volumes/T5\":[\"16777244\",\"2\",\"0\",\"0\",\"16893\"]}")
START = time.monotonic()
UNTIL = START + 5.0
MAX_METADATA_CALLS = 256
MAX_ACCESS_CALLS = 24
MAX_READLINK_CALLS = 2
MAX_LINK_BYTES = 4096
MAX_FD_ROWS = 22
OUTPUT_CAP = 65536
pending = None
stage = 'initial'
active_ordinal = None
counts = {'metadata': 0, 'access': 0, 'readlink': 0, 'linkBytes': 0}
rows = []
by_path = {}

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def caught_signal(number, frame):
    global pending
    if pending is None:
        pending = number

def remaining():
    need(pending is None, 'pending_signal')
    need(time.monotonic() < UNTIL, 'metadata_absolute_deadline')

def consume(kind):
    remaining()
    cap = {'metadata': MAX_METADATA_CALLS, 'access': MAX_ACCESS_CALLS,
           'readlink': MAX_READLINK_CALLS}[kind]
    need(counts[kind] < cap, 'fixed_syscall_bound')
    counts[kind] += 1

def ident(value):
    return tuple(str(x) for x in (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns))

def metadata(fn, *args, **kwargs):
    consume('metadata')
    result = fn(*args, **kwargs)
    remaining()
    return result

def named(path):
    if path == '/':
        return metadata(os.lstat, '/')
    parent, name = os.path.split(path)
    return metadata(os.stat, name, dir_fd=by_path[parent]['fd'], follow_symlinks=False)

def modes(st):
    gids = set(os.getgroups()) | {os.getgid(), os.getegid()}
    shift = 6 if st.st_uid == os.geteuid() else 3 if st.st_gid in gids else 0
    bits = (stat.S_IMODE(st.st_mode) >> shift) & 7
    return {'uid': st.st_uid, 'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode),
            'ownerClass': st.st_uid == os.geteuid(),
            'groupClass': st.st_uid != os.geteuid() and st.st_gid in gids,
            'dacReadBit': bool(bits & 4), 'dacWriteBit': bool(bits & 2),
            'dacExecuteOrSearchBit': bool(bits & 1),
            'notAclTccOrLaunchdProof': True}

def access_for_exact_path(path, mask):
    consume('access')
    if os.access not in os.supports_effective_ids:
        return {'effectiveIdsSupported': False, 'allowed': None}
    value = os.access(path, mask, effective_ids=True)
    remaining()
    return {'effectiveIdsSupported': True, 'allowed': bool(value),
            'observerContextOnly': True, 'launchdContextQualified': False}

def open_fixed(path, directory, access_mask):
    global stage, active_ordinal
    stage = 'fixed_named_before'
    active_ordinal = len(rows)
    need(path in DIRS or path in (PATHS['regular'], PATHS['wrapper'],
         PATHS['stdout'], PATHS['stderr']), 'closed_open_path')
    need(len(rows) < MAX_FD_ROWS, 'fixed_fd_row_cap')
    before = named(path)
    need(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode),
         'fixed_expected_type_no_symlink')
    row = {'ordinal': len(rows), 'path': path, 'directory': directory,
           'fd': None, 'openAttempted': False, 'created': False,
           'closeAttempted': False, 'closed': False, 'before': ident(before)}
    rows.append(row)  # Register an empty slot before open can return a descriptor.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    stage = 'fixed_readonly_metadata_fd_open'
    remaining()
    row['openAttempted'] = True
    if path == '/':
        row['fd'] = os.open('/', flags)
    else:
        parent, name = os.path.split(path)
        row['fd'] = os.open(name, flags, dir_fd=by_path[parent]['fd'])
    row['created'] = True
    # The installed handler only records pending; it never throws across registration.
    stage = 'fixed_fd_and_named_binding'
    current = metadata(os.fstat, row['fd'])
    need(ident(current) == row['before'] == ident(named(path)),
         'fixed_full9_around_open')
    by_path[path] = row
    if path in ANCHOR_OBJECTS:
        need(list(row['before'][:5]) == ANCHOR_OBJECTS[path],
             'original_t5_anchor_object_identity')
    if path == PATHS['regular']:
        need(row['before'] == REGULAR_IDENTITY, 'regular_python_previous_full9')
    if path.startswith('/Volumes/T5/'):
        need(str(before.st_dev) == ANCHOR_OBJECTS['/Volumes/T5'][0],
             'same_observed_t5_device')
    row['permissionBits'] = modes(current)
    row['access'] = access_for_exact_path(path, access_mask)
    return row

def readlink_fixed():
    consume('readlink')
    parent, name = os.path.split(PATHS['alias'])
    value = os.readlink(name, dir_fd=by_path[parent]['fd'])
    encoded = os.fsencode(value)
    counts['linkBytes'] += len(encoded)
    need(len(encoded) <= MAX_LINK_BYTES, 'bounded_symlink_text')
    remaining()
    return value

def observe_alias(result):
    global stage, active_ordinal
    active_ordinal = MAX_FD_ROWS
    stage = 'fixed_alias_before'
    before = named(PATHS['alias'])
    need(stat.S_ISLNK(before.st_mode) or stat.S_ISREG(before.st_mode),
         'original_alias_file_or_symlink')
    link = None
    if stat.S_ISLNK(before.st_mode):
        need(0 <= before.st_size <= MAX_LINK_BYTES, 'alias_metadata_link_bound')
        link = readlink_fixed()
    # These two exact-path stat calls let the kernel resolve the old alias.
    # No application target traversal/open, no new path admission or body read.
    stage = 'fixed_alias_follow_stat'
    first_target = metadata(os.stat, PATHS['alias'], follow_symlinks=True)
    permission = access_for_exact_path(PATHS['alias'], os.X_OK)
    second_target = metadata(os.stat, PATHS['alias'], follow_symlinks=True)
    if link is not None:
        need(link == readlink_fixed(), 'same_fixed_alias_link_twice')
    after = named(PATHS['alias'])
    need(ident(before) == ident(after), 'fixed_alias_full9_stable')
    need(ident(first_target) == ident(second_target), 'fixed_alias_target_stable')
    regular = metadata(os.fstat, by_path[PATHS['regular']]['fd'])
    one_hop = None if link is None else os.path.normpath(
        link if os.path.isabs(link) else os.path.join(os.path.dirname(PATHS['alias']), link))
    result['originalInterpreterAlias'] = {
        'path': PATHS['alias'], 'beforeIdentity': list(ident(before)),
        'afterIdentity': list(ident(after)), 'isSymlink': stat.S_ISLNK(before.st_mode),
        'stableAliasAndTarget': True, 'targetIsRegular': stat.S_ISREG(first_target.st_mode),
        'targetFull9EqualsObservedRegularInterpreter': ident(first_target) == ident(regular),
        'singleLexicalHopEqualsObservedRegularPath': one_hop == PATHS['regular'],
        'unknownLinkTextPublished': False, 'unknownLinkHashPublished': False,
        'permission': permission, 'sequentialNotAtomicResolution': True}

def recheck_all():
    global stage, active_ordinal
    stage = 'final_named_fd_full9'
    for row in rows:
        active_ordinal = row['ordinal']
        remaining()
        need(row['created'] and ident(metadata(os.fstat, row['fd'])) == row['before']
             == ident(named(row['path'])), 'fixed_full9_final_drift')

def public_error(error):
    number = getattr(error, 'errno', None)
    return {'type': type(error).__name__,
            'code': str(error) if isinstance(error, Refused) else None,
            'errno': number if type(number) is int and 0 <= number <= 4095 else None,
            'stage': stage, 'fixedPathOrdinal': active_ordinal,
            'messageOrDynamicFilenamePublished': False}

def main():
    global stage, active_ordinal
    previous = {}
    installed = []
    work_complete = False
    result = {'schema': 'heptabao.mac-owned-launchd-path-metadata.r1',
        'ok': False, 'outcomeUnknown': False, 'originalJob': '1a1ae51309d-fc05-5ef8',
        'target': 'gui/501/org.heptabao.qa.mac-authbus-4e808-owner-r1.server',
        'newSharedSeconds': 5, 'outerSeconds': 60,
        'privateFileBodyBytesRead': 0, 'publicFileBodyBytesRead': 0,
        'applicationChildrenCreated': 0, 'serviceMutationAttempted': False,
        'configurationChanged': False, 'directoryEnumerationPerformed': False,
        'sdkOrProviderExecuted': False, 'originalRegistrationClosureQualified': False,
        'historicalLineageClosureQualified': False, 'launchdStartupCauseQualified': False,
        'currentFileWholeHashObserved': False,
        'noHashQualificationFromMetadata': True,
        'observedContextIsNotLaunchdTccContext': True,
        'kernelAliasResolutionDoesNotAdmitOtherTargets': True,
        'syscallsAreSynchronousNotHardPreemptible': True}
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.geteuid() == 501,
             'fixed_mac_observer_identity')
        need(sys.executable == PATHS['regular'], 'exact_observed_regular_interpreter')
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, caught_signal)
            installed.append(sig)
        for path in DIRS:
            open_fixed(path, True, os.X_OK)
        for name, permission in (('regular', os.X_OK), ('wrapper', os.R_OK),
                                 ('stdout', os.W_OK), ('stderr', os.W_OK)):
            open_fixed(PATHS[name], False, permission)
        observe_alias(result)
        recheck_all()
        work_complete = True
    except BaseException as error:
        result['error'] = public_error(error)
    finally:
        close_errors = []
        for row in reversed(rows):
            if row['fd'] is not None and not row['closeAttempted']:
                row['closeAttempted'] = True
                try:
                    os.close(row['fd'])
                    row['closed'] = True
                except BaseException as error:
                    close_errors.append({'ordinal': row['ordinal'], 'type': type(error).__name__})
        restore_errors = []
        for sig in reversed(installed):
            try:
                signal.signal(sig, previous[sig])
            except BaseException as error:
                restore_errors.append(type(error).__name__)
        result['closeErrors'] = close_errors
        result['signalRestoreErrors'] = restore_errors
    closed = all(row['fd'] is None or (row['closeAttempted'] and row['closed']) for row in rows)
    result['fixedPaths'] = [{k: v for k, v in row.items() if k != 'fd'} for row in rows]
    result['allReturnedApplicationDescriptorsClosed'] = closed
    result['applicationFdScopeDoesNotEnumerateInterpreterInternalFds'] = True
    result['pendingSignalAfterHandlerRestore'] = pending
    final_clock = time.monotonic()
    result['elapsedSeconds'] = final_clock - START
    result['deadlineMetAfterClosure'] = final_clock < UNTIL
    result['budget'] = dict(counts)
    result['outcomeUnknown'] = bool(not closed or result['closeErrors']
        or result['signalRestoreErrors'] or pending is not None)
    result['ok'] = bool(work_complete and not result['outcomeUnknown'] and final_clock < UNTIL)
    result['authoritativeExitZeroAndCompleteFinalStdoutRequired'] = True
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
    if len(raw) > OUTPUT_CAP:
        return 1
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    if time.monotonic() >= UNTIL or pending is not None:
        return 1
    return 0 if result['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
