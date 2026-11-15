#!/usr/bin/env python3
"""Parse only the already captured private R3 gateway inputs; never execute them."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

PAYLOAD = {}  # ASSEMBLED_PUBLIC_SOURCES
START = time.monotonic()
UNTIL = START + 15
BASE = Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r3/output')
OUTPUT = Path('/Users/qianqi/heptabao-current-r3-wrapper-source-20261106-r1')
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
rows, originals, codes = [], [], set()
report = {'schema': 'heptabao.parameter-wrapper-private-copy-qualification.public.r1',
          'ok': False, 'originalInventoryJob': '1a1b3333a55-fc05-8103',
          'originalWrapperJob': '1a1b337c5dc-fc05-8123',
          'originalEnvironmentJob': '1a1b33a5411-fc05-813d',
          'historicalPrivateCopiesOnly': True, 'currentProductionFilesRead': 0,
          'childCount': 0, 'sqlConnections': 0, 'networkCalls': 0,
          'providerCalls': 0, 'serviceActions': 0, 'productionWrites': 0,
          'actualShellExecutionQualified': False, 'actualCurrentSdkSelectionQualified': False,
          'productionFallbackQualified': False,
          'privateNamesValuesOrDigestsPublished': False, 'privateReviewOutputs': 0}


def need(value, code):
    if not value:
        codes.add(code)
        raise RuntimeError(code)


def within():
    need(time.monotonic() < UNTIL, 'original_private_copy_projection_deadline')


def identity(value):
    return tuple(getattr(value, name) for name in FIELDS)


def track(fd, path):
    row = {'fd': fd, 'path': path, 'closeAttempts': 0, 'closed': False}
    rows.append(row)
    row['identity'] = identity(os.fstat(fd))
    return row


def close(row):
    if not row['closeAttempts']:
        row['closeAttempts'] += 1
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            codes.add('original_descriptor_close_unknown')


def parents(path):
    held, parent = [], None
    try:
        for part in [Path('/'), *list(reversed(path.parents))[1:], path]:
            within()
            fd = (os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) if parent is None
                  else os.open(part.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
            row = track(fd, part)
            held.append(row)
            info = os.fstat(fd)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 501)
                 and not stat.S_IMODE(info.st_mode) & 0o022,
                 'private_copy_parent_custody')
            need(identity(info) == identity(part.lstat()), 'same_named_private_parent')
            parent = fd
        return held
    except BaseException:
        for row in reversed(held):
            close(row)
        raise


def read(path, *, record=True):
    within()
    held = parents(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=held[-1]['fd'])
        row = track(fd, path)
        held.append(row)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and 0 < info.st_size <= 1048576, 'fixed_private_copy_file_custody')
        raw = bytearray()
        while len(raw) <= info.st_size:
            within()
            part = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == info.st_size, 'complete_private_copy_bytes')
        for item in held:
            need(identity(os.fstat(item['fd'])) == item['identity'] == identity(item['path'].lstat()),
                 'same_full9_during_private_copy_read')
        raw = bytes(raw)
        if record:
            originals.append((path, row['identity'], raw))
        return raw
    finally:
        for row in reversed(held):
            close(row)


def write(name, raw):
    within()
    held = parents(OUTPUT)
    parent = held[-1]
    try:
        need(stat.S_IMODE(os.fstat(parent['fd']).st_mode) == 0o700,
             'original_private_projection_root_0700')
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent['fd'])
        row = track(fd, OUTPUT / name)
        held.append(row)
        view = memoryview(raw)
        while view:
            within()
            count = os.write(fd, view)
            need(count > 0, 'private_review_write_progress')
            view = view[count:]
        os.fsync(fd)
        need(os.pread(fd, len(raw) + 1, 0) == raw, 'private_review_durable_whole_bytes')
        os.fsync(parent['fd'])
        # Only this pre-existing private observation directory receives new
        # entries. Bind its original inode/owner/mode; do not claim unchanged
        # mtime/ctime for our own newly created review artifacts.
        need(identity(os.fstat(parent['fd']))[:5] == parent['identity'][:5]
             == identity(OUTPUT.lstat())[:5], 'same_owned_private_output_directory')
        report['privateReviewOutputs'] += 1
    finally:
        for row in reversed(held):
            close(row)


try:
    need(sys.platform == 'darwin' and os.getuid() == 501 and set(PAYLOAD) == {
        'mac_gateway_local_fallback_r1.py', 'mac_gateway_parameter_wrapper_fallback_r1.py'},
        'fixed_actual_mac_and_public_source_scope')
    for filename in ('mac_gateway_local_fallback_r1.py', 'mac_gateway_parameter_wrapper_fallback_r1.py'):
        source = PAYLOAD[filename]
        raw = base64.b64decode(source['base64'], validate=True)
        need(hashlib.sha256(raw).hexdigest() == source['sha256'], 'whole_public_source_pin')
        name = filename[:-3]
        need(name not in sys.modules, 'original_pure_module_not_preimported')
        module = types.ModuleType(name)
        module.__file__ = '<source-bound-pure-' + filename + '>'
        sys.modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    fallback = sys.modules['mac_gateway_parameter_wrapper_fallback_r1']
    binding = fallback.original.strict_json(read(BASE / 'gateway-restore-inputs.private.json'))
    config = read(BASE / 'configuration.original.private.json')
    plist = read(BASE / 'gateway-original.plist.private')
    wrapper_record = fallback.original.strict_json(read(OUTPUT / 'binding.private.json'))
    environment_record = fallback.original.strict_json(read(OUTPUT / 'environment-binding.private.json'))
    wrapper = read(OUTPUT / 'registered-script.original.private')
    environment = read(OUTPUT / 'environment.original.private')
    need(wrapper_record['originalInventoryJob'] == environment_record['originalInventoryJob']
         == report['originalInventoryJob'] and environment_record['originalWrapperProjectionJob']
         == report['originalWrapperJob'] and environment_record['present'] is True,
         'same_original_private_observation_authority')
    source_binding = {'schema': 'heptabao.current-parameter-wrapper.private.r1',
        'arguments': wrapper_record['arguments'], 'wrapperPath': wrapper_record['scriptPath'],
        'wrapperFull9': wrapper_record['scriptFull9'], 'wrapperSha256': wrapper_record['scriptSha256'],
        'environmentPath': environment_record['environmentPath'],
        'environmentFull9': environment_record['environmentFull9'],
        'environmentSha256': environment_record['environmentSha256'],
        'historicalPrivateCopiesOnly': True, 'sameParentRetainedDescriptors': False}
    prepared = fallback.make_parameter_wrapper_fallback(config, plist, binding,
                                                         wrapper, environment, source_binding)
    report['strictLiteralAssignmentCount'] = len(prepared['originalLiteralValues'])
    report['strictLiteralExportedCount'] = sum(prepared['originalLiteralExportFlags'].values())
    report['fallback'] = prepared['public']
    for name, raw in (
        ('strict-fallback-r1.review.config.private.json', prepared['configBytes']),
        ('strict-fallback-r1.review.plist.private', prepared['plistBytes']),
        ('strict-fallback-r1.review.environment.private', prepared['environmentBytes']),
        ('strict-fallback-r1.source-binding.private.json',
         (json.dumps(source_binding, sort_keys=True, separators=(',', ':')) + '\n').encode()),
    ):
        write(name, raw)
    for path, before, raw in originals:
        need(identity(path.lstat()) == before and read(path, record=False) == raw,
             'all_original_private_copies_full9_and_whole_bytes_stable')
    within()
    report.update(ok=True, fixedPrivateCopiesVerified=len(originals),
                  publicPureSourcePins={key: value['sha256'] for key, value in PAYLOAD.items()},
                  strictOriginalParameterWrapperAccepted=True,
                  originalConfigurationAndOtherPlistValuesPreserved=True,
                  originalCopiesUnchanged=True)
except BaseException as error:
    code = str(error)
    if re.fullmatch(r'(?:wrapper|fallback)_[a-z0-9_]{1,128}', code):
        codes.add(code)
    report.update(ok=False, errorType=type(error).__name__, refusalCodes=sorted(codes))
finally:
    for row in reversed(rows):
        close(row)
    report.update(descriptorsOpened=len(rows), descriptorsClosed=sum(row['closed'] for row in rows),
                  allDescriptorsClosedOnce=all(row['closed'] and row['closeAttempts'] == 1 for row in rows),
                  elapsedSeconds=time.monotonic() - START)
    if not report['allDescriptorsClosedOnce'] or time.monotonic() >= UNTIL:
        report['ok'] = False
print(json.dumps(report, sort_keys=True, separators=(',', ':')))
raise SystemExit(0 if report['ok'] else 1)
