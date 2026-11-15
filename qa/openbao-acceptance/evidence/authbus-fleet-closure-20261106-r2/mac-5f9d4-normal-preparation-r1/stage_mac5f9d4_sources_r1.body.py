#!/usr/bin/env python3
"""Create only this normal-build controller and selection on the fixed T5."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OUT = ROOT / 'build-test-5f9d4-r1'
SOURCE = ROOT / 'source-5f9d4-r1'
BUNDLE = ROOT / 'control/candidate-5f9d4-from-4bde9.bundle'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
START = time.monotonic()
UNTIL = START + 45
CONTROL = None
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
# PAYLOAD_PLACEHOLDER
REPORT = {'schema': 'heptabao.mac-normal5f9d4-source-staging.r1', 'ok': False,
    'sourceCommit': '5f9d4263b136685244aba93e45a69139cb8aba41',
    'sourceTree': '2c69f04159c112a883abe57f0d367a2627197c7a',
    'newOutput': str(OUT), 'newCloneNotCreated': str(SOURCE),
    'bundleDestination': str(BUNDLE), 'bundleUploaded': False,
    'compilerCommands': 0, 'sourceCheckoutCommands': 0, 'productProcesses': 0,
    'currentCredentialsRead': 0, 'productionChanged': False,
    'normal107Qualified': False, 'directed15Qualified': False,
    'parentSeconds': 45, 'supervisorSeconds': 70, 'automaticRetry': False,
    'createdFiles': []}


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def remaining():
    need(CONTROL is None or CONTROL.pending is None, 'staging_cancelled')
    value = UNTIL - time.monotonic()
    need(value > 0, 'staging_original_deadline')
    return value


def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def main():
    global CONTROL
    volume = commands = signals = None
    try:
        os.umask(0o077); sys.dont_write_bytecode = True
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'staging_exact_mac_python_owner')
        for name, text in PAYLOAD['sources'].items():
            raw = text.encode(); pin = PAYLOAD['pins'][name]
            need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'staging_complete_helper_pin')
            ast.parse(text)
            module = types.ModuleType(Path(name).stem); module.__file__ = str(OUT / name)
            sys.modules[module.__name__] = module
            exec(compile(text, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from mac_normal_build_t5_guard_r1 import HeldT5
        signals = Signals(); signals.install(); CONTROL = signals
        commands = Commands(signals)
        pins = {}
        for name, expected in TOOL_PINS.items():
            value = public_code_pin(name, remaining=remaining, critical=signals.critical)
            need((value['bytes'], value['sha256']) == expected, 'staging_exact_native_tool')
            pins[name] = value
        need(not OUT.exists() and not OUT.is_symlink() and not SOURCE.exists() and not SOURCE.is_symlink()
             and not BUNDLE.exists() and not BUNDLE.is_symlink(), 'staging_three_new_destinations_absent')
        need(ROOT.is_dir() and ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_uid == 501
             and ROOT.stat().st_gid == 20 and stat.S_IMODE(ROOT.stat().st_mode) == 0o700,
             'staging_original_private_continuation_root')
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(json.dumps(PAYLOAD['pins'], sort_keys=True).encode()).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758', 'expectedVolumeDevice': '16777244',
            'anchors': [{'path': p, 'identity': list(full9(Path(p).lstat()))} for p in ('/', '/Volumes', '/Volumes/T5')]}
        raw = (json.dumps(anchor, sort_keys=True, separators=(',', ':')) + '\n').encode()
        volume = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('normal5f9d4-staging-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
            until=min(UNTIL, time.monotonic() + 10), maximum=262144)
        need(type(row['exitCode']) is int and row['exitCode'] == 0 and not row['outcomeUnknown'] and not err,
             'staging_original_volume_command_known_success')
        volume.accept_diskutil(out)
        need(set(PAYLOAD['files']) == {'controller.original.py', 'test-selection.public.json'}, 'staging_exact_two_files')
        volume.mkdir_new(OUT)
        for name, text in PAYLOAD['files'].items():
            raw = text.encode(); pin = PAYLOAD['filePins'][name]
            need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'staging_public_source_pin')
            receipt = volume.write_new(OUT / name, raw)
            need(volume.read(OUT / name, 1048576) == raw, 'staging_whole_published_readback')
            REPORT['createdFiles'].append({'name': name, **pin, 'identity': receipt['identity']})
        with volume.parent(BUNDLE) as (parent, name):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused('staging_bundle_became_present')
        need(not SOURCE.exists() and not SOURCE.is_symlink(), 'staging_clone_still_absent')
        volume.check()
        for name, expected in pins.items():
            need(public_code_pin(name, remaining=remaining, critical=signals.critical) == expected,
                 'staging_original_tools_unchanged')
        REPORT.update(ok=True, originalT5UuidVerified=True, twoWholeFilesReadBack=True,
                      newSourceAndBundleAbsent=True)
    except BaseException as error:
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) else 'normal_source_staging_failed'
        REPORT['errorType'] = type(error).__name__
        REPORT['ok'] = False
    finally:
        if volume is not None:
            try:
                volume.close()
            except BaseException:
                REPORT['ok'] = False
            REPORT['volumeClosure'] = volume.public_state()
        state = commands.public() if commands is not None else {'commands': [], 'allOwnedCommandsStopped': True, 'unknownCommandCount': 0}
        REPORT['commands'] = state
        REPORT['originalDeadlineAfterClosurePassed'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = signals is not None and signals.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and state['allOwnedCommandsStopped'] and state['unknownCommandCount'] == 0
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed')
            and REPORT['volumeClosure']['allDescriptorsClosed'] and REPORT['originalDeadlineAfterClosurePassed']
            and not REPORT['cancellationObserved'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
