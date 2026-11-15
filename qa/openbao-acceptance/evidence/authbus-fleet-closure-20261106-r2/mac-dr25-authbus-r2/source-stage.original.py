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

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
CONTROL = ROOT / 'control/dr25-authbus-r2'
BASE = ROOT / 'source-4bde9-r1'
SOURCE = ROOT / 'source-dr25-authbus-r2'
BUNDLE = ROOT / 'control/candidate-5ded-from-4bde9.bundle'
OLD_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
OLD_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
COMMIT = '5ded017e1c858b8602a73678acc29df75386a84d'
TREE = '9d1d040a063504ede67559fadb556897591642f2'
BUNDLE_SHA = 'eef7fc4f17d9818ad53fda4cf57b1de2ca7a31661833fae61695d89ff5dfbab3'
WRAPPER_SHA = 'd435a05dec3dc28b976164540c1173b67a5a3f8360a6e5fd31a3926fe0c03a25'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
CODE_PINS = {
    'qa/openbao-acceptance/kv2_dr_process_custody.py': '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',
    'qa/openbao-acceptance/owned_process.py': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0',
    'qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py': '388f763d810e1694ce9fe3d4ce52325318aad8ec4fa4d87ebbcd6cfbe7f1f5a0',
    'qa/openbao-acceptance/kv2_271_lossless_native_live.py': '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581',
}
NEW_CODE_PINS = dict(CODE_PINS)
NEW_CODE_PINS['qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py'] = '01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67'
NEW_TEST = 'crates/heptabao-server/src/service_native_jwt_tests.rs'
NEW_TEST_SHA = '1571d88838fb127509cdbe24a7e7b5402453ec4cb1dbb784d56753aa2f49e584'
FORBIDDEN = (
    ROOT / 'full34-dr25-authbus-r2', ROOT / 'dr25-execution-authbus-r2',
    Path('/Users/qianqi/heptabao-dr25-backups-20261106-authbus-r2'), ROOT / 'dr25-key-custody-authbus-r2',
)
WRAPPER_TEXT = "#!/usr/bin/env python3\n\"\"\"Fixed synthetic Mac full34+DR25 attempt; a failed107 receipt never admits it.\n\nPrepare is read-only. Run creates only the named fresh private directories. The\nsame Python process enters the pinned DR controller, retaining its original\nprocess custody. Runtime must also declare its unchanged 1800-second outer cap.\n\"\"\"\nfrom __future__ import annotations\n\nimport time\nENTRY_MONOTONIC = time.monotonic()\n\nimport argparse\nimport contextlib\nimport hashlib\nimport importlib\nimport json\nimport os\nfrom pathlib import Path\nimport plistlib\nimport re\nimport signal\nimport stat\nimport subprocess\nimport sys\nimport threading\n\nROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')\nSOURCE = ROOT / 'source-dr25-authbus-r2'\nQA_COMMIT = '5ded017e1c858b8602a73678acc29df75386a84d'\nQA_TREE = '9d1d040a063504ede67559fadb556897591642f2'\nPRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'\nPRODUCT_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'\nBUILD = ROOT / 'build-test-4bde9-r1'\nSELECTION_SHA = '7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595'\nWORK = ROOT / 'full34-dr25-authbus-r2'\nOUT = ROOT / 'dr25-execution-authbus-r2'\nBACKUP = Path('/Users/qianqi/heptabao-dr25-backups-20261106-authbus-r2')\nKEYS = ROOT / 'dr25-key-custody-authbus-r2'\nORACLE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016')\nPYTHON = Path('/opt/homebrew/bin/python3')\nPINS = {\n    'python': (PYTHON, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13', 34640),\n    'oracle_binary': (ORACLE / 'bao', '50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c', 177888914),\n    'oracle_archive': (ORACLE / 'oracle-official.tar.gz', '15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91', 73965161),\n    'main': (SOURCE / 'qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py', '01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67', 72065),\n    'custody': (SOURCE / 'qa/openbao-acceptance/kv2_dr_process_custody.py', '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008', 26131),\n    'full34': (SOURCE / 'qa/openbao-acceptance/kv2_271_lossless_native_live.py', '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581', 49393),\n}\nVOLUMES = (('/Volumes/T5', 'FB804D1B-24CB-4D6E-AEA7-A9E180807758', False),\n           ('/System/Volumes/Data', '66612ABB-2CE6-4BDE-8B11-8104E60307CC', True))\nOUTER_SECONDS, PREPARE_SECONDS, WORK_SECONDS = 1800, 60, 1740\nCUSTODY = None\n\n\nclass Failure(RuntimeError):\n    pass\n\n\nclass DeadlineExpired(BaseException):\n    pass\n\n\ndef need(value, label):\n    if not value:\n        raise Failure(label)\n\n\ndef encode(value):\n    return (json.dumps(value, sort_keys=True, indent=2) + '\\n').encode()\n\n\ndef sha(raw):\n    return hashlib.sha256(raw).hexdigest()\n\n\ndef private_new(path, raw):\n    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n    try:\n        view = memoryview(raw)\n        while view:\n            count = os.write(fd, view)\n            need(count > 0, 'private_short_write')\n            view = view[count:]\n        os.fsync(fd)\n    finally:\n        os.close(fd)\n\n\nclass Deadline:\n    \"\"\"One entry time, a fixed prepare boundary, and an unrenewable work end.\"\"\"\n    def __init__(self, started, *, prepare=PREPARE_SECONDS, work=WORK_SECONDS):\n        self.started, self.prepare_end, self.work_end = started, started + prepare, started + work\n        self.fired = False\n        self.phase = 'prepare'\n        self.fired_phase = None\n        self.previous = None\n        self.restored = False\n\n    def _alarm(self, signum, frame):\n        self.fired = True  # Independent of any controller result or deferred cleanup.\n        self.fired_phase = self.fired_phase or self.phase\n        owner = getattr(CUSTODY, '_ACTIVE', None) if CUSTODY else None\n        if owner is not None:\n            owner._interrupt(signum, frame)  # No signal, process lookup or new worker here.\n        else:\n            raise DeadlineExpired()\n\n    def __enter__(self):\n        need(threading.current_thread() is threading.main_thread(), 'deadline_main_thread')\n        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'foreign_real_timer')\n        self.previous = signal.getsignal(signal.SIGALRM)\n        need(self.previous == signal.SIG_DFL, 'foreign_alarm_handler')\n        signal.signal(signal.SIGALRM, self._alarm)\n        try:\n            self._arm(self.prepare_end)\n        except BaseException:\n            signal.signal(signal.SIGALRM, self.previous)\n            raise\n        return self\n\n    def _arm(self, until):\n        need(not self.fired and time.monotonic() < until, 'absolute_deadline_expired')\n        signal.setitimer(signal.ITIMER_REAL, max(0.000001, until - time.monotonic()))\n\n    def enter_work(self):\n        need(self.phase == 'prepare' and time.monotonic() < self.prepare_end and not self.fired,\n             'prepare_original_deadline_expired')\n        self.phase = 'work'\n        self._arm(self.work_end)  # Absolute job-entry +1740; preparation time is included.\n\n    def eligible(self):\n        end = self.prepare_end if self.phase == 'prepare' else self.work_end\n        return not self.fired and time.monotonic() < end\n\n    def __exit__(self, *_):\n        signal.setitimer(signal.ITIMER_REAL, 0)\n        signal.signal(signal.SIGALRM, self.previous)\n        self.restored = True\n\n    def observation(self):\n        return {'entry_monotonic': self.started, 'work_end_monotonic': self.work_end,\n                'fired': self.fired, 'fired_phase': self.fired_phase,\n                'deadline_renewed': False, 'work_seconds_from_entry': WORK_SECONDS,\n                'runtime_outer_seconds': OUTER_SECONDS, 'cleanup_reserve_within_outer_seconds': 60}\n\n\n@contextlib.contextmanager\ndef private_stdio(root):\n    \"\"\"Capture Python and inherited native fd1/fd2; never hash these outputs publicly.\"\"\"\n    originals, files = {}, []\n    try:\n        sys.stdout.flush(); sys.stderr.flush()\n        for descriptor, name in ((1, 'controller.stdout.private'), (2, 'controller.stderr.private')):\n            originals[descriptor] = os.dup(descriptor)\n            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n            files.append(fd)\n            os.dup2(fd, descriptor)\n        yield\n    finally:\n        try:\n            sys.stdout.flush(); sys.stderr.flush()\n            for fd in files:\n                os.fsync(fd)\n        finally:\n            for descriptor, original in originals.items():\n                os.dup2(original, descriptor)\n                os.close(original)\n            for fd in files:\n                os.close(fd)\n\n\ndef file_pin(path, *, expected=None, size=None, private=False):\n    # A symlink is allowed only for the explicit Homebrew interpreter alias.\n    path = path.resolve(strict=True) if path == PYTHON else path\n    before = path.lstat()\n    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'input_regular_single_link')\n    if private:\n        need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,\n             'private_input_custody')\n    need(size is None or before.st_size == size, 'input_byte_count')\n    h = hashlib.sha256()\n    with open(path, 'rb', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as stream:\n        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_nlink')\n        identity = tuple(getattr(before, name) for name in fields)\n        need(tuple(getattr(os.fstat(stream.fileno()), name) for name in fields) == identity, 'input_open_changed')\n        for block in iter(lambda: stream.read(1024 * 1024), b''):\n            h.update(block)\n        need(tuple(getattr(os.fstat(stream.fileno()), name) for name in fields) == identity, 'input_fd_changed')\n    need(tuple(getattr(path.lstat(), name) for name in fields) == identity, 'input_name_changed')\n    need(expected is None or h.hexdigest() == expected, 'input_sha256')\n    return {'path': str(path), 'sha256': h.hexdigest(), 'bytes': before.st_size,\n            'device': before.st_dev, 'inode': before.st_ino, 'uid': before.st_uid,\n            'mode': stat.S_IMODE(before.st_mode), 'links': before.st_nlink}\n\n\ndef load_modules():\n    global CUSTODY\n    need(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.dont_write_bytecode,\n         'isolated_no_site_no_bytecode_interpreter_required')\n    for name, (path, expected, size) in PINS.items():\n        file_pin(path, expected=expected, size=size)\n    need(Path(sys.executable).resolve(strict=True) == PYTHON.resolve(strict=True), 'actual_interpreter')\n    sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))\n    for name in ('kv2_native_fresh_directory_dr_live', 'kv2_dr_process_custody'):\n        need(name not in sys.modules, 'foreign_preloaded_controller')\n    dr = importlib.import_module('kv2_native_fresh_directory_dr_live')\n    CUSTODY = importlib.import_module('kv2_dr_process_custody')\n    need(dr.ROOT == SOURCE and dr.full.HTTP_SECONDS == 15 and dr.full.MIGRATION_SECONDS == 360,\n         'unchanged_controller_and_original_budgets')\n    return dr\n\n\ndef command(argv, deadline):\n    end = deadline.prepare_end if deadline.phase == 'prepare' else deadline.work_end\n    remaining = end - time.monotonic()\n    need(remaining > 0 and not deadline.fired, 'prepare_original_deadline_expired')\n    return subprocess.check_output(argv, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,\n                                   timeout=min(15, remaining), cwd=SOURCE,\n                                   env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8',\n                                        'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',\n                                        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'})\n\n\ndef preparation(dr, receipt_sha, deadline, *, out_identity=None):\n    need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_native_mac_owner')\n    root = dr.private_parent(ROOT)\n    need(SOURCE.resolve(strict=True) == SOURCE, 'source_path_links')\n    if out_identity is None:\n        need(not os.path.lexists(OUT), 'new_wrapper_output_required')\n    else:\n        need(dr.private_parent(OUT) == out_identity, 'wrapper_output_changed')\n    for path in (WORK, BACKUP, KEYS):\n        need(not os.path.lexists(path), 'fresh_output_paths_required')\n    need(dr.disjoint([WORK, OUT, BACKUP, KEYS]), 'disjoint_fresh_paths')\n    need(BACKUP.parent.resolve(strict=True) == BACKUP.parent\n         and BACKUP.parent.stat().st_uid == os.geteuid()\n         and stat.S_IMODE(BACKUP.parent.stat().st_mode) & 0o022 == 0, 'internal_backup_parent')\n    need(BACKUP.parent.stat().st_dev != root['device'], 'different_backup_filesystem')\n    inputs = {name: file_pin(path, expected=expected, size=size)\n              for name, (path, expected, size) in PINS.items()}\n    inputs['wrapper'] = file_pin(Path(__file__).resolve())\n    files = {'server': BUILD / 'artifacts/heptabao-server', 'seed': BUILD / 'artifacts/heptabao-seed',\n             'receipt': BUILD / 'result.public.json', 'selection': BUILD / 'test-selection.public.json',\n             'build_log': BUILD / '13-normal-release-build.stdout'}\n    inputs.update({name: file_pin(path, private=name in ('receipt', 'selection')) for name, path in files.items()})\n    need(inputs['receipt']['sha256'] == receipt_sha and inputs['selection']['sha256'] == SELECTION_SHA,\n         'independent_build_and_selection_pins')\n    receipt = dr.full.decode(dr.full.private_read(files['receipt'], 8 * 1024 * 1024))\n    selection = dr.full.decode(dr.full.private_read(files['selection'], 8 * 1024 * 1024))\n    build = dr.validate_build_receipt(receipt, PRODUCT_COMMIT, inputs['server'], inputs['seed'], selection, SELECTION_SHA)\n    need(build['source_tree'] == PRODUCT_TREE, 'fixed_product_tree')\n    with CUSTODY.activated() as owner:\n        def git(*args):\n            return command(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *args], deadline).decode().strip()\n        source = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),\n                  'dirty': bool(git('status', '--porcelain', '--untracked-files=all'))}\n        need(source == {'commit': QA_COMMIT, 'tree': QA_TREE, 'dirty': False}, 'exact_clean_qa_source')\n        need(git('rev-parse', PRODUCT_COMMIT + '^{tree}') == PRODUCT_TREE, 'build_commit_tree')\n        need(not git('diff', '--name-only', PRODUCT_COMMIT, 'HEAD', '--', '.', ':!qa', ':!docs'),\n             'product_diff_from_bound_build')\n        volumes = []\n        for mount, uuid, internal in VOLUMES:\n            value = plistlib.loads(command(['/usr/sbin/diskutil', 'info', '-plist', mount], deadline))\n            need(value.get('MountPoint') == mount and value.get('VolumeUUID') == uuid\n                 and value.get('FilesystemType') == 'apfs' and value.get('Internal') is internal\n                 and isinstance(value.get('DeviceIdentifier'), str), 'fixed_volume_identity')\n            volumes.append({key: value[key] for key in ('MountPoint', 'VolumeUUID', 'FilesystemType', 'Internal', 'DeviceIdentifier')})\n        need(Path(VOLUMES[0][0]).stat().st_dev == root['device']\n             and Path(VOLUMES[1][0]).stat().st_dev == BACKUP.parent.stat().st_dev, 'mount_to_actual_parent_devices')\n        owner.assert_retired()\n    custody = owner.receipt()\n    need(custody.get('passed_process_custody') is True and custody.get('finished') is True,\n         'prepare_originals_retired')\n    need(deadline.eligible() and time.monotonic() < deadline.prepare_end, 'prepare_original_deadline_expired')\n    binding = {'schema': 'heptabao.mac-dr25-fixed-inputs.v1', 'source': source, 'inputs': inputs,\n               'build': build, 'root': root, 'backup_existing_parent': dr.directory_identity(BACKUP.parent),\n               'volumes': volumes, 'paths': {key: str(path) for key, path in\n                   (('work', WORK), ('out', OUT), ('backup_parent', BACKUP), ('key_parent', KEYS))},\n               'http_seconds': 15, 'migration_seconds': 360, 'outer_seconds': OUTER_SECONDS,\n               'same_process_entry': True, 'production_authority': False}\n    return binding, custody\n\n\ndef driver_argv(receipt_sha):\n    return ['--binary', str(BUILD / 'artifacts/heptabao-server'),\n            '--seed-binary', str(BUILD / 'artifacts/heptabao-seed'),\n            '--build-source-commit', PRODUCT_COMMIT,\n            '--build-log', str(BUILD / '13-normal-release-build.stdout'),\n            '--build-receipt', str(BUILD / 'result.public.json'), '--build-receipt-sha256', receipt_sha,\n            '--private-work-root', str(WORK), '--backup-parent', str(BACKUP), '--key-parent', str(KEYS)]\n\n\ndef qualify_summary(dr, summary, code):\n    need(code == 0 and summary.get('status') == 'passed' and summary.get('failure') is None,\n         'actual_dr_controller_failed')\n    need(dr.complete(summary.get('checks', [])) and summary.get('baseline', {}).get('qualified') is True\n         and summary.get('fresh_directory_same_seal_v6_recovery_verified') is True,\n         'actual_full31_and_dr25_required')\n    original = WORK / 'quarantine/original-closure/summary.json'\n    need(summary['baseline'].get('summary') == str(original), 'quarantined_original_summary_required')\n    pin = dr.file_pin(original, private=True)\n    need(pin['sha256'] == summary['baseline'].get('sha256'), 'bound_original_full34_summary')\n    baseline = dr.full.decode(dr.full.private_read(original, 32 * 1024 * 1024))\n    need(dr.full34_complete(baseline), 'independently_rechecked_original_full31')\n    custody = summary.get('process_custody', {})\n    need(custody.get('passed_process_custody') is True and custody.get('finished') is True\n         and custody.get('failed') is False and getattr(CUSTODY, '_ACTIVE', None) is None,\n         'all_originals_retired_before_wrapper_completion')\n    return {'baseline_31_passed': True, 'dr25_passed': True,\n            'fresh_directory_same_seal_v6_recovery_verified': True,\n            'all_originals_retired': True, 'summary': str(WORK / 'dr25-summary.json')}\n\n\ndef main(argv=None):\n    # Starts immediately after importing the monotonic clock, before all other\n    # wrapper/controller imports, argument parsing, hashing or preparation.\n    started = ENTRY_MONOTONIC\n    parser = argparse.ArgumentParser(description=__doc__)\n    action = parser.add_mutually_exclusive_group(required=True)\n    action.add_argument('--prepare-only', action='store_true')\n    action.add_argument('--run', metavar='PREPARED_SHA256')\n    parser.add_argument('--build-receipt-sha256', required=True)\n    args = parser.parse_args(argv)\n    need(re.fullmatch('[0-9a-f]{64}', args.build_receipt_sha256) is not None, 'receipt_pin_required')\n    need(args.run is None or re.fullmatch('[0-9a-f]{64}', args.run) is not None, 'prepared_pin_required')\n    os.umask(0o077)\n    report = {'schema': 'heptabao.mac-full34-dr25-fixed-execution.v1', 'status': 'failed',\n              'production_authority': False, 'formal_kv2_migration_qualified': False,\n              'physical_ha_qualified': False, 'authbus_qualified': False, 'full_replacement_qualified': False,\n              'http_seconds': 15, 'migration_seconds': 360, 'runtime_outer_seconds': OUTER_SECONDS,\n              'automatic_retry': False, 'summary_content_or_private_output_fingerprints_published': False}\n    out_identity = None\n    timer = Deadline(started)\n    try:\n        with timer:\n            dr = load_modules()\n            if args.run:\n                dr.private_parent(ROOT)\n                need(not os.path.lexists(OUT), 'new_wrapper_output_required')\n                OUT.mkdir(mode=0o700)\n                out_identity = dr.private_parent(OUT)\n                private_new(OUT / 'controller.original.py', Path(__file__).read_bytes())\n            binding, prep_custody = preparation(dr, args.build_receipt_sha256, timer, out_identity=out_identity)\n            prepared_sha = sha(encode(binding))\n            if args.prepare_only:\n                need(timer.eligible(), 'prepare_original_deadline_expired')\n                report.update(status='prepared', prepared=binding, prepared_sha256=prepared_sha,\n                              preparation_process_custody=prep_custody, product_started=False)\n            else:\n                need(prepared_sha == args.run, 'actual_readonly_preparation_changed')\n                timer.enter_work()\n                private_new(OUT / 'prepared.public.json', encode({'binding': binding, 'prepared_sha256': prepared_sha,\n                                                               'process_custody': prep_custody}))\n                BACKUP.mkdir(mode=0o700); KEYS.mkdir(mode=0o700)\n                backup, keys = dr.private_parent(BACKUP), dr.private_parent(KEYS)\n                need(backup['device'] != dr.directory_identity(ROOT)['device']\n                     and dr.disjoint([BACKUP, KEYS]), 'fresh_directory_device_and_key_boundary')\n                (OUT / 'tmp').mkdir(mode=0o700)\n                environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',\n                    'TMPDIR': str(OUT / 'tmp'), 'HB_ORACLE_BINARY': str(ORACLE / 'bao'),\n                    'HB_ORACLE_ARCHIVE': str(ORACLE / 'oracle-official.tar.gz'),\n                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',\n                    'GIT_OPTIONAL_LOCKS': '0'}\n                os.environ.clear(); os.environ.update(environment)\n                private_new(OUT / 'intent.public.json', encode({'argv': driver_argv(args.build_receipt_sha256),\n                    'prepared_sha256': prepared_sha, 'backup_parent': backup, 'key_parent': keys,\n                    'same_process_entry': True, 'original_outer_seconds': OUTER_SECONDS,\n                    'work_deadline_from_entry_seconds': WORK_SECONDS, 'production_authority': False}))\n                with private_stdio(OUT):\n                    code = dr.main(driver_argv(args.build_receipt_sha256))\n                report['controller_exit_code'] = code\n                summary = dr.full.decode(dr.full.private_read(WORK / 'dr25-summary.json', 32 * 1024 * 1024))\n                checks = summary.get('checks', [])\n                report.update(summary=str(WORK / 'dr25-summary.json'),\n                              observed_dr25_check_count=len(checks),\n                              observed_dr25_pass_count=sum(row.get('passed') is True for row in checks),\n                              missing_required_dr25=[name for name in dr.CHECKS\n                                  if not any(row.get('case') == name and row.get('passed') is True for row in checks)])\n                report.update(qualify_summary(dr, summary, code))\n                need(timer.eligible(), 'job_absolute_deadline_failed')\n                report['status'] = 'passed'\n            # The alarm stays armed through terminal-summary binding and custody checks.\n            need(timer.eligible(), 'job_absolute_deadline_failed')\n            report['control_work_elapsed_seconds'] = time.monotonic() - started\n    except BaseException as error:\n        report['status'] = 'failed'\n        report['failure'] = (str(error) if isinstance(error, Failure)\n                             and re.fullmatch('[a-z0-9_]{1,120}', str(error)) else type(error).__name__)\n    finally:\n        report.update(deadline=timer.observation(), elapsed_seconds=time.monotonic() - started,\n                      signal_and_timer_restored=timer.restored,\n                      elapsed_observation_before_receipt_publication=True,\n                      durable_completion_authority='separate_runtime_terminal_with_original_1800_second_cap')\n        limit = PREPARE_SECONDS if args.prepare_only else WORK_SECONDS\n        if timer.fired or time.monotonic() - started >= limit:\n            report.update(status='failed', failure='job_absolute_deadline_failed')\n        if out_identity is not None:\n            private_new(OUT / 'result.public.json', encode(report))\n    print(json.dumps(report if args.prepare_only else {key: report.get(key) for key in\n        ('status', 'failure', 'controller_exit_code', 'baseline_31_passed', 'dr25_passed', 'elapsed_seconds')}), flush=True)\n    return 0 if report['status'] in ('prepared', 'passed') else 1\n\n\nif __name__ == '__main__':\n    try:\n        raise SystemExit(main())\n    except BaseException as error:\n        if isinstance(error, SystemExit):\n            raise\n        print(json.dumps({'status': 'failed', 'failure': type(error).__name__, 'production_authority': False}), flush=True)\n        raise SystemExit(1) from None\n"
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
       'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': 'file'}
REPORT = {'schema': 'heptabao.mac-dr25-source-stage.v1', 'status': 'failed', 'failure': None,
          'source_commit': COMMIT, 'source_tree': TREE, 'wrapper_sha256': WRAPPER_SHA,
          'bundle_sha256': BUNDLE_SHA, 'work_seconds': 52, 'runtime_outer_seconds': 60,
          'product_started': False, 'prepare_only_executed': False, 'dr_started': False,
          'production_authority': False, 'actual_107_pass_claimed': False,
          'running_build_source_or_artifacts_opened': False, 'commands': []}
OWNER = None
CUSTODY = None
FIRED = False
CONTROL_CREATED = False


class StageFailure(RuntimeError):
    pass


class StageDeadline(BaseException):
    pass


def need(value, label):
    if not value:
        raise StageFailure(label)


def room():
    need(not FIRED and time.monotonic() - ENTRY < 52, 'stage_work_deadline')


def alarm(signum, frame):
    global FIRED
    FIRED = True
    if OWNER is not None:
        OWNER._interrupt(signum, frame)
    else:
        raise StageDeadline()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def private_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def pin(path, expected, length=None):
    room()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.geteuid(), 'input_regular_owned_unlinked')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        t = os.fstat(fd)
        shape = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(shape(s) == shape(t) and len(data) == s.st_size, 'input_changed_during_read')
        need(hashlib.sha256(data).hexdigest() == expected, 'input_sha_mismatch')
        need(length is None or len(data) == length, 'input_size_mismatch')
        return {'bytes': len(data), 'sha256': expected, 'device': s.st_dev, 'inode': s.st_ino}
    finally:
        os.close(fd)


def directory(path, private=False):
    room()
    s = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid(), 'directory_identity')
    need(not private or stat.S_IMODE(s.st_mode) == 0o700, 'private_directory_mode')
    return {'device': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid, 'mode': stat.S_IMODE(s.st_mode)}


def check_uncreated():
    room()
    rows = [{'path': str(path), 'exists': os.path.lexists(path)} for path in FORBIDDEN]
    need(all(row['exists'] is False for row in rows), 'dr_outputs_must_remain_absent')
    return rows


def command(label, cwd, arguments):
    room()
    argv = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *arguments]
    number = len(REPORT['commands']) + 1
    stdout = CONTROL / (str(number).zfill(2) + '-' + label + '.stdout')
    stderr = CONTROL / (str(number).zfill(2) + '-' + label + '.stderr')
    row = {'label': label, 'argv': argv, 'cwd': str(cwd), 'stdout': stdout.name,
           'stderr': stderr.name, 'returncode': None}
    REPORT['commands'].append(row)
    then = time.monotonic()
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(argv, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try:
            process.wait(timeout=min(15, 52 - (time.monotonic() - ENTRY)))
        finally:
            row['returncode'] = process.returncode
            row['elapsed_seconds'] = round(time.monotonic() - then, 6)
    need(row['returncode'] == 0, 'git_command_failed')
    raw = stdout.read_bytes()
    need(len(raw) <= 65536 and stderr.stat().st_size <= 65536, 'git_output_shape')
    room()
    return raw.decode('utf-8', 'strict').strip()


def identity(label, path):
    return {'commit': command(label + '-head', path, ['rev-parse', 'HEAD']),
            'tree': command(label + '-tree', path, ['rev-parse', 'HEAD^{tree}']),
            'status': command(label + '-status', path, ['status', '--porcelain', '--untracked-files=all'])}


def objects(path):
    root = path / '.git/objects'
    need(not os.path.lexists(root / 'info/alternates'), 'shared_git_alternates_refused')
    rows = []
    for current, dirs, files in os.walk(root, followlinks=False):
        room()
        for name in dirs:
            need(not (Path(current) / name).is_symlink(), 'git_object_directory_symlink')
        for name in files:
            room()
            s = (Path(current) / name).lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'git_object_hardlink_or_symlink')
            rows.append((s.st_dev, s.st_ino))
            need(len(rows) <= 4096, 'git_object_enumeration_cap')
    need(rows, 'git_object_inventory_empty')
    return set(rows)


def run():
    global OWNER, CUSTODY, CONTROL_CREATED
    need(sys.platform == 'darwin' and sys.version_info[:3] == (3, 14, 3) and os.geteuid() == 501, 'fixed_mac_python_owner')
    need(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'foreign_alarm_refused')
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, max(.001, 52 - (time.monotonic() - ENTRY)))
    try:
        os.umask(0o077)
        REPORT['python'] = pin(Path(sys.executable).resolve(), PYTHON_SHA, 34640)
        REPORT['root'] = directory(ROOT, True)
        directory(CONTROL.parent, True)
        REPORT['base_directory'] = directory(BASE, True)
        REPORT['dr_outputs_before'] = check_uncreated()
        need(not os.path.lexists(CONTROL) and not os.path.lexists(SOURCE), 'fresh_stage_and_source_required')
        REPORT['bundle'] = pin(BUNDLE, BUNDLE_SHA, 401428)
        REPORT['base_code_before'] = {name: pin(BASE / name, value) for name, value in CODE_PINS.items()}
        wrapper = WRAPPER_TEXT.encode()
        need(len(wrapper) == 22654 and hashlib.sha256(wrapper).hexdigest() == WRAPPER_SHA, 'fixed_wrapper_bytes')
        CONTROL.mkdir(mode=0o700)
        CONTROL_CREATED = True
        REPORT['control_directory'] = directory(CONTROL, True)
        private_new(CONTROL / 'dr25_mac_fixed_wrapper.py', wrapper)
        need(sys.orig_argv[-2] == '-c', 'original_controller_argument_required')
        controller = sys.orig_argv[-1].encode()
        private_new(CONTROL / 'stage-controller.original.py', controller)
        REPORT['controller_sha256'] = hashlib.sha256(controller).hexdigest()
        private_new(CONTROL / 'intent.public.json', encoded({
            'source_commit': COMMIT, 'source_tree': TREE, 'bundle': REPORT['bundle'],
            'base_commit': OLD_COMMIT, 'base_tree': OLD_TREE, 'wrapper_sha256': WRAPPER_SHA,
            'clone_no_hardlinks': True, 'source': str(SOURCE), 'control': str(CONTROL),
            'work_seconds': 52, 'runtime_outer_seconds': 60, 'prepare_only_executed': False,
            'product_started': False, 'dr_started': False, 'production_authority': False}))
        sys.path.insert(0, str(BASE / 'qa/openbao-acceptance'))
        CUSTODY = importlib.import_module('kv2_dr_process_custody')
        need(Path(CUSTODY.__file__).resolve() == BASE / 'qa/openbao-acceptance/kv2_dr_process_custody.py', 'exact_custody_module')
        with CUSTODY.activated() as owner:
            OWNER = owner
            try:
                REPORT['base_before'] = identity('base-before', BASE)
                need(REPORT['base_before'] == {'commit': OLD_COMMIT, 'tree': OLD_TREE, 'status': ''}, 'exact_clean_old_source')
                command('clone', ROOT, ['clone', '--no-hardlinks', '--no-checkout', '--', str(BASE), str(SOURCE)])
                REPORT['source_directory'] = directory(SOURCE, True)
                command('bundle-verify', SOURCE, ['bundle', 'verify', str(BUNDLE)])
                command('fetch-bundle', SOURCE, ['fetch', '--no-tags', str(BUNDLE), COMMIT])
                command('checkout', SOURCE, ['checkout', '--detach', COMMIT])
                REPORT['source'] = identity('source', SOURCE)
                need(REPORT['source'] == {'commit': COMMIT, 'tree': TREE, 'status': ''}, 'exact_clean_new_source')
                REPORT['source_pins'] = {name: pin(SOURCE / name, value) for name, value in NEW_CODE_PINS.items()}
                REPORT['test_source'] = pin(SOURCE / NEW_TEST, NEW_TEST_SHA, 44096)
                old_objects, new_objects = objects(BASE), objects(SOURCE)
                need(not (old_objects & new_objects), 'git_objects_share_inode')
                REPORT['git_object_independence'] = {'old_count': len(old_objects), 'new_count': len(new_objects),
                    'shared_inode_count': 0, 'new_object_link_counts_one': True, 'alternates_absent': True}
                REPORT['base_after'] = identity('base-after', BASE)
                need(REPORT['base_after'] == REPORT['base_before'], 'old_source_changed')
                REPORT['base_code_after'] = {name: pin(BASE / name, value) for name, value in CODE_PINS.items()}
                need(REPORT['base_code_after'] == REPORT['base_code_before'], 'old_code_identity_changed')
                REPORT['bundle_after'] = pin(BUNDLE, BUNDLE_SHA, 401428)
                need(REPORT['bundle_after'] == REPORT['bundle'], 'bundle_identity_changed')
                REPORT['wrapper'] = pin(CONTROL / 'dr25_mac_fixed_wrapper.py', WRAPPER_SHA, 22654)
                REPORT['dr_outputs_after'] = check_uncreated()
                owner.assert_retired()
            finally:
                REPORT['process_custody'] = owner.finish()
            need(REPORT['process_custody'].get('passed_process_custody') is True and not owner.failed, 'stage_original_processes_not_retired')
        room()
        REPORT['status'] = 'staged_not_executed'
    except BaseException as error:
        REPORT['status'] = 'failed'
        REPORT['failure'] = (str(error) if isinstance(error, StageFailure) and re.fullmatch('[a-z0-9_]{1,100}', str(error)) else type(error).__name__)
    finally:
        if OWNER is not None:
            REPORT['process_custody'] = OWNER.finish()
            if not REPORT['process_custody'].get('passed_process_custody'):
                REPORT['status'] = 'failed'
                REPORT['failure'] = REPORT['failure'] or 'stage_original_processes_not_retired'
        REPORT['deadline_fired'] = FIRED
        REPORT['control_work_elapsed_seconds'] = round(time.monotonic() - ENTRY, 6)
        if FIRED or time.monotonic() - ENTRY >= 52:
            REPORT.update(status='failed', failure='stage_work_deadline')
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        REPORT['signal_and_timer_restored'] = signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        REPORT['runtime_terminal_required'] = True
        if CONTROL_CREATED:
            private_new(CONTROL / 'result.public.json', encoded(REPORT))
    print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['status'] == 'staged_not_executed' else 1


if __name__ == '__main__':
    raise SystemExit(run())
