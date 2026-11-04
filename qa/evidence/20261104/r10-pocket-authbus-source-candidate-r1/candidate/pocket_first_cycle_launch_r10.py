#!/usr/bin/env python3
"""One fresh Pocket preflight or first-cycle run. No production write or retry."""
from pathlib import Path
import argparse, hashlib, json, os, re, signal, stat, subprocess, time

P = Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
Q = P / 'shared-first-cycle-r10-qa-r1'; I = P / 'shared-first-cycle-inputs-r1'
A = P / 'shared-first-cycle-r10-artifacts-r1'
SCENARIO = 'shared-managed12-original-local-source'
UNIT_IDS = ['openclaw-authbus-restart-when-idle.service', 'openclaw-gateway.service']
os.umask(0o077)

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def put(path, value):
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def units():
    result = subprocess.run(['/usr/bin/systemctl', '--user', 'show', *UNIT_IDS,
        '--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState', '--no-pager'],
        capture_output=True, text=True, timeout=5)
    need(result.returncode == 0, 'production_unit_observation_failed')
    values = []
    for block in result.stdout.strip().split('\n\n'):
        value = {}
        for line in block.splitlines():
            k, sep, v = line.partition('=')
            if sep and k in ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'UnitFileState'):
                value[k] = v
        values.append(value)
    values.sort(key=lambda d: d.get('Id', ''))
    need([v.get('Id') for v in values] == UNIT_IDS, 'exact_two_held_units_required')
    return values

PROTECTED = [
    Path('/home/alex/.openclaw/openclaw.json'), Path('/home/alex/.codex/auth.json'), Path('/home/alex/.codex/config.toml'),
    Path('/home/alex/.config/systemd/user/openclaw-gateway.service'),
    Path('/home/alex/.config/systemd/user/openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf'),
    Path('/home/alex/.config/systemd/user/openclaw-authbus-restart-when-idle.service'),
    Path('/home/alex/.config/systemd/user/openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf'),
    Path('/home/alex/heptabao-authbus-persistent-guard-hb3-r1/hold-0dcbd843db6bbaf3fb0fdab97ae4775029d63660a7365b8da5b498385917c5e5.json'),
    Path('/home/alex/heptabao-authbus-persistent-guard-hb3-r1/hold-89902581f0d98cb21706f6dfdb9e879d2d6dffc7b8f4f3f4a9c654645f9624a1.json')]
HOLD_PINS = ['0fccbd0c976d259d01b359c3fd7e82552d182a656eb0af44faac89a863ceef9d',
             '370fc76cad249542b4b73763909fb546624071a4febd437501aa3a3b543cabc4']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('preflight', 'live'), required=True)
    parser.add_argument('--qa-pins-sha256', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[a-f0-9]{64}', args.qa_pins_sha256), 'qa_manifest_digest_shape')
    run = P / ('shared-first-cycle-r10-' + args.phase + '-r1')
    need(P.resolve(strict=True) == P, 'project_root_no_symlink')
    run.mkdir(mode=0o700)  # An existing generation is refused, never reopened.
    process = None; timed = False; code = None; core = None; started = time.monotonic()
    before = None; unit_before = None; intent_path = run / 'intent.public.json'
    creating_child = False; pending_signal = None
    def interrupted(signum, frame):
        nonlocal pending_signal
        if creating_child:
            pending_signal = signum
            return
        raise Refused('owned_run_interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    report = {'schema': 'heptabao.pocket-shared-first-cycle-launch-result.v1', 'ok': False,
        'phase': args.phase, 'fixtureScenario': SCENARIO, 'automaticRetry': False,
        'productionChanged': False, 'productionTrafficCutover': False, 'providerNetworkEgress': False,
        'providerAvailabilityQualified': False, 'holdReleasePerformed': False}
    try:
        before = {str(p): sha(p) for p in PROTECTED}; unit_before = units()
        need(all(u.get('LoadState') == 'loaded' and u.get('MainPID') == '0'
                 and u.get('ActiveState') == 'inactive' and u.get('SubState') == 'dead'
                 for u in unit_before), 'both_production_units_must_remain_held_inactive')
        need([before[str(p)] for p in PROTECTED[-2:]] == HOLD_PINS, 'original_hold_marker_pins')
        manifest_path = Q / 'qa-pins.public.json'
        need(sha(manifest_path) == args.qa_pins_sha256, 'externally_reviewed_qa_manifest_pin')
        pins = json.loads(manifest_path.read_bytes())['files']
        for name, pin in pins.items():
            need(re.fullmatch('[a-z0-9_.-]+', name) and sha(Q / name) == pin['sha256']
                 and (Q / name).stat().st_size == pin['bytes'], 'qa_source_pin')
        prepare = I / 'prepare-r10-r1.public.json'; prep = json.loads(prepare.read_bytes())
        need(prep['ok'] is True and prep['qaPinsSha256'] == args.qa_pins_sha256
             and prep['consumerSha256'] == pins['pocket_first_cycle_consumer_r1.mjs']['sha256']
             and prep['controllerSha256'] == pins['pocket_shared_first_cycle_live_r2.py']['sha256'],
             'prepared_qa_binding')
        if args.phase == 'live':
            prior = P / 'shared-first-cycle-r10-preflight-r1'
            prior_result = json.loads((prior / 'execution.result.public.json').read_bytes())
            prior_intent = json.loads((prior / 'intent.public.json').read_bytes())
            prior_core = json.loads((prior / 'live/result.public.json').read_bytes())
            need(prior_result['ok'] is True and prior_result['phase'] == 'preflight'
                 and prior_core['ok'] is True and prior_core['preflightOnly'] is True
                 and prior_core['actualRuntimeExecuted'] is False
                 and prior_result['coreResultSha256'] == sha(prior / 'live/result.public.json')
                 and prior_result['intentSha256'] == sha(prior / 'intent.public.json')
                 and prior_intent['qaPinsSha256'] == args.qa_pins_sha256
                 and prior_intent['prepareSha256'] == sha(prepare), 'exact_readonly_preflight_required')
        parent_net = os.stat('/proc/self/ns/net').st_ino
        cmd = ['/usr/bin/python3', '-I', '-S', '-B', str(Q / 'pocket_shared_first_cycle_live_r2.py'),
            '--project-root', str(P), '--work-dir', str(run / 'live'), '--binary', str(A / 'heptabao-server'),
            '--build-result', str(A / 'normal-build.result.public.json'), '--native-receipt', str(A / 'native-build.public.json'),
            '--prepare', str(prepare), '--consumer', str(Q / 'pocket_first_cycle_consumer_r1.mjs'),
            '--trusted-packet', str(I / 'managed-profile12.private.json'),
            '--trusted-projection', str(I / 'source-projection.public.json'),
            '--coordinator-source', str(Q / 'authbus_coordinator.py'), '--scenario', SCENARIO,
            '--node', '/usr/bin/node', '--parent-netns-inode', str(parent_net)]
        if args.phase == 'preflight':
            cmd.append('--preflight-only')
        wrap = ['/usr/bin/bwrap', '--ro-bind', '/', '/', '--bind', str(run), str(run),
            '--ro-bind', '/home/alex/.openclaw', '/home/alex/.openclaw',
            '--ro-bind', '/home/alex/.codex', '/home/alex/.codex',
            '--ro-bind', '/home/alex/.npm-global/lib/node_modules/openclaw', '/home/alex/.npm-global/lib/node_modules/openclaw',
            '--ro-bind', str(P / 'source'), str(P / 'source'), '--ro-bind', str(Q), str(Q), '--ro-bind', str(I), str(I),
            '--proc', '/proc', '--dev', '/dev', '--unshare-net', '--unshare-pid', '--die-with-parent',
            '--chdir', str(run), '--', *cmd]
        intent = {'schema': 'heptabao.pocket-shared-first-cycle-launch-intent.v1', 'phase': args.phase,
            'scenario': SCENARIO, 'argv': wrap, 'sourceCommit': '49503322c7f446e5eb41e7744f1fdbd7f1192ecc',
            'sourceTree': '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9',
            'binarySha256': '67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113',
            'prepareSha256': sha(prepare), 'qaPinsSha256': args.qa_pins_sha256, 'launcherSha256': sha(__file__),
            'unitsBefore': unit_before, 'protectedInputPinsBefore': before,
            'budgets': {'httpSeconds': 10, 'consumerSeconds': 70, 'rollbackSeconds': 35, 'outerSeconds': 440},
            'kernelPrivatePidNamespace': True, 'kernelPrivateNetworkNamespace': True,
            'onlyFreshRunDirectoryWritable': True, 'productionChanged': False, 'automaticRetry': False}
        put(intent_path, intent)
        with (run / 'stdout.private').open('xb') as stdout, (run / 'stderr.private').open('xb') as stderr:
            try:
                creating_child = True
                try:
                    process = subprocess.Popen(wrap, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                        env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/home/alex'}, start_new_session=True)
                finally:
                    creating_child = False
                if pending_signal is not None:
                    raise Refused('owned_run_interrupted_during_spawn')
                code = process.wait(timeout=440)
            except subprocess.TimeoutExpired:
                timed = True
            finally:
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    code = process.wait(timeout=10)
                stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        core_path = run / 'live/result.public.json'
        if core_path.exists():
            core = json.loads(core_path.read_bytes())
            report.update(coreResultPath=str(core_path), coreResultSha256=sha(core_path),
                coreChecks=len(core.get('checks', [])), corePassed=sum(c.get('passed') is True for c in core.get('checks', [])),
                ownedNativeCleanupQualified=core.get('ownedNativeProcessesStopped') is True)
        report['ok'] = code == 0 and not timed and core is not None and core.get('ok') is True
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Refused) else type(error).__name__
        report['errorClass'] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                code = process.wait(timeout=10)
            except Exception as error:
                report['cleanupErrorClass'] = type(error).__name__; report['ok'] = False
        report.update(returncode=code, outerTimeout=timed,
            outcomeUnknown=timed or (process is not None and core is None)
              or (core is not None and (core.get('outcomeUnknown') is True
                  or any(v.get('outcome') in ('failed_or_unknown','no_candidate_checkpoint_unknown',
                                            'owned_consumer_not_confirmed_stopped_unknown')
                         for v in core.get('rollbackGuards', {}).values()))),
            ownedNamespaceProcessExited=process is None or process.returncode is not None,
            pidNamespaceTeardownEnforced=True, elapsedSeconds=round(time.monotonic() - started, 3))
        if intent_path.exists():
            report['intentSha256'] = sha(intent_path)
        try:
            unit_after = units(); after = {str(p): sha(p) for p in PROTECTED}
            report.update(productionUnitsBefore=unit_before, productionUnitsAfter=unit_after,
                productionUnitsUnchanged=unit_before == unit_after, protectedInputsUnchanged=before == after)
            if before != after or unit_before != unit_after:
                report['ok'] = False
        except Exception as error:
            report['productionFenceErrorClass'] = type(error).__name__; report['ok'] = False
        for name in ('stdout', 'stderr'):
            if (run / (name + '.private')).exists():
                report[name + 'Sha256'] = sha(run / (name + '.private'))
        put(run / 'execution.result.public.json', report)
    print(json.dumps({'ok': report['ok'], 'phase': args.phase, 'path': str(run / 'execution.result.public.json'),
                      'sha256': sha(run / 'execution.result.public.json'), 'outcomeUnknown': report['outcomeUnknown']}))
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
