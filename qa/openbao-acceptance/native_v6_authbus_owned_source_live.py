#!/usr/bin/env python3
"""One exact main-owned OAuth snapshot through the independent AuthBus service.

Run only on main's existing ordinary owner. The snapshot, production profile
name, identity and all credentials remain on that host. A new loopback V6,
unchanged plugin copy and new actual SDK SQLite stores exercise publication,
CAS conflict, process death, cold recovery, backup, configuration rollback and
revocation. No provider/refresh, production store write or cutover is allowed.
The prior synthetic-only central driver and consumer are not modified.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import owned_process
from cert_auth_live import cert_sha256
from native_v6_authbus_client_live import CanaryFailure, NativeInstance, private, sha
from native_v6_openclaw_authbus_live import FILES, mkdir


HERE = Path(__file__).resolve().parent
MOUNT = 'openclaw-auth'
PRODUCER, FOLLOWER, WRITER = 'authbus-owned-producer', 'authbus-owned-follower', 'authbus-owned-writer'
CONSUMER = HERE / 'native_v6_authbus_owned_source_consumer.mjs'
CENTRAL_SHA = '81bfbacfd14df399c1e8eef963447803cee8e01aebc2474c0f39c2595e7fce47'
INSPECTOR_SHA = '703cb463ce43488ff29f8a8394fab4bd591c69bc2a06c1c5ddc64d0abc1e14de'
ORIGINAL_PLUGIN_SHA = 'b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b'
PLUGIN_CONTRACT = {
    'index.js': ORIGINAL_PLUGIN_SHA,
    'bad-refresh-quarantine.js': '916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286',
    'codex-client-recycler.js': 'd3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d',
    'lease-assignments.js': '24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7',
    'order-policy.js': '16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301',
    'provider-error-classifier.js': '3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77',
    'runtime-refresh-policy.js': '8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547',
}
ROOT_HOME = Path('/home/qian-qi')
SOURCE_STATE = ROOT_HOME / '.openclaw'
SOURCE_OWNER = SOURCE_STATE / 'agents/main/agent'
SOURCE_SDK = ROOT_HOME / '.npm-global/lib/node_modules/openclaw'
SOURCE_INSPECTOR = ROOT_HOME / 'heptabao-next-gates-20261017/authbus-sdk-owned-inspection-r1/authbus_sdk_owned_source.mjs'
SOURCE_OUTPUT = SOURCE_INSPECTOR.parent / 'owner-export-r1-7b0b24e17c16/snapshot'
SOURCE_RECEIPT_SHA = '41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907'
SOURCE_CANDIDATE_SHA = 'f2c164581d5afb0c9f95b9a71aedaa3f2a889817dabe1201169f7b5ce6f5dbe6'
SOURCE_CONFIG_SHA = '791d2d5e7166d02b871a8aa21b0194ca65456c0019757451bfe46d0fe8127d55'
SOURCE_INSPECT_RECEIPT_SHA = 'e058878b389fe28c9d32c046eeb37557d1838343a8bf0922cab50a2cd77e538b'
SELECTION = {
    'scopeAgentDir': str(SOURCE_OWNER), 'ownerAgentDir': str(SOURCE_OWNER),
    'profileIdSha256': '7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d',
    'credentialDigest': '71c3e21e28368490383dc3628f561e42fef261b0f4ef78263e4dcf3873dc381b',
    'identityDigest': 'c84e09f9ec9749c94545ddf65091f448ff795b318fde24a3780b6f000ff4ee9d',
}
SDK_CONTRACT = {'version': '2026.7.1-2', 'files': {
    'dist/store-DH33UrUj.js': '25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf',
    'dist/source-check-ZSz5NzGW.js': '9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9',
    'dist/sqlite-B1ze-fre.js': 'ed940f0ba0877eea0f00b2da30e727714993db60156fefc6fe80ac8564984c50',
    'dist/plugin-sdk/agent-runtime.js': '7831532d17eeaddd62889b2e8bb7b65ea7a7851901f69ceec23607a8c579dd95',
    'dist/agent-scope-config-BxAUeF6t.js': '83ef65476ae41bfcf040b1503f468074f36d602e9fa46551822cb7768bef3a1f',
}}
LIMIT = 2 * 1024 * 1024
SECONDS = 360
REFRESH_MARGIN_MS = 900000


def require(value, code):
    if not value:
        raise CanaryFailure(code)


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def owned_directory(path, *, private_only=True):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'directory_alias_rejected')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and (not private_only or stat.S_IMODE(info.st_mode) == 0o700), 'owned_directory_custody')


def read_owned(path, maximum=LIMIT):
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, 'private_parent_alias_rejected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum, 'owned_file_custody')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block); chunks.append(block)
            require(size <= maximum, 'owned_file_bound')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, field) == getattr(after, field) for field in fields), 'owned_file_changed_during_read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def private_json(path):
    return json.loads(read_owned(path))


def import_central(path):
    require(path.is_absolute() and not path.is_symlink() and sha(path) == CENTRAL_SHA, 'central_source_fingerprint')
    spec = importlib.util.spec_from_file_location('owned_source_frozen_authbus_coordinator', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def remaining(deadline, maximum=75):
    require(isinstance(deadline, (int, float)) and not isinstance(deadline, bool)
            and math.isfinite(deadline), 'original_operation_deadline_shape')
    value = deadline - time.monotonic()
    require(value > 0, 'original_operation_deadline_elapsed')
    return min(maximum, value)


def pending_may_have_dispatched(path):
    """A post-dispatch failure must retain uncertainty, including an expired
    local deadline after the server returned a committed manifest response.
    Only the original coordinator's durable receipt/history resolves it.
    """
    try:
        record = private_json(path)
    except FileNotFoundError:
        return False
    except Exception:
        return True
    return not isinstance(record, dict) or record.get('phase') not in ('prepared', 'profile_confirmed')


def validate_observation(receipt, *, mode, selection=SELECTION):
    require(isinstance(receipt, dict) and receipt.get('schema') == 'authbus-owned-sdk-source-public-v1'
            and receipt.get('ok') is True and receipt.get('mode') == mode
            and receipt.get('hostId') == 'desktop' and receipt.get('stateDir') == str(SOURCE_STATE)
            and receipt.get('configSha256') == SOURCE_CONFIG_SHA and receipt.get('sdkContract') == SDK_CONTRACT
            and receipt.get('agentDirs') == [str(SOURCE_OWNER)]
            and receipt.get('defaultAgentDir') == str(SOURCE_OWNER), 'owner_observation_scope_changed')
    for key in ('productionMutation', 'productionCutover', 'providerCalled', 'oauthRefreshed',
                'externalCliProfilesImported', 'j3160Contacted', 'productionStoreWriteAttempted', 'providerLivenessVerified'):
        require(receipt.get(key) is False, 'owner_observation_effect_not_proven_false')
    require(receipt.get('readOnlyProductionAccess') is True
            and receipt.get('actualSdkReadOnlyOwnerApiUsed') is True
            and receipt.get('sourceSnapshotNotARefreshLease') is True, 'owner_observation_contract_changed')
    rows = receipt.get('profiles')
    require(isinstance(rows, list) and len(rows) <= 128, 'owner_observation_profile_bound')
    matches = [row for row in rows if isinstance(row, dict)
               and row.get('profileIdSha256') == selection['profileIdSha256']
               and row.get('scopeAgentDir') == selection['scopeAgentDir']]
    require(len(matches) == 1, 'owner_exact_selected_profile_missing')
    row = matches[0]
    require(all(row.get(key) == value for key, value in selection.items())
            and row.get('ownerDatabasePath') == str(SOURCE_OWNER / 'openclaw-agent.sqlite')
            and row.get('persistedOwnerMatchesEffective') is True and row.get('hasSecretReference') is False
            and row.get('inheritedFromMain') is False and row.get('provider') == 'openai' and row.get('type') == 'oauth'
            and row.get('oauthRefreshAttempted') is False and row.get('providerLivenessVerified') is False,
            'exact_persisted_source_changed')
    return row


def validate_candidate(candidate, central, *, selection=SELECTION):
    require(candidate.get('schema') == 'authbus-owned-sdk-source-snapshot-v1'
            and candidate.get('hostId') == 'desktop' and candidate.get('stateDir') == str(SOURCE_STATE)
            and candidate.get('sdkContract') == SDK_CONTRACT and candidate.get('configSha256') == SOURCE_CONFIG_SHA
            and candidate.get('inspectReceiptSha256') == SOURCE_INSPECT_RECEIPT_SHA, 'candidate_original_provenance_changed')
    require(candidate.get('constraints') == {
        'providerLivenessVerified': False, 'oauthRefreshed': False, 'productionCutover': False,
        'snapshotRequiresRecheckBeforePublication': True, 'coordinatorOwnershipQualified': False,
    }, 'candidate_authority_boundary_changed')
    records = candidate.get('profiles')
    require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict), 'single_exact_candidate_required')
    record = records[0]; credential = record.get('credential')
    central.credential_valid(credential)
    require(isinstance(record.get('profileId'), str)
            and hash_bytes(record['profileId'].encode()) == selection['profileIdSha256']
            and record.get('digest') == selection['credentialDigest'] == central.digest(credential)
            and record.get('identity') == selection['identityDigest'] == central.identity(credential)
            and credential.get('provider') == 'openai' and credential.get('type') == 'oauth', 'candidate_selected_bytes_changed')
    require(record.get('source') == {
        'scopeAgentDir': str(SOURCE_OWNER), 'ownerAgentDir': str(SOURCE_OWNER),
        'databasePath': str(SOURCE_OWNER / 'openclaw-agent.sqlite'), 'method': 'actual_sdk_readonly_persisted_owner',
    }, 'candidate_original_owner_path_changed')
    return record


def source_secrets(record):
    return [record['profileId']] + [
        value for key, value in record['credential'].items()
        if key not in ('provider', 'type', 'chatgptPlanType') and isinstance(value, str) and value
    ]


def ensure_redacted(value, confidential):
    encoded = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
    require(all(secret.encode() not in encoded and json.dumps(secret)[1:-1].encode() not in encoded
                for secret in confidential if secret), 'public_owned_source_evidence_refused')


def clean_environment(home):
    # No gateway environment, external credentials, Node loader or auth scope
    # is inherited by any actual SDK child.
    return {'HOME': str(home), 'USER': pwd.getpwuid(os.geteuid()).pw_name,
            'LOGNAME': pwd.getpwuid(os.geteuid()).pw_name, 'PATH': '/usr/bin:/bin',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


def source_recheck(run_dir, deadline, confidential, *, inspector=SOURCE_INSPECTOR):
    """Read the actual owner with the unchanged original inspector, once.

    The caller's original monotonic deadline is only consumed. A fresh read
    cannot renew the bearer, extend the operation, or create refresh ownership.
    """
    remaining(deadline)
    require(inspector == SOURCE_INSPECTOR and hash_bytes(read_owned(inspector)) == INSPECTOR_SHA,
            'original_inspector_changed')
    require(hash_bytes(read_owned(SOURCE_STATE / 'openclaw.json')) == SOURCE_CONFIG_SHA, 'production_config_changed')
    output = run_dir / 'source-read'; config_path = run_dir / 'source-inspect.private.json'
    require(not os.path.lexists(output) and not os.path.lexists(config_path), 'source_recheck_output_already_exists')
    config = {'schema': 'authbus-owned-sdk-source-v1', 'mode': 'inspect', 'hostId': 'desktop',
              'sdkRoot': str(SOURCE_SDK), 'stateDir': str(SOURCE_STATE), 'configPath': str(SOURCE_STATE / 'openclaw.json'),
              'outputDir': str(output), 'agentDirs': [str(SOURCE_OWNER)]}
    private(config_path, json.dumps(config))
    result = owned_process.run(['/usr/bin/node', str(inspector), str(config_path)],
        cwd=run_dir, env=clean_environment(ROOT_HOME), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=remaining(deadline), label='authbus-owned.source-read')
    private(run_dir / 'source-inspector.stdout.private.log', result.stdout)
    private(run_dir / 'source-inspector.stderr.private.log', result.stderr)
    require(len(result.stdout) + len(result.stderr) <= LIMIT, 'source_inspector_diagnostic_bound')
    ensure_redacted(result.stdout + result.stderr, confidential)
    require(result.returncode == 0, 'source_inspector_recheck_failed')
    remaining(deadline)
    raw = read_owned(output / 'public-receipt.json'); receipt = json.loads(raw)
    ensure_redacted(receipt, confidential)
    row = validate_observation(receipt, mode='inspect')
    require(hash_bytes(read_owned(inspector)) == INSPECTOR_SHA
            and hash_bytes(read_owned(SOURCE_STATE / 'openclaw.json')) == SOURCE_CONFIG_SHA,
            'source_configuration_changed_during_recheck')
    require(row.get('expiresMs', 0) > int(time.time() * 1000) + REFRESH_MARGIN_MS,
            'original_source_expiry_margin_elapsed')
    return {'receiptPath': str(output / 'public-receipt.json'), 'receiptSha256': hash_bytes(raw),
            'inspectorSha256': INSPECTOR_SHA, 'configSha256': SOURCE_CONFIG_SHA,
            'profileIdSha256': SELECTION['profileIdSha256'], 'credentialDigest': SELECTION['credentialDigest'],
            'identityDigest': SELECTION['identityDigest'], 'ownerStillExact': True,
            'originalOperationDeadlineReused': True, 'providerLivenessVerified': False, 'snapshotNotARefreshLease': True}


def run_worker(config_path):
    """Private fault adapter around the exact frozen independent service."""
    cfg = private_json(config_path)
    root, output = Path(cfg['workRoot']), Path(cfg['runDir'])
    owned_directory(root); owned_directory(output)
    require(output.is_relative_to(root) and cfg.get('schema') == 'authbus-owned-worker-v1', 'worker_scope')
    central = import_central(Path(cfg['centralSource']))
    candidate_bytes = read_owned(root / 'source-owned.private.json')
    require(hash_bytes(candidate_bytes) == SOURCE_CANDIDATE_SHA, 'worker_owned_source_changed')
    record = validate_candidate(json.loads(candidate_bytes), central)
    confidential = source_secrets(record)
    config = central.load_config(Path(cfg['centralConfig']))
    require(config['address'].startswith('https://127.0.0.1:'), 'worker_loopback_only')
    deadline = cfg['absoluteDeadlineMonotonic']
    require(isinstance(deadline, (float, int)) and not isinstance(deadline, bool), 'worker_deadline_shape')

    class BoundBao(central.Bao):
        def _dispatch(self, method, route, body=None, *, bearer=None, started_at=None, bearer_deadline=None):
            remaining(deadline)
            # The actual client's original accepted lease is never enlarged.
            bound = min(deadline, bearer_deadline) if bearer_deadline is not None else deadline
            try:
                value = super()._dispatch(method, route, body, bearer=bearer, started_at=started_at, bearer_deadline=bound)
            except central.Conflict:
                # The unchanged Bao dispatch creates this exception only for
                # the real HTTP 400 plus exact errors == [CAS_ERROR] body.
                report.setdefault('actualCasConflictReplies', []).append({
                    'method': method, 'routeSha256': hash_bytes(route.encode()),
                    'status': 400, 'originalExactErrorContract': True,
                    'errorSha256': hash_bytes(central.CAS_ERROR.encode())})
                raise
            if route in ('auth/approle/login', 'auth/token/renew-self'):
                report.setdefault('completedAuthRoutes', []).append(route)
            return value

    client = BoundBao(config); secondary = []
    report = {'schema': 'authbus-owned-source-worker-v1', 'ok': False, 'action': cfg['action'],
              'sourceSha256': CENTRAL_SHA, 'realOwnedCredentialFixture': True,
              'syntheticCredentialFixture': False, 'productionMutation': False,
              'providerCalled': False, 'oauthRefreshed': False, 'originalOperationDeadlineReused': True}

    def capture():
        tokens = [item.token for item in [client, *secondary] if item.token is not None]
        private(output / 'tokens.private.json', json.dumps({'tokens': tokens}))

    def hook(phase):
        remaining(deadline)
        if phase == 'profile_confirmed':
            # This is immediately before the original coordinator writes its
            # manifest_dispatched journal and sends its single actual CAS.
            report['sourceReadBeforeManifest'] = source_recheck(output, deadline, confidential)
            if cfg.get('fault') == 'cas_metadata_race':
                competitor = BoundBao(config); secondary.append(competitor)
                current = competitor.read('manifest')
                current['data']['coordinator']['fixtureOperatorRevision'] = current['version']
                competitor.write('manifest', current['data'], current['version'])
                report['actualCompetingManifestCas'] = True
        if cfg.get('fault') == 'crash_after_manifest_commit' and phase == 'manifest_committed_before_journal_reply':
            capture()
            payload = {**report, 'injectedProcessExit': 73, 'lastObservedPhase': phase, 'publicSuccessClaimed': False}
            ensure_redacted(payload, confidential + client.secrets + [value for item in secondary for value in item.secrets])
            private(output / 'receipt.json', json.dumps(payload))
            os._exit(73)

    worker = central.Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'], hook)
    code = 2
    try:
        remaining(deadline)
        if cfg['action'] == 'initialize':
            result = worker.initialize()
        elif cfg['action'] == 'authorize':
            report['sourceReadBeforeAuthorization'] = source_recheck(output, deadline, confidential)
            expected_grant = {'profileId': record['profileId'], 'sourceHost': PRODUCER,
                              'provider': 'openai', 'identityDigest': record['identity'],
                              'expectedCurrentDigest': None, 'nextDigest': record['digest']}
            require({key: value for key, value in cfg['authorization'].items() if key != 'authorizationId'} == expected_grant,
                    'only_exact_initial_source_grant_allowed')
            result = worker.authorize(cfg['authorization'])
        elif cfg['action'] == 'recover':
            with central.operation_lock(worker.state):
                result = {'recovered_pending': worker.recover_locked()}
                worker.finish_previous_receipt(worker.manifest())
        elif cfg['action'] == 'renew-due':
            client.ensure_token(); before = client.token
            require(client.read('manifest') is not None, 'renew_live_manifest_before')
            # A conservative earlier local refresh point exercises the real
            # renew API. It never lengthens the original token lease.
            original = client.deadline
            client.deadline = min(original, time.monotonic() + 20)
            client.ensure_token()
            require(client.read('manifest') is not None, 'renew_live_manifest_after')
            result = {'actualRenewSelfSameBearer': client.token == before,
                      'forcedLocalDueClock': True, 'realLeaseExpiryWaited': False,
                      'originalLeaseOnlyShortenedBeforeRenew': original >= time.monotonic(),
                      'sameBearerLiveReadBeforeAndAfter': True}
        elif cfg['action'] == 'once':
            result = worker.once()
        else:
            raise CanaryFailure('worker_action')
        # Preserve a completed operation's observed result even when the
        # shared deadline expires immediately before public qualification.
        report['result'] = result
        remaining(deadline); report.update(ok=True); code = 0
    except Exception as exc:
        unknown = isinstance(exc, central.UnknownOutcome) or pending_may_have_dispatched(worker.pending)
        report.update(error=str(exc) if isinstance(exc, (central.Error, CanaryFailure)) else type(exc).__name__,
                      unknownOutcome=unknown, pendingRequiresRecovery=worker.pending.exists())
        code = 3 if unknown else 2
    finally:
        capture()
        ensure_redacted(report, confidential + client.secrets + worker.secrets
                        + [value for item in secondary for value in item.secrets])
        private(output / 'receipt.json', json.dumps(report))
    print(json.dumps(report, sort_keys=True))
    return code


def run(args, report, confidential):
    started = time.monotonic(); deadline = started + SECONDS
    require(Path(pwd.getpwuid(os.geteuid()).pw_dir) == ROOT_HOME and os.geteuid() != 0, 'actual_main_owner_required')
    require(args.source_receipt == SOURCE_OUTPUT / 'public-receipt.json'
            and args.source_receipt_sha256 == SOURCE_RECEIPT_SHA
            and args.source_inspector == SOURCE_INSPECTOR and args.openclaw_root == SOURCE_SDK
            and args.node == Path('/usr/bin/node'), 'exact_main_source_paths_required')
    root = args.work_dir
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent
            and root.is_relative_to(ROOT_HOME / 'heptabao-next-gates-20261017')
            and not root.is_relative_to(SOURCE_STATE) and not os.path.lexists(root), 'new_owned_fixture_root_required')
    root.mkdir(mode=0o700, parents=False, exist_ok=False); owned_directory(root)
    report['_owned_work_root_created'] = True
    report.update(checks=[], clients=[], central_actions=[], source_rechecks=[], server_cycles=[],
                  binary_sha256=sha(args.binary), driver_sha256=sha(__file__),
                  consumer_sha256=sha(CONSUMER), central_source_sha256=sha(args.central_source),
                  originalOperationBudgetSeconds=SECONDS, operationStartedMonotonic=started)
    central = import_central(args.central_source)
    owned_directory(SOURCE_OUTPUT)
    export_bytes = read_owned(args.source_receipt)
    require(hash_bytes(export_bytes) == SOURCE_RECEIPT_SHA, 'actual_export_receipt_bytes_changed')
    export_receipt = json.loads(export_bytes)
    validate_observation(export_receipt, mode='export')
    candidate_path = SOURCE_OUTPUT / 'candidate.private.json'
    require(export_receipt.get('privateCandidatePath') == str(candidate_path)
            and export_receipt.get('privateCandidateSha256') == SOURCE_CANDIDATE_SHA
            and export_receipt.get('privateCandidateMode') == '0o600'
            and export_receipt.get('persistedOwnerRecheckedAfterExport') is True
            and export_receipt.get('exportedProfileCount') == 1, 'actual_export_candidate_binding_changed')
    candidate_bytes = read_owned(candidate_path)
    require(hash_bytes(candidate_bytes) == SOURCE_CANDIDATE_SHA, 'actual_private_candidate_bytes_changed')
    record = validate_candidate(json.loads(candidate_bytes), central)
    confidential.extend(source_secrets(record))
    require(record['credential']['expires'] > int(time.time() * 1000) + REFRESH_MARGIN_MS, 'source_expiry_margin_elapsed')
    private(root / 'source-owned.private.json', candidate_bytes)
    private(root / 'source-export.public.json', export_bytes)
    profile, credential_a, digest_a = record['profileId'], record['credential'], record['digest']
    report['source'] = {'physicalHost': 'main', 'hostId': 'desktop', 'sourceOwnershipQualified': True,
        'exportReceiptPath': str(args.source_receipt), 'exportReceiptSha256': SOURCE_RECEIPT_SHA,
        'privateCandidatePath': str(candidate_path), 'privateCandidateSha256': SOURCE_CANDIDATE_SHA,
        'fixtureCopyExactBytes': True, 'profileIdSha256': SELECTION['profileIdSha256'],
        'credentialDigest': digest_a, 'identityDigest': record['identity'], 'provider': 'openai', 'type': 'oauth',
        'expiresMs': credential_a['expires'], 'providerLivenessVerified': False, 'snapshotNotARefreshLease': True,
        'sourceCandidateTransferredOffOwnerHost': False, 'fixtureProducerHostId': PRODUCER,
        'sourceHostAliasOnlyInsideFixture': True}
    issued, logs, roles, states, bindings = [], [], {}, {}, {}
    instance = None

    def check(name, condition, **metadata):
        report['checks'].append({'case': name, 'passed': bool(condition), **metadata})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, route, body=None, *, token=None, expected=200):
        remaining(deadline)
        status, value = instance.call(method, route, body, token=token)
        remaining(deadline)
        check(name, status == expected, status=status, expected=expected)
        return value

    def read_manifest(name):
        return call(name, 'GET', MOUNT + '/data/manifest')

    def entry_of(manifest):
        items = manifest['data']['data']['profiles']
        check('manifest.one_exact_profile.' + str(len(report['checks'])),
              len(items) == 1 and items[0]['profileId'] == profile)
        return items[0]

    def role(host, policy):
        route = 'auth/approle/role/' + host
        call(host + '.policy', 'PUT', 'sys/policies/acl/' + host, {'policy': policy}, expected=204)
        call(host + '.role', 'POST', route, {'token_policies': [host], 'token_ttl': '1200s', 'token_max_ttl': '1800s',
             'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204)
        role_id = call(host + '.role_id', 'GET', route + '/role-id')['data']['role_id']
        sid = call(host + '.sid', 'POST', route + '/secret-id', {})['data']
        confidential.extend((role_id, sid['secret_id'], sid['secret_id_accessor']))
        directory = root / 'credentials' / host; mkdir(directory)
        private(directory / 'role_id', role_id); private(directory / 'secret_id', sid['secret_id'])
        private(directory / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
        roles[host] = {'role': route, 'role_id': role_id, **sid}
        return directory

    def prepare_state(host, credential_dir, leader=False):
        state = root / host; agent = state / 'agents/main/agent'
        for directory in (state, state / 'agents', state / 'agents/main', agent, state / 'home', state / 'credentials'):
            mkdir(directory)
        private(state / 'openclaw.json', json.dumps({'agents': {'list': [{'id': 'main', 'default': True, 'agentDir': str(agent)}]}}))
        binding = {'address': instance.address, 'caFile': str(credential_dir / 'ca.crt'),
                   'roleIdFile': str(credential_dir / 'role_id'), 'secretIdFile': str(credential_dir / 'secret_id'),
                   'hostId': PRODUCER if leader else FOLLOWER, 'leader': leader, 'publishNew': True, 'manageOrder': True,
                   'releaseGeneration': 201, 'pollIntervalMs': 15000, 'refreshMarginMs': REFRESH_MARGIN_MS, 'maxRefreshesPerCycle': 1}
        binding_path = root / (host + '-binding.private.json'); private(binding_path, json.dumps(binding))
        states[host], bindings[host] = (state, agent), binding_path

    def collect_process(name, argv, run_dir, expected, environment):
        result = owned_process.run(argv, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=remaining(deadline), label='authbus-owned.' + name)
        for filename, data in (('stdout.log', result.stdout), ('stderr.log', result.stderr)):
            private(run_dir / filename, data); logs.append(run_dir / filename)
        check(name + '.bounded_public_stream', len(result.stdout) + len(result.stderr) <= LIMIT)
        capture_path = run_dir / 'tokens.private.json'
        if capture_path.exists():
            for item in private_json(capture_path).get('tokens', []):
                token = item.get('token') if isinstance(item, dict) else item
                check(name + '.captured_actual_token', isinstance(token, str) and len(token) >= 8)
                confidential.append(token); issued.append(token)
                if isinstance(item, dict) and isinstance(item.get('accessor'), str):
                    confidential.append(item['accessor'])
        # Capture this invocation's new bearer before inspecting its stdout.
        ensure_redacted(result.stdout + result.stderr, confidential)
        check(name + '.public_stream_redacted', True)
        receipt = private_json(run_dir / 'receipt.json'); ensure_redacted(receipt, confidential)
        check(name + '.public_receipt_redacted', True)
        if receipt.get('unknownOutcome') is True:
            # The child may have reached the canonical manifest before its
            # deadline/transport failure. Preserve that boundary in the main
            # receipt even when the unexpected exit prevents later recovery.
            report['mutationOutcomeUnknown'] = True
            report.setdefault('unknown_outcomes', []).append({
                'case': name, 'workerReceiptPath': str(run_dir / 'receipt.json'),
                'workerReceiptSha256': hash_bytes(read_owned(run_dir / 'receipt.json')),
                'pendingRequiresRecovery': receipt.get('pendingRequiresRecovery') is True,
                'automaticRetryAllowed': False})
        check(name + '.exit', result.returncode == expected, actual=result.returncode, expected=expected)
        return receipt

    def central_action(name, action='once', expected=0, **extra):
        run_dir = root / 'runs' / name; mkdir(run_dir)
        cfg = {'schema': 'authbus-owned-worker-v1', 'workRoot': str(root), 'runDir': str(run_dir),
               'centralSource': str(root / 'authbus_coordinator.py'), 'centralConfig': str(root / 'central-config.private.json'),
               'absoluteDeadlineMonotonic': deadline, 'action': action, **extra}
        path = run_dir / 'worker.private.json'; private(path, json.dumps(cfg))
        result = collect_process(name, [sys.executable, str(Path(__file__).resolve()), '--worker', str(path)],
                                 run_dir, expected, clean_environment(ROOT_HOME))
        report['central_actions'].append({'case': name, **result})
        if expected == 0:
            check(name + '.actual_service_ok', result.get('ok') is True)
        return result

    def client(name, host, steps=None, expected=0):
        state, agent = states[host]; run_dir = root / 'runs' / name; mkdir(run_dir)
        cfg = {'schema': 'authbus-owned-source-client-driver-v1', 'workRoot': str(root), 'stateDir': str(state),
               'agentDir': str(agent), 'runDir': str(run_dir), 'homeDir': str(state / 'home'),
               'oauthDir': str(state / 'credentials'), 'configPath': str(state / 'openclaw.json'),
               'openclawRoot': str(args.openclaw_root), 'pluginEntry': str(root / 'plugin/index.js'),
               'pluginConfig': private_json(bindings[host]), 'capturePath': str(run_dir / 'tokens.private.json'),
               'receiptPath': str(run_dir / 'receipt.json'), 'diagnosticsPath': str(run_dir / 'sdk-diagnostics.private.log'),
               'sourceCandidatePath': str(root / 'source-owned.private.json'), 'sourceCandidateSha256': SOURCE_CANDIDATE_SHA,
               'sourceReceiptSha256': SOURCE_RECEIPT_SHA, 'serverCertificateSha256': report['server_cert_der_sha256'],
               'absoluteDeadlineMonotonicNs': str(int(deadline * 1000000000)),
               'steps': steps or [{}]}
        path = run_dir / 'client.private.json'; private(path, json.dumps(cfg))
        result = collect_process(name, [str(args.node), str(CONSUMER), str(path)], run_dir, expected, clean_environment(state / 'home'))
        report['clients'].append({'case': name, **result})
        check(name + '.original_operation_deadline', result.get('originalOperationDeadlineReused') is True)
        check(name + '.actual_default_scope', result.get('defaultAgentScoped') is True)
        check(name + '.no_provider_or_external_cli_attempt', result.get('outsideNetworkAttempts') == 0
              and result.get('childProcessAttempts') == 0)
        if expected == 0:
            check(name + '.actual_original_plugin_ok', result.get('ok') is True)
            check(name + '.actual_approle_login', result.get('authentications') == 1)
            observations = result['observations']
            check(name + '.real_full_tls', bool(observations) and all(item.get('tlsAuthorized') is True
                  and item.get('peerCertificateSha256') == report['server_cert_der_sha256']
                  and item.get('isSessionReused') is False
                  and item.get('originalOperationDeadlineReused') is True for item in observations))
            check(name + '.actual_default_shadow', all(cycle['plugin'].get('schedulerMode') == 'shadow'
                  and cycle['plugin'].get('strictLeaseAssignments') == 0 for cycle in result['cycles']))
        return result

    def profile_digest(snapshot):
        return snapshot['profilesByIdSha256'].get(SELECTION['profileIdSha256'])

    def restart(name):
        remaining(deadline)
        old = instance.process; instance.stop()
        report['server_cycles'].append({'case': name, 'original_pid': old.pid, 'exit_code': old.returncode, 'method': 'SIGKILL'})
        check(name + '.actual_sigkill', old.returncode == -9)
        check(name + '.binary_unchanged', sha(args.binary) == report['binary_sha256'])
        instance.start()
        call(name + '.sealed', 'GET', 'sys/health', expected=503)
        call(name + '.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        capacity = call(name + '.capacity', 'GET', 'sys/internal/capacity')['data']
        check(name + '.native_v6', capacity.get('native_kv2_reader_format') == 2)

    # The only inherited process is this QA driver. Set a minimal environment
    # before NativeInstance starts the disposable server/openssl children.
    environment_before = dict(os.environ)
    umask_before = os.umask(0o077)
    os.environ.clear(); os.environ.update(clean_environment(ROOT_HOME))
    try:
        for directory in (root / 'plugin', root / 'node_modules', root / 'credentials', root / 'runs', root / 'central-state'):
            mkdir(directory)
        private(root / 'authbus_coordinator.py', args.central_source.read_bytes())
        report['plugin_source_sha256'] = {}
        require(set(FILES) == set(PLUGIN_CONTRACT), 'original_plugin_dependency_set_changed')
        for name in FILES:
            source = args.plugin_root / name
            check('original_plugin.' + name, source.is_file() and not source.is_symlink() and source.stat().st_size <= 262144)
            source_bytes = source.read_bytes()
            report['plugin_source_sha256'][name] = hash_bytes(source_bytes)
            check('original_plugin.frozen_fingerprint.' + name,
                  report['plugin_source_sha256'][name] == PLUGIN_CONTRACT[name])
            private(root / 'plugin' / name, source_bytes)
        check('original_plugin.expected_main_version', report['plugin_source_sha256']['index.js'] == ORIGINAL_PLUGIN_SHA)
        private(root / 'plugin/package.json', json.dumps({'type': 'module', 'private': True}))
        (root / 'node_modules/openclaw').symlink_to(args.openclaw_root, target_is_directory=True)
        source_preflight_dir = root / 'runs/source_initial_recheck'; mkdir(source_preflight_dir)
        report['source_rechecks'].append(source_recheck(source_preflight_dir, deadline, confidential))
        instance = NativeInstance(args.binary, root / 'server')
        report['server_cert_der_sha256'] = cert_sha256(instance.root / 'tls.crt'); instance.start()
        init = call('server.init', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        instance.token, unseal = init['root_token'], init['keys_base64'][0]
        confidential.extend((instance.token, unseal))
        private(root / 'recovery.private.json', json.dumps({'root_token': instance.token, 'unseal_key': unseal}))
        call('server.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('server.mount', 'POST', 'sys/mounts/' + MOUNT, {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('server.activate_native', 'POST', 'sys/internal/native-v6/activate', {}, expected=204)
        check('server.native_format2', call('server.capacity', 'GET', 'sys/internal/capacity')['data'].get('native_kv2_reader_format') == 2)
        call('server.approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        for key, data in [('order-policy', {'schemaVersion': 1, 'generation': 0, 'providers': {}}),
                          ('scheduler-assignments', {'schemaVersion': 1, 'generation': 0, 'scopes': [], 'assignments': [], 'refreshLeases': []})]:
            call('bootstrap.empty.' + key, 'POST', MOUNT + '/data/' + key, {'data': data, 'options': {'cas': 0}})
        # No active refresh profile is selected. The original plugin's leader
        # refresh branch has zero candidates; the Node network gate also
        # rejects and counts any outside request/CLI attempt.
        report['refreshExclusion'] = {'originalOrderPolicyHasNoActiveProfiles': True,
            'originalCredentialExpiryUnmodified': True, 'providerNetworkDenied': True}
        for host in (PRODUCER, FOLLOWER):
            policy = f'''path "{MOUNT}/data/manifest" {{ capabilities=["read"] }}
path "{MOUNT}/data/profiles/*" {{ capabilities=["read"] }}
path "{MOUNT}/data/order-policy" {{ capabilities=["read"] }}
path "{MOUNT}/data/scheduler-assignments" {{ capabilities=["read"] }}
path "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["create"] }}
path "auth/token/renew-self" {{ capabilities=["update"] }}
path "auth/token/revoke-self" {{ capabilities=["update"] }}'''
            credential_dir = role(host, policy); prepare_state(host, credential_dir, leader=host == PRODUCER)
        writer_policy = f'''path "{MOUNT}/data/manifest" {{ capabilities=["create","read","update"] }}
path "{MOUNT}/data/profiles/*" {{ capabilities=["create","read"] }}
path "{MOUNT}/data/coordinator-receipts/*" {{ capabilities=["create","read"] }}
path "auth/token/renew-self" {{ capabilities=["update"] }}
path "auth/token/revoke-self" {{ capabilities=["update"] }}'''
        for host in (PRODUCER, FOLLOWER):
            writer_policy += f'\npath "{MOUNT}/metadata/inbox/{host}" {{ capabilities=["list"] }}\npath "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["read"] }}'
        credential_dir = role(WRITER, writer_policy)
        config = {'schema': 'heptabao-authbus-coordinator-v1.config', 'address': instance.address,
                  'ca_file': str(credential_dir / 'ca.crt'), 'role_id_file': str(credential_dir / 'role_id'),
                  'secret_id_file': str(credential_dir / 'secret_id'), 'server_certificate_sha256': report['server_cert_der_sha256'],
                  'state_dir': str(root / 'central-state'), 'owner_id': str(uuid.uuid4()),
                  'source_hosts': [PRODUCER, FOLLOWER], 'production_cutover': False}
        private(root / 'central-config.private.json', json.dumps(config))
        central_action('central_initialize', 'initialize')
        published = client('original_producer_exact_source_event', PRODUCER, [{}, {'upsertOwnedSource': True}])
        check('original_producer.leader_true', all(cycle['plugin'].get('leader') is True for cycle in published['cycles']))
        check('original_producer.baseline_then_one_new_event', [cycle['plugin'].get('publishedEvents') for cycle in published['cycles']] == [0, 1])
        deferred = central_action('central_requires_operator')
        check('central.no_implicit_source_authority', deferred['result']['committed'] == 0 and deferred['result']['deferred'] == 1)
        check('central.no_implicit_publication', read_manifest('manifest_before_authorization')['data']['data']['profiles'] == [])
        grant = {'authorizationId': str(uuid.uuid4()), 'profileId': profile, 'sourceHost': PRODUCER,
                 'provider': 'openai', 'identityDigest': record['identity'], 'expectedCurrentDigest': None, 'nextDigest': digest_a}
        central_action('operator_authorize_exact_a', 'authorize', authorization=grant)
        race = central_action('actual_manifest_cas_race', fault='cas_metadata_race')
        check('central.actual_cas_rejection', race.get('actualCompetingManifestCas') is True
              and race['result']['deferred'] == 1
              and race.get('actualCasConflictReplies') == [{
                  'method': 'POST', 'routeSha256': hash_bytes((MOUNT + '/data/manifest').encode()),
                  'status': 400, 'originalExactErrorContract': True,
                  'errorSha256': hash_bytes(central.CAS_ERROR.encode())}])
        check('central.conflict_published_no_credential', read_manifest('canonical_after_conflict')['data']['data']['profiles'] == [])
        check('central.conflict_completed_no_unknown_pending', not (root / 'central-state/pending.private.json').exists())
        central_action('actual_central_process_crash', expected=73, fault='crash_after_manifest_commit')
        pending = private_json(root / 'central-state/pending.private.json')
        check('central.write_ahead_journal_survived', pending.get('phase') == 'manifest_dispatched')
        manifest_a = read_manifest('canonical_a_before_recovery'); entry_a = entry_of(manifest_a)
        check('central.actual_commit_without_success_receipt', entry_a['digest'] == digest_a
              and manifest_a['data']['data']['generation'] == 1)
        payload_a = call('immutable_a_read', 'GET', MOUNT + '/data/profiles/' + entry_a['key'])['data']
        check('central.original_credential_payload_exact', central.canonical(payload_a['data']['credential']) == central.canonical(credential_a)
              and entry_a['digest'] == digest_a and payload_a['metadata']['version'] == 1)
        check('central.full_document_content_address', entry_a['key'] == 'sha256-' + central.digest(payload_a['data']))
        restart('server_cold_restart_with_pending')
        recovered = central_action('central_cold_recover', 'recover')
        check('central.current_or_historical_manifest_recovery', recovered['result']['recovered_pending'] is True)
        after_recovery = read_manifest('canonical_a_after_recovery')
        check('central.recovery_did_not_replay_manifest', after_recovery['data']['metadata']['version'] == manifest_a['data']['metadata']['version'])
        check('central.pending_cleared_after_immutable_receipt', not (root / 'central-state/pending.private.json').exists())
        client('original_producer_accept_a', PRODUCER)
        follower_a = client('original_follower_consume_a', FOLLOWER)
        check('original_follower.leader_false', follower_a['cycles'][0]['plugin'].get('leader') is False)
        check('original_follower.actual_sdk_exact_a', profile_digest(follower_a['cycles'][0]['after']) == digest_a
              and follower_a['cycles'][0]['before']['profilesByIdSha256'] == {})
        backup = root / 'follower-backup'; mkdir(backup)
        backup_files = []
        for suffix in ('', '-wal'):
            source = states[FOLLOWER][1] / ('openclaw-agent.sqlite' + suffix)
            if source.exists():
                data = read_owned(source, 32 * 1024 * 1024)
                private(backup / source.name, data)
                backup_files.append({'name': source.name, 'bytes': len(data), 'sha256': hash_bytes(data)})
        check('backup.closed_actual_sdk_database', any(item['name'] == 'openclaw-agent.sqlite' for item in backup_files))
        report['backup'] = {'processClosedBeforeCopy': True, 'files': backup_files, 'sourceCredentialDigest': digest_a}
        restore_host = 'authbus-owned-restored'; prepare_state(restore_host, root / 'credentials' / FOLLOWER)
        for item in backup_files:
            data = read_owned(backup / item['name'], 32 * 1024 * 1024)
            check('backup.bytes_exact.' + item['name'], hash_bytes(data) == item['sha256'])
            private(states[restore_host][1] / item['name'], data)
        restored = client('actual_sdk_backup_restore', restore_host)
        check('backup.actual_sdk_restored_same_real_source', profile_digest(restored['cycles'][0]['before']) == digest_a
              and profile_digest(restored['cycles'][0]['after']) == digest_a)
        binding_path = bindings[FOLLOWER]; original_binding = read_owned(binding_path)
        owned_process.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                           '-subj', '/CN=AuthBus Owned Source Wrong CA', '-keyout', str(root / 'wrong-ca.key'),
                           '-out', str(root / 'wrong-ca.crt')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=remaining(deadline), label='authbus-owned.wrong-ca')
        (root / 'wrong-ca.key').chmod(0o600); (root / 'wrong-ca.crt').chmod(0o600)
        wrong = private_json(binding_path); wrong['caFile'] = str(root / 'wrong-ca.crt')
        private(binding_path, json.dumps(wrong), replace=True)
        rejected = client('follower_bad_binding', FOLLOWER, expected=3)
        check('rollback.no_auth_and_real_local_value_retained', rejected.get('authentications') == 0
              and profile_digest(rejected['cycles'][0]['after']) == digest_a)
        private(binding_path, original_binding, replace=True)
        rollback = client('follower_binding_rollback', FOLLOWER)
        check('rollback.same_binding_bytes_and_actual_sdk', read_owned(binding_path) == original_binding
              and profile_digest(rollback['cycles'][0]['after']) == digest_a)
        renewed = central_action('central_actual_renewal_api', 'renew-due')
        check('central.renew_same_bearer_real_api', renewed['result']['actualRenewSelfSameBearer'] is True
              and renewed['result']['sameBearerLiveReadBeforeAndAfter'] is True
              and renewed['completedAuthRoutes'] == ['auth/approle/login', 'auth/token/renew-self'])
        writer_token = issued[-1]
        client('original_producer_acl_read_control', PRODUCER); producer_token = issued[-1]
        call('acl.producer_live_read_control', 'GET', MOUNT + '/data/manifest', token=producer_token)
        call('acl.writer_live_read_control', 'GET', MOUNT + '/data/manifest', token=writer_token)
        call('acl.producer_canonical_write_denied', 'POST', MOUNT + '/data/manifest',
             {'data': {}, 'options': {'cas': after_recovery['data']['metadata']['version']}}, token=producer_token, expected=403)
        call('acl.producer_other_inbox_denied', 'POST', MOUNT + '/data/inbox/' + FOLLOWER + '/' + str(uuid.uuid4()),
             {'data': {}, 'options': {'cas': 0}}, token=producer_token, expected=403)
        call('acl.writer_immutable_update_denied', 'POST', MOUNT + '/data/profiles/' + entry_a['key'],
             {'data': {}, 'options': {'cas': 1}}, token=writer_token, expected=403)
        latest_receipt = after_recovery['data']['data']['coordinator']['lastReceipt']
        receipt_key = 'coordinator-receipts/' + hash_bytes((latest_receipt['sourceHost'] + '\0' + latest_receipt['eventId']).encode())
        call('acl.writer_receipt_update_denied', 'POST', MOUNT + '/data/' + receipt_key,
             {'data': {}, 'options': {'cas': 1}}, token=writer_token, expected=403)
        call('acl.writer_inbox_injection_denied', 'POST', MOUNT + '/data/inbox/' + PRODUCER + '/' + str(uuid.uuid4()),
             {'data': {}, 'options': {'cas': 0}}, token=writer_token, expected=403)
        dedup = central_action('central_cold_dedup')
        check('central.same_event_not_republished', dedup['result']['committed'] == 0
              and read_manifest('canonical_final_generation')['data']['data']['generation'] == 1)
        all_tokens = list(dict.fromkeys(issued))
        for index, token in enumerate(all_tokens):
            call('revoke.token_live_before.' + str(index), 'GET', MOUNT + '/data/manifest', token=token)
            call('revoke.token.' + str(index), 'POST', 'auth/token/revoke-self', {}, token=token, expected=204)
            call('revoke.token_denied.' + str(index), 'GET', MOUNT + '/data/manifest', token=token, expected=403)
        for host in (PRODUCER, FOLLOWER, WRITER):
            call('revoke.sid.' + host, 'POST', roles[host]['role'] + '/secret-id-accessor/destroy',
                 {'secret_id_accessor': roles[host]['secret_id_accessor']}, expected=204)
            call('revoke.sid_login_denied.' + host, 'POST', 'auth/approle/login',
                 {'role_id': roles[host]['role_id'], 'secret_id': roles[host]['secret_id']}, token='', expected=400)
        revoked_login = client('original_follower_sid_revoked', FOLLOWER, expected=3)
        check('revoke.original_plugin_exact_sid_denial', revoked_login['authentications'] == 0
              and any(item.get('route') == 'login' and item.get('status') == 400 for item in revoked_login['observations']))
        restart('revocations_cold_restart')
        for index, token in enumerate(all_tokens):
            call('revoke.persisted_token.' + str(index), 'GET', MOUNT + '/data/manifest', token=token, expected=403)
        for host in (PRODUCER, FOLLOWER, WRITER):
            call('revoke.persisted_sid_login_denied.' + host, 'POST', 'auth/approle/login',
                 {'role_id': roles[host]['role_id'], 'secret_id': roles[host]['secret_id']}, token='', expected=400)
        source_final_dir = root / 'runs/source_final_recheck'; mkdir(source_final_dir)
        report['source_rechecks'].append(source_recheck(source_final_dir, deadline, confidential))
        check('source.original_plugin_unchanged', all(sha(args.plugin_root / name) == expected
              for name, expected in report['plugin_source_sha256'].items()))
        check('source.central_code_unchanged', sha(args.central_source) == CENTRAL_SHA == sha(root / 'authbus_coordinator.py'))
        check('source.export_bytes_unchanged', hash_bytes(read_owned(candidate_path)) == SOURCE_CANDIDATE_SHA
              and hash_bytes(read_owned(args.source_receipt)) == SOURCE_RECEIPT_SHA)
        all_public_diagnostics = b''.join(read_owned(path) for path in logs) + (instance.root / 'server.log').read_bytes()
        ensure_redacted(all_public_diagnostics, confidential); ensure_redacted(report, confidential)
        check('evidence.no_secret_profile_or_identity_in_public_receipts', True)
        remaining(deadline)
        report.update(ok=True, actual_independent_service_credential_publication=True,
                      actual_original_producer_and_consumer=True, actual_sdk_qualified=True,
                      actual_service_https_qualified=True, central_process_crash_and_server_restart_qualified=True,
                      allIssuedFixtureTokensRevokedAndColdDenied=True, allFixtureAppRoleSecretIdsDestroyed=True,
                      allFixtureAppRoleSecretIdsColdLoginDenied=True,
                      revokedTokenScope='captured_fixture_approle_bearers',
                      sourceStillExactAtFinalRecheck=True, sourceSnapshotNotARefreshLease=True,
                      provider_liveness_verified=False, oauth_refresh_ownership_qualified=False,
                      enforced_scheduler_qualified=False, production_coordinator_replacement=False,
                      realCredentialVersionsUsed=1, originalOperationElapsedSeconds=round(time.monotonic() - started, 3))
    finally:
        if instance is not None:
            instance.stop()
        os.environ.clear(); os.environ.update(environment_before)
        os.umask(umask_before)


class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.central = import_central(HERE.parents[1] / 'tools/authbus/authbus_coordinator.py')

    def fixtures(self):
        credential = {'provider': 'openai', 'type': 'oauth', 'access': 'synthetic-owned-access',
                      'refresh': 'synthetic-owned-refresh', 'expires': 1900000000000,
                      'email': 'synthetic-owned@example.invalid', 'accountId': 'synthetic-owned'}
        selection = {**SELECTION, 'profileIdSha256': hash_bytes(b'openai:synthetic-owned'),
                     'credentialDigest': self.central.digest(credential), 'identityDigest': self.central.identity(credential)}
        candidate = {'schema': 'authbus-owned-sdk-source-snapshot-v1', 'hostId': 'desktop', 'stateDir': str(SOURCE_STATE),
                     'configSha256': SOURCE_CONFIG_SHA, 'inspectReceiptSha256': SOURCE_INSPECT_RECEIPT_SHA,
                     'sdkContract': SDK_CONTRACT, 'constraints': {'providerLivenessVerified': False, 'oauthRefreshed': False,
                         'productionCutover': False, 'snapshotRequiresRecheckBeforePublication': True, 'coordinatorOwnershipQualified': False},
                     'profiles': [{'profileId': 'openai:synthetic-owned', 'credential': credential,
                         'digest': selection['credentialDigest'], 'identity': selection['identityDigest'],
                         'source': {'scopeAgentDir': str(SOURCE_OWNER), 'ownerAgentDir': str(SOURCE_OWNER),
                                    'databasePath': str(SOURCE_OWNER / 'openclaw-agent.sqlite'), 'method': 'actual_sdk_readonly_persisted_owner'}}]}
        row = {**selection, 'ownerDatabasePath': str(SOURCE_OWNER / 'openclaw-agent.sqlite'),
               'persistedOwnerMatchesEffective': True, 'hasSecretReference': False, 'inheritedFromMain': False,
               'provider': 'openai', 'type': 'oauth', 'oauthRefreshAttempted': False, 'providerLivenessVerified': False}
        receipt = {'schema': 'authbus-owned-sdk-source-public-v1', 'ok': True, 'mode': 'inspect', 'hostId': 'desktop',
                   'stateDir': str(SOURCE_STATE), 'configSha256': SOURCE_CONFIG_SHA, 'sdkContract': SDK_CONTRACT,
                   'agentDirs': [str(SOURCE_OWNER)], 'defaultAgentDir': str(SOURCE_OWNER), 'profiles': [row],
                   'readOnlyProductionAccess': True, 'actualSdkReadOnlyOwnerApiUsed': True, 'sourceSnapshotNotARefreshLease': True}
        for key in ('productionMutation', 'productionCutover', 'providerCalled', 'oauthRefreshed',
                    'externalCliProfilesImported', 'j3160Contacted', 'productionStoreWriteAttempted', 'providerLivenessVerified'):
            receipt[key] = False
        return copy.deepcopy(candidate), copy.deepcopy(receipt), selection

    def test_exact_source_and_owner(self):
        candidate, receipt, selection = self.fixtures()
        self.assertEqual(validate_candidate(candidate, self.central, selection=selection)['digest'], selection['credentialDigest'])
        self.assertEqual(validate_observation(receipt, mode='inspect', selection=selection)['credentialDigest'], selection['credentialDigest'])

    def test_changed_source_refuses_without_alternative(self):
        candidate, receipt, selection = self.fixtures()
        receipt['profiles'][0]['credentialDigest'] = '0' * 64
        with self.assertRaises(CanaryFailure):
            validate_observation(receipt, mode='inspect', selection=selection)
        candidate['profiles'][0]['credential']['access'] += '-changed'
        with self.assertRaises(CanaryFailure):
            validate_candidate(candidate, self.central, selection=selection)

    def test_changed_identity_and_owner(self):
        _, receipt, selection = self.fixtures()
        for field in ('identityDigest', 'ownerAgentDir', 'scopeAgentDir'):
            changed = copy.deepcopy(receipt); changed['profiles'][0][field] += '-changed'
            with self.assertRaises(CanaryFailure):
                validate_observation(changed, mode='inspect', selection=selection)

    def test_refresh_or_provider_claim_refused(self):
        candidate, receipt, selection = self.fixtures()
        for field in ('providerLivenessVerified', 'oauthRefreshed', 'coordinatorOwnershipQualified'):
            changed = copy.deepcopy(candidate); changed['constraints'][field] = True
            with self.assertRaises(CanaryFailure):
                validate_candidate(changed, self.central, selection=selection)
        receipt['providerCalled'] = True
        with self.assertRaises(CanaryFailure):
            validate_observation(receipt, mode='inspect', selection=selection)

    def test_sdk_or_config_changed(self):
        _, receipt, selection = self.fixtures()
        for field in ('configSha256', 'sdkContract'):
            changed = copy.deepcopy(receipt); changed[field] = 'changed'
            with self.assertRaises(CanaryFailure):
                validate_observation(changed, mode='inspect', selection=selection)

    def test_duplicate_profile_refused(self):
        candidate, receipt, selection = self.fixtures()
        candidate['profiles'].append(candidate['profiles'][0])
        with self.assertRaises(CanaryFailure):
            validate_candidate(candidate, self.central, selection=selection)
        receipt['profiles'].append(receipt['profiles'][0])
        with self.assertRaises(CanaryFailure):
            validate_observation(receipt, mode='inspect', selection=selection)

    def test_profile_identity_and_credentials_are_private(self):
        candidate, _, _ = self.fixtures(); values = source_secrets(candidate['profiles'][0])
        for value in values:
            with self.assertRaises(CanaryFailure):
                ensure_redacted({'accidental': value}, values)
        ensure_redacted({'digest': candidate['profiles'][0]['digest']}, values)

    def test_js_canonical_unicode_digest(self):
        self.assertEqual(self.central.canonical({'z': 1, 'identity': '测试'}), '{"identity":"测试","z":1}'.encode())

    def test_original_deadline_does_not_restart(self):
        from unittest.mock import patch
        with patch('time.monotonic', return_value=108.0):
            self.assertEqual(remaining(110.0), 2.0)
        with patch('time.monotonic', return_value=110.0):
            with self.assertRaises(CanaryFailure):
                remaining(110.0)
        for value in (float('nan'), float('inf'), True, '110'):
            with self.assertRaises(CanaryFailure):
                remaining(value)

    def test_post_dispatch_deadline_does_not_claim_known_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'pending.private.json'
            self.assertFalse(pending_may_have_dispatched(path))
            for phase in ('prepared', 'profile_confirmed', 'manifest_dispatched',
                          'manifest_confirmed', 'receipt_confirmed', 'invalid'):
                private(path, json.dumps({'phase': phase}), replace=path.exists())
                self.assertEqual(pending_may_have_dispatched(path), phase not in ('prepared', 'profile_confirmed'))
            private(path, '{unreadable journal', replace=True)
            self.assertTrue(pending_may_have_dispatched(path))

    def test_private_file_mode_symlink_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); filename = root / 'source.private.json'
            private(filename, '{}')
            self.assertEqual(read_owned(filename), b'{}')
            filename.chmod(0o644)
            with self.assertRaises(CanaryFailure):
                read_owned(filename)
            filename.chmod(0o600)
            with self.assertRaises(CanaryFailure):
                read_owned(filename, 1)
            alias = root / 'alias'; alias.symlink_to(filename)
            with self.assertRaises(OSError):
                read_owned(alias)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts))
        print(json.dumps({'schema': 'authbus-owned-live-contract-test-v1', 'ok': result.wasSuccessful(),
                          'tests': result.testsRun, 'syntheticOnly': True, 'actualSdkQualified': False,
                          'providerCalled': False, 'productionMutation': False}, sort_keys=True))
        return 0 if result.wasSuccessful() else 1
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        try:
            return run_worker(Path(sys.argv[2]))
        except Exception as exc:
            print(json.dumps({'schema': 'authbus-owned-source-worker-v1', 'ok': False,
                              'error': 'worker_preflight_or_private_evidence_failed', 'errorClass': type(exc).__name__,
                              'productionMutation': False}))
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--central-source', type=Path, required=True)
    parser.add_argument('--plugin-root', type=Path, required=True)
    parser.add_argument('--openclaw-root', type=Path, required=True)
    parser.add_argument('--node', type=Path, default=Path('/usr/bin/node'))
    parser.add_argument('--source-receipt', type=Path, required=True)
    parser.add_argument('--source-receipt-sha256', required=True)
    parser.add_argument('--source-inspector', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 'native-v6-authbus-real-owned-source-live-v1', 'ok': False,
              'production_cutover': False, 'production_coordinator_replacement': False, 'production_mutation': False,
              'j3160_contacted': False, 'real_provider_credentials': True, 'provider_called': False,
              'physical_host': 'main', 'single_node_native_fixture': True, 'ha_cluster_qualified': False,
              'provider_liveness_verified': False, 'oauth_refreshed': False, 'oauth_refresh_ownership_qualified': False,
              'enforced_scheduler_qualified': False, 'actual_sdk_qualified': False, 'actual_service_https_qualified': False}
    confidential = []
    try:
        run(args, report, confidential)
    except Exception as exc:
        report.update(ok=False, error=str(exc) if isinstance(exc, CanaryFailure) else type(exc).__name__)
    created = report.pop('_owned_work_root_created', False)
    try:
        ensure_redacted(report, confidential)
    except CanaryFailure:
        report = {'schema': 'native-v6-authbus-real-owned-source-live-v1', 'ok': False,
                  'error': 'public_owned_source_evidence_refused', 'production_mutation': False, 'production_cutover': False}
    if created:
        owned_directory(args.work_dir)
        private(args.work_dir / 'public-receipt.json', json.dumps(report, sort_keys=True))
    print(json.dumps({'ok': report['ok'], 'checks': len(report.get('checks', [])),
                      'public_receipt_path': str(args.work_dir / 'public-receipt.json'),
                      'error': report.get('error'), 'production_cutover': False,
                      'provider_called': False, 'oauth_refreshed': False}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
