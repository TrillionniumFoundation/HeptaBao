#!/usr/bin/env python3
"""Finite profile-3 binding audit of already captured inputs; no live/provider I/O."""
from pathlib import Path
import hashlib, json, os
from authbus_profile2_selector_live import read_private, put, need

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1')
CAPTURE = ROOT / 'native-multisource-prepare-r1'
OUT = ROOT / 'profile3-current-bindings-r1'
TARGET = 'dfe45608d591590e55167d33f097a2a7f7119cd2256d8ebdc149e06d1befd1ae'
sha = lambda b: hashlib.sha256(b).hexdigest()


def main():
    os.umask(0o077); OUT.mkdir(mode=0o700)
    inputs = {}
    def read(name):
        b = read_private(CAPTURE / name); inputs[name] = sha(b); return json.loads(b)
    prepared = read('prepare.public.json'); order = read('order.public.json')
    cfg = read('original-config.private.json'); rows = read('captured-auth-rows.private.json')
    binding = read('order-binding.private.json'); documents = read('seed-documents.private.json')
    need(prepared['ok'] and order['ok'], 'captured_preparation_must_be_successful')
    need(inputs['order-binding.private.json'] == order['orderBindingSha256'], 'actual_sdk_order_binding_pin')
    need(inputs['seed-documents.private.json'] == order['seedDocumentsSha256'], 'replacement_manifest_pin')
    main_store = binding['originalStore']; all_profiles = main_store['profiles']; ids = list(all_profiles)
    matches = [pid for pid, c in all_profiles.items() if sha(c.get('accountId', '').encode()) == TARGET]
    need(len(matches) == 1 and ids.index(matches[0]) == 2, 'captured_profile3_identity')
    pid = matches[0]; credential = all_profiles[pid]
    identity_values = {pid: 'profileId', credential['accountId']: 'accountId'}
    if credential.get('email'): identity_values[credential['email']] = 'email'
    refs = []
    def safe_key(key):
        key = str(key)
        for ordinal, known in enumerate(ids, 1): key = key.replace(known, '<profile-' + str(ordinal) + '>')
        for value in identity_values:
            if value: key = key.replace(value, '<profile-3-identity>')
        return key
    def walk(value, trail):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in identity_values:
                    refs.append({'path': '.'.join(trail + [safe_key(key)]), 'kind': 'object-key-' + identity_values[key],
                                 'metadataDefinition': trail[:2] == ['auth', 'profiles']})
                walk(item, trail + [safe_key(key)])
        elif isinstance(value, list):
            for index, item in enumerate(value): walk(item, trail + ['[' + str(index) + ']'])
        elif isinstance(value, str) and value in identity_values:
            refs.append({'path': '.'.join(trail), 'kind': 'value-' + identity_values[value],
                         'metadataDefinition': trail[:2] == ['auth', 'profiles']})
    walk(cfg, [])
    stores = []
    for captured in rows:
        store_rows = captured['rows']['store']; state_rows = captured['rows']['state']
        data = json.loads(store_rows[0][1]) if store_rows else {}
        state = json.loads(state_rows[0][1]) if state_rows else {}
        profiles = data.get('profiles', {}); local_ids = list(profiles)
        local_matches = [key for key, c in profiles.items() if sha(c.get('accountId', '').encode()) == TARGET]
        local_order = state.get('order', {}).get('openai')
        selected_stats = state.get('usageStats', {}).get(local_matches[0], {}) if len(local_matches) == 1 else {}
        stores.append({'agent': captured['agent'], 'capturedCredentialCount': len(profiles),
            'targetPresent': bool(local_matches), 'targetMatchCount': len(local_matches),
            'targetLocalOrdinals': [local_ids.index(key) + 1 for key in local_matches],
            'storedOpenaiOrderPresent': local_order is not None,
            'storedOpenaiOrderTargetIncluded': any(key in (local_order or []) for key in local_matches),
            'storedOpenaiOrderCount': len(local_order or []),
            'safeTargetUsageTimestamps': {key: value for key, value in selected_stats.items()
                if key in ('lastUsed', 'lastFailureAt', 'cooldownUntil', 'blockedUntil') and isinstance(value, (int, float))},
            'actualSdkOrderEvaluatedForThisAgent': captured['agent'] == 'main'})
    original_order = binding['originalOrder']; target_position = original_order.index(pid) + 1 if pid in original_order else None
    configured_value_refs = [r for r in refs if not r['metadataDefinition']]
    manifest_profiles = documents['manifest']['profiles']
    report = {'schema': 'heptabao.mac-profile3-captured-current-binding-audit.v1', 'ok': True,
        'scope': 'Only the already captured current configuration, five logical auth stores, actual main SDK order and replacement fixture manifest; no new production-store access, provider call or live-session scan.',
        'inputRoot': str(CAPTURE), 'inputSha256': inputs,
        'productionConfigSha256AtCapture': prepared['productionConfigSha256'],
        'knownTargetIdentitySha256': TARGET, 'targetOrdinal': 3,
        'currentConfigExactIdentityReferences': refs,
        'explicitNonMetadataConfigReferenceCount': len(configured_value_refs),
        'capturedStores': stores,
        'actualMainOriginalSdkOrderOrdinals': [ids.index(key) + 1 for key in original_order],
        'targetInActualMainSdkCandidates': target_position is not None,
        'targetOriginalSdkCandidatePosition': target_position,
        'targetSelectedAsFirstDefaultCandidate': target_position == 1,
        'replacementIsolatedManifestContainsTarget': any(p['profileId'] == pid for p in manifest_profiles),
        'replacementIsolatedManagedOrderContainsTarget': pid in binding['projectedManagedOrder'],
        'replacementTargetExclusionReason': 'Explicit prior HTTP401 invalid_refresh_token; original credentials retained in untouched production stores and private recovery captures.',
        'productionRemoteManifestObserved': False, 'productionGatewayLiveSessionOverridesObserved': False,
        'currentInvocationOfTargetProven': False, 'inactiveHistoricalOnlyProven': target_position is None and not configured_value_refs,
        'needsProviderLoginForHeptaBaoStorageOperations': False,
        'providerRecoveryIsSeparateFromStorageContract': True,
        'noAccountDeletedRenamedOrReplaced': True, 'humanLoginStarted': False,
        'providerRequests': 0, 'productionChanged': False, 'credentialValuesPublished': False, 'accountIdentitiesPublished': False,
        'interpretation': ('The captured production main SDK order still contains profile 3 as a fallback; it is not the first default candidate. '
            'No live-session use or mandatory dedicated consumer is inferred. This is not proof that the account is purely historical. '
            'The new isolated manifest excludes that confirmed-invalid generation while preserving its original identity and recovery material. '
            'Provider recovery or explicit treatment of this stale fallback is separate from HeptaBao KV/AppRole/TLS/renew/revoke functionality.')}
    public = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    sensitive = [value for c in all_profiles.values() for key, value in c.items()
                 if isinstance(value, str) and len(value) >= 8 and key not in ('type', 'provider', 'chatgptPlanType')]
    need(all(v.encode() not in public for v in sensitive), 'public_report_no_identity_or_credentials')
    put(OUT / 'result.public.json', report)
    print(json.dumps({'ok': True, 'receipt': str(OUT / 'result.public.json'),
        'sha256': sha((OUT / 'result.public.json').read_bytes()),
        'mainCandidatePosition': target_position, 'explicitNonMetadataReferences': len(configured_value_refs)}))


if __name__ == '__main__': main()
