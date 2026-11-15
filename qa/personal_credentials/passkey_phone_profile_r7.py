#!/usr/bin/env python3
"""Frozen r7 storage-fix phone acceptance declaration; no execution or qualification implied."""
import json

PROFILE = {'schema': 1,
 'profile': 'android16-native-passkey-r7-synthetic',
 'runtime_source_bundle_sha256': 'e2e79c7e35a507c11ba2a52a67c5a4882528d2447fa1c489977a64ad992f91b6',
 'build_receipt_sha256': 'e12bd68de3c606e03ce22a7a688ebb90c7b6ec4a951d15e5be233339e698042b',
 'host_result_sha256': '173a3777dd928acb8b3a18f1e7bb81e995c74fd501c48cd35cdb702a2ade7c57',
 'dex_line_check_sha256': '1aa1b59249be927fa41c68d21015b9503903485d74fa1fd52f0497ba41479abc',
 'run_paths': {'operator_host': 'pocket4',
               'operator_base': '/home/alex/HeptaBaoPasskey-20261106-r7',
               'driver_root': '/home/alex/HeptaBaoPasskey-20261106-r7/live-r7',
               'artifacts': '/home/alex/HeptaBaoPasskey-20261106-r7/artifacts',
               'rp_root': '/home/alex/HeptaBaoPasskey-20261106-r7/rp-r7',
               'device_documents': '/sdcard/Download/HeptaBao-Passkey-QA-20261106-r7',
               'build_source': '/Users/qianqi/HeptaBaoPasskey-20261106-r1/snapshot-r7-final/source',
               'build_output': '/Users/qianqi/HeptaBaoPasskey-20261106-r1/build-r7'},
 'device_sha256': '41ad305f8562a6c47710afe71fabf30cb8692a71d3de1a47ca9949b669bcc6c1',
 'android_api': 36,
 'rp_id': 'passkeys.heptabao.test',
 'fixture_certificate_sha256': 'cb684e07720b0233e9aa87bc74e87cf40956476770dabc2a426bee30dcba6135',
 'rp_source_sha256': '386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63',
 'credential_entry': 'synthetic_only_adb_input_text_argv',
 'production_qualified': False,
 'general_web_rp_support': False,
 'physical_cross_device_passkey_migration': False,
 'case_result_states': ['passed', 'failed', 'blocked', 'missing'],
 'cases': [{'id': 'M01',
            'group': 'main',
            'behavior': 'ordinary SAF imports the fixed encrypted seed into a fresh app-private store after '
                        'password approval',
            'evidence': ['SAF actual UI', 'fixed seed digest', 'provider import result']},
           {'id': 'M02',
            'group': 'main',
            'behavior': 'real platform CredentialManager create completes after provider selection and fresh '
                        'password approval; independent RP verifies registration',
            'evidence': ['platform selector',
                         'OperationActivity approval',
                         'RP registration record and public-key digest']},
           {'id': 'M03',
            'group': 'main',
            'behavior': 'real CredentialManager get returns a signature accepted by independent RP with '
                        'exact challenge, native origin, RP ID, UP, UV and increasing counter',
            'evidence': ['actual fixture authentication result',
                         'RP verification event and persisted counter']},
           {'id': 'M04',
            'group': 'main',
            'behavior': 'ordinary SAF exports a latest confirmed encrypted backup and provider reports '
                        'write/read-back verification',
            'evidence': ['actual document selection',
                         'provider export result',
                         'exported ciphertext digest']},
           {'id': 'M05',
            'group': 'main',
            'behavior': 'after a verified latest external backup and frozen reset intent, the exact '
                        'initially-absent owned provider is cleared through Android pm clear; its old '
                        'process is gone and an ordinary new process restores through SAF into the reset '
                        'app-private store',
            'evidence': ['initial absence and exact installed provider APK digest',
                         'actual latest external backup digest plus unchanged RP public-key/counter snapshot',
                         'nonempty old provider process identity captured before reset',
                         'durable case-specific reset intent written before effect',
                         'exact pm clear exit zero and Success acknowledgement',
                         'APK and all three settings unchanged across reset',
                         'old process gone and different process after ordinary launch',
                         'ordinary SAF restore result; no claimed private-directory inode readback']},
           {'id': 'M06',
            'group': 'main',
            'behavior': 'real get after fresh-store restore verifies against the original RP public key with '
                        'a strictly newer counter and backup-state flag',
            'evidence': ['RP persisted key before/after', 'verified counter and flags']},
           {'id': 'G01',
            'group': 'guard',
            'behavior': 'wrong password during import does not activate the staged vault',
            'evidence': ['provider rejection', 'active-store state unchanged']},
           {'id': 'G02',
            'group': 'guard',
            'behavior': 'wrong password for a selected CredentialManager operation does not deliver a '
                        'credential',
            'evidence': ['provider rejection', 'RP successful-event/counter state unchanged']},
           {'id': 'G03',
            'group': 'guard',
            'behavior': 'locked provider refuses CredentialManager credential delivery',
            'evidence': ['explicit lock', 'platform result', 'RP state unchanged']},
           {'id': 'G04',
            'group': 'guard',
            'behavior': 'wrong RP target is refused',
            'evidence': ['fixture wrong-target action', 'platform/provider rejection', 'RP state unchanged']},
           {'id': 'G05',
            'group': 'guard',
            'behavior': 'same package signed by the wrong certificate is refused',
            'evidence': ['installed artifact digest', 'platform/provider rejection', 'RP state unchanged']},
           {'id': 'G06',
            'group': 'guard',
            'behavior': 'wrong package signed by the pinned certificate is refused',
            'evidence': ['decoy artifact digest', 'platform/provider rejection', 'RP state unchanged']},
           {'id': 'G07',
            'group': 'guard',
            'behavior': 'cancel/back before approval yields no RP-accepted credential',
            'evidence': ['ordinary task transition without task clearing',
                         'platform result',
                         'RP state unchanged']},
           {'id': 'G08',
            'group': 'guard',
            'behavior': 'after selecting a backup target, opening a new picker and cancelling makes Write '
                        'refuse the old target',
            'evidence': ['picker cancellation', 'provider refusal', 'old target digest unchanged']},
           {'id': 'G09',
            'group': 'guard',
            'behavior': 'after staging A, cancelling or failing a new selection makes Import refuse reuse of '
                        'A',
            'evidence': ['new selection cancellation/failure',
                         'provider refusal',
                         'active-store state unchanged']},
           {'id': 'G10',
            'group': 'guard',
            'behavior': 'wrong password for export is refused before truncating or writing the selected '
                        'destination',
            'evidence': ['provider rejection', 'destination content digest unchanged']},
           {'id': 'G11',
            'group': 'guard',
            'behavior': 'restoring a stale backup whose counter was already used does not bypass the RP '
                        'strict counter rule',
            'evidence': ['stale backup digest and counter history',
                         'RP counter_rollback_or_replay rejection']},
           {'id': 'M07',
            'group': 'cleanup',
            'behavior': "settings are compare-restored; only this run's package hashes, reverse mapping and "
                        'tracked synthetic documents are removed; unknown changes are preserved and reported',
            'evidence': ['pre-action private journal',
                         'final settings comparison',
                         'positive package absence queries',
                         'reverse/document cleanup receipt',
                         'full settings tuple recognized by the predeclared joint-state restore plan; '
                         'unknown tuple preserved as a whole']}],
 'report_rules': ['Keep every case; report expected, executed, passed, failed, blocked and missing '
                  'separately.',
                  'A successful ADB phase, installation, host test or signature-only unit test does not pass '
                  'a CredentialManager behavior.',
                  'Retain initial failures and later candidate attempts; do not pool runtime hashes into one '
                  'qualification.',
                  'Fresh-store restore on this one phone is not physical cross-device migration or generic '
                  'passkey portability.',
                  'Latest-backup recovery is supported only when its counter has not been superseded at the '
                  'strict RP.',
                  'Do not pool r4, the failed first r5 build, r5b, r6 or different r7 artifacts into one result.',
                  'Preserve setup failures separately from all eighteen case states; phase success does not '
                  'pass a case.',
                  'M07 passes only after settings, exact package absence, owned reverse mapping and tracked '
                  'synthetic documents are all checked.'],
 'provider_apk_sha256': 'b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459',
 'fixture_apk_sha256': '88a5731f2b24ca6a07a8748422e344443cab7c43db3c96e4907aa3137ff8de8f',
 'wrong_certificate_fixture_apk_sha256': '2c1de4d6b9eaa1685e9aee35386d16c51f5dd0cd6971dd5385253b90387b9e1e',
 'wrong_certificate_sha256': '50e5b45daa0f5d87fbe796e9dc9bd1b5f67d2ed686e308b283a7e9be2830124d',
 'wrong_package_fixture_apk_sha256': '2fe1613b38ab332d8020c235cba657256af155495b7a368046f0b32f00cda8fb',
 'seed_ciphertext_sha256': 'bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917',
 'seed_producer_binary_sha256': 'b0cccc3c204d6be5e2e20ee5830e34cb1242d3ac03ea42cd3b7e26a3ea416358',
 'seed_producer_source_commit': 'a1b6ff4506f52082a0893b7167fafb4ff95610be',
 'seed_producer_build_receipt_sha256': 'fa166952072d99490164cb355e1b9784e14791faf39cb48a2f226aed627ccdd4',
 'phone_driver_sha256': 'e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd',
 'phone_driver_guard_sha256': 'b4639c6e70301628f3412a8e8870caf4b305c3d75b7a34bec7467926cf680814',
 'inherited_case_definition_source_sha256': '6a26dbf2c4394becba2eb0c21192853afb5f176ede68f2e4dbf9d00ed9b1a7b0',
 'synthetic_only': True,
 'expected_case_count': 18,
 'hardware_attestation_qualified': False,
 'settings_admission': {'driver_policy': 'select_primary_with_verified_system_bridge_from_empty',
                        'credential_service_before': 'empty',
                        'credential_service_primary_before': 'empty',
                        'autofill_before': 'captured actual original value in private journal',
                        'provider_components': ['org.heptabao.passkey.preview/.ProviderService',
                                                'org.heptabao.passkey.preview/org.heptabao.passkey.preview.ProviderService'],
                        'system_bridge_component': 'com.android.credentialmanager/com.android.credentialmanager.autofill.CredentialAutofillService',
                        'system_bridge_apk_path': '/system/priv-app/CredentialManager/CredentialManager.apk',
                        'system_bridge_apk_sha256': '05d91aee432f7e1db6bcaaec3721f94752e40a4895519c17cc81c51b850f75a9',
                        'required_evidence': ['SYSTEM package flag',
                                              'actual service query',
                                              'APK digest',
                                              'durable exact joint after-state intent before ordinary '
                                              'settings UI selection'],
                        'restoration': 'compare the complete three-value tuple against the durable original '
                                       'and allowed recovery chain; preserve unknown changes before package '
                                       'or reverse cleanup'},
 'reset_admission': {'helper_repository_path': 'qa/personal_credentials/passkey_reset_provider_r7.py',
                     'helper_binding': 'freeze and independently review a separate helper SHA and '
                                       'case-specific checkpoint before any reset; the author cannot '
                                       'self-grant that review',
                     'destructive_scope': 'only org.heptabao.passkey.preview, initially absent and currently '
                                          'matching this profile APK',
                     'latest_recovery_backup_required': True,
                     'rp_public_key_and_counter_snapshot_required': True,
                     'nonempty_old_provider_process_required': True,
                     'durable_intent_before_pm_clear': True,
                     'unknown_outcome_must_not_be_redispatched': True,
                     'applies_to': ['M05', 'G11 and every additional reset'],
                     'stale_input_is_not_the_latest_recovery_backup': True,
                     'execution_has_occurred': False},
 'causal_observation_rules': ['G11 stale ciphertext must come from an actual SAF export in this run. Advance counters only through ordinary CredentialManager operations and independent RP verification; never edit a phone or RP counter to manufacture rejection.',
                            'Each negative case needs fresh provider eligibility and a current real '
                              'CredentialManager request or documented platform refusal; unchanged RP state '
                              'alone is insufficient.',
                              'Record eligibility/ticket freshness and operation timing; do not count '
                              'natural five-minute index or three-minute ticket expiry as '
                              'wrong-target/cancel proof.',
                              'Use actual RP option-request progression to demonstrate a fresh request where '
                              'the fixture obtains options, and compare accepted events/key/counter '
                              'separately from option allocation.',
                              'G01 and G10 require wrong_key_or_corrupt from the attempted wrong-password '
                              'operation, not a missing-selection refusal.',
                              'G08 requires choose_backup_destination_first after cancelling a new picker '
                              'and an unchanged original destination digest.',
                              'G09 requires choose_encrypted_vault_first after cancelling/failing a new '
                              'picker, with no reactivation of the old staged input.',
                              'G11 requires a new independent RP verification_rejected event with '
                              'counter_rollback_or_replay, not merely a generic fixture error.',
                              'A fresh native store on this same physical phone is an app-data reset/restore '
                              'observation; do not claim a second physical passkey device or a measured '
                              'private-directory inode.',
                              'A separately reviewed reset helper may be bound before its first case while '
                              'earlier non-destructive cases run; pending helper work cannot pass or erase a '
                              'case.']}

if __name__ == "__main__":
    print(json.dumps(PROFILE, sort_keys=True, indent=2))
