#!/usr/bin/env python3
"""Pure classification of fixed candidate files and selected owner values.

This module performs no I/O. Its caller must bind actual process identity,
selector bytes, file generations and current main3 ownership. Results describe
the supplied candidate files, never a running process's cached authentication.
It deliberately cannot grant maintenance or provider dispatch authority.

Source contracts: official openai/codex rust-v0.133.0. Config key is
cli_auth_credentials_store (config_toml.rs a4d384b5f39e3d56d252afa6dd0437c02469aab8).
File/keyring/auto/ephemeral and the File default are in types.rs c7d0a5876b7daf81d50b7cfa6a1cf8f601155428.
AuthDotJson.tokens.refresh_token is from storage.rs 3a1c8ae6aa530e287e479837c7dec47c96ead15c
and token_data.rs 2952ecb2a7cb50fb7c1b1d462eb6f2f16231baf3.
AuthManager a2e4e8e0d8669dcb47efd70908109dbac04fe33a gives ephemeral
auth precedence and can refresh from cached auth; file inequality is no proof
that the running process does not hold a shared refresh object.
"""
from __future__ import annotations

import hmac
import json
from pathlib import PurePosixPath
import tomllib

HOME = PurePosixPath('/Users/qianqi')
CANDIDATE = HOME / '.codex'
MAXIMUM = 1048576
MODES = frozenset(('file', 'keyring', 'auto', 'ephemeral'))


class CandidateRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise CandidateRefused(code)


def strict_json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAXIMUM, 'candidate_bounded_json')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'candidate_duplicate_json_key')
            result[key] = value
        return result
    def constant(_):
        raise CandidateRefused('candidate_nonfinite_json')
    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                            parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise CandidateRefused('candidate_invalid_complete_json') from None
    need(type(result) is dict, 'candidate_json_object')
    return result


def fixed_candidate_paths(selection):
    """No extra home, profile, or higher-layer configuration read is admitted."""
    need(type(selection) is dict and set(selection) == {'private', 'public'},
         'candidate_original_selector_shape')
    private, public = selection['private'], selection['public']
    need(type(private) is dict and type(public) is dict
         and public.get('configurationKeyBoundToOfficialV0133Source') is True
         and public.get('environmentSectionState') == 'entries_returned',
         'candidate_fresh_corrected_selector_required')
    selectors = private.get('selectors')
    need(type(selectors) is dict and selectors.get('HOME') == str(HOME)
         and 'CODEX_HOME' not in selectors
         and 'OPENCLAW_STATE_DIR' not in selectors and 'OPENCLAW_CONFIG_PATH' not in selectors,
         'candidate_only_observed_default_home_scope')
    need(private.get('candidateHome') == {'kind': 'default_candidate_from_observed_home',
                                         'path': str(CANDIDATE)},
         'candidate_exact_default_home_path')
    need(private.get('profileV2Selector') is None
         and public.get('profileV2SelectionPresent') is False,
         'candidate_profile_v2_requires_separate_exact_path_binding')
    return (str(CANDIDATE / 'config.toml'), str(CANDIDATE / 'auth.json'))


def configuration_view(raw, selection):
    fixed_candidate_paths(selection)
    need(raw is None or type(raw) is bytes and len(raw) <= MAXIMUM,
         'candidate_bounded_user_configuration')
    try:
        doc = {} if raw is None else tomllib.loads(raw.decode('utf-8', 'strict'))
    except (UnicodeError, ValueError, RecursionError):
        raise CandidateRefused('candidate_invalid_user_toml') from None
    need(type(doc) is dict, 'candidate_user_toml_table')
    value = doc.get('cli_auth_credentials_store')
    need(value is None or type(value) is str and value in MODES,
         'candidate_store_mode_exact_source_enum')
    override = selection['private'].get('storageModeOverride')
    need(override is None or type(override) is str and override in MODES,
         'candidate_cli_store_mode_exact_source_enum')
    unknown = selection['public'].get('otherConfigurationOverrides')
    need(type(unknown) is int and 0 <= unknown <= 512,
         'candidate_other_overrides_bounded')
    profile = selection['private'].get('profileSelector')
    if profile is not None:
        need(type(profile) is str and 0 < len(profile) <= 256,
             'candidate_bounded_legacy_profile')
    # The legacy profile schema has no auth-store key. Do not silently erase
    # an unexpected same-named nested declaration in an actual input.
    profiles = doc.get('profiles', {})
    need(type(profiles) is dict, 'candidate_profiles_table')
    chosen = profiles.get(profile, {}) if profile is not None else {}
    need(type(chosen) is dict, 'candidate_selected_profile_table')
    nested = 'cli_auth_credentials_store' in chosen
    wrong_key = 'cli_auth_credentials_store_mode' in doc
    return {'userConfigPresent': raw is not None,
        'userConfigStoreMode': value,
        'cliStoreModeOverride': override,
        'candidateModeIgnoringUnobservedLayers': override or value or 'file',
        'candidateModeSource': 'observed-cli-override' if override is not None else
                              'observed-user-declaration' if value is not None else 'source-default',
        'otherConfigurationOverrideCount': unknown,
        'legacyProfileSelected': profile is not None,
        'unrecognizedNestedAuthStoreDeclaration': nested,
        'unrecognizedInternalFieldSpellingPresent': wrong_key,
        'systemManagedProjectAndRuntimeLayersBound': False,
        'installedPackageVersionProvesLoadedNativeImage': False,
        'effectiveBackendQualified': False,
        'ephemeralPrecedenceAndCachedAuthExcluded': False}


def selected_values(owner_entries):
    need(type(owner_entries) is list and len(owner_entries) == 3,
         'candidate_exact_current_three_selected_owners')
    identifiers, credentials = [], []
    for row in owner_entries:
        need(type(row) is dict and type(row.get('profileId')) is str
             and 0 < len(row['profileId']) <= 240 and type(row.get('credential')) is dict,
             'candidate_actual_selected_owner_shape')
        credential = row['credential']
        value = credential.get('refresh')
        need(credential.get('provider') == 'openai' and credential.get('type') == 'oauth'
             and type(value) is str and 0 < len(value.encode('utf-8')) <= 131072,
             'candidate_selected_oauth_refresh_present')
        identifiers.append(row['profileId']); credentials.append(credential)
    need(len(set(identifiers)) == 3
         and len({row['refresh'] for row in credentials}) == 3,
         'candidate_ambiguous_selected_owner_or_refresh_object')
    return credentials


def compare_candidate_auth(raw, owner_entries):
    """Byte equality stays private; public output contains counts/enums only."""
    credentials = selected_values(owner_entries)
    if raw is None:
        return {'private': {'matchedOwnerOrdinals': [], 'candidateAuthPresent': False},
            'public': {'candidateAuthPresent': False, 'storedRefreshFieldPresent': False,
                'candidateFileRelation': 'candidate-file-absent', 'matchingSelectedOwnerCount': 0,
                'allSelectedOwnerValuesCompared': False, 'runningCachedCredentialRelation': 'unknown',
                'effectiveBackendQualified': False, 'productionRefreshAdmission': False}}
    doc = strict_json(raw)
    tokens = doc.get('tokens')
    need(tokens is None or type(tokens) is dict, 'candidate_tokens_object_or_absence')
    value = tokens.get('refresh_token') if tokens is not None else None
    need(value is None or type(value) is str and len(value.encode('utf-8')) <= 131072,
         'candidate_bounded_refresh_field')
    present = bool(value)
    matches = []
    if present:
        candidate = value.encode('utf-8')
        for ordinal, credential in enumerate(credentials):
            if hmac.compare_digest(candidate, credential['refresh'].encode('utf-8')):
                matches.append(ordinal)
    account = tokens.get('account_id') if tokens is not None else None
    need(account is None or type(account) is str and len(account.encode('utf-8')) <= 4096,
         'candidate_bounded_account_field')
    account_matches, account_compared = [], []
    if type(account) is str and account:
        for ordinal, credential in enumerate(credentials):
            other = credential.get('accountId')
            if type(other) is str and other:
                need(len(other.encode('utf-8')) <= 4096, 'candidate_bounded_selected_account_field')
                account_compared.append(ordinal)
                if hmac.compare_digest(account.encode('utf-8'), other.encode('utf-8')):
                    account_matches.append(ordinal)
    relation = 'shared-candidate-refresh' if matches else \
               'different-candidate-refresh' if present else 'no-stored-refresh-field'
    return {'private': {'candidateAuthPresent': True, 'matchedOwnerOrdinals': matches,
        'accountComparedOrdinals': account_compared, 'accountMatchedOrdinals': account_matches},
        'public': {'candidateAuthPresent': True, 'storedRefreshFieldPresent': present,
            'candidateFileRelation': relation, 'matchingSelectedOwnerCount': len(matches),
            'allSelectedOwnerValuesCompared': present,
            'accountFieldComparedCount': len(account_compared), 'accountFieldEqualCount': len(account_matches),
            'runningCachedCredentialRelation': 'unknown', 'effectiveBackendQualified': False,
            'credentialValueOrDigestPublished': False, 'productionRefreshAdmission': False}}
