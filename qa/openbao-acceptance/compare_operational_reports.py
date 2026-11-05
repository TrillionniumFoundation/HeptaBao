#!/usr/bin/env python3
"""Compare the fixed bounded operational-process profile, not all OpenBao surfaces.

Reports are implementation-controlled inputs, not independent attestations.
Source, binary and Oracle identity must match the frozen run. Empty, duplicate,
failed, dirty-source, non-boolean and re-scoped observations cannot pass.
"""
import json
import re
from bao_http import SafeArgumentParser, private_json, private_write
from official_openbao_launcher import BINARY_SHA256, ARTIFACT_SHA256, SUPPORTED_VERSIONS, VERSION, pinned_artifact

CANDIDATE_ONLY = {'server.init','server.unseal','idle.tune','idle.issue','idle.wrap',
                  'idle.no_request_commits_observed','idle.expired_lease_missing','idle.expired_wrapping_denied'}
EXPECTED_COMMON = {'setup.kv_mount','setup.kv_write','setup.policy','setup.auth_mount','setup.role',
    'agent.real_login_ready','agent.private_sink','agent.checkpoint_contains_no_secrets','proxy.listener_ready',
    'proxy.real_secret_read','proxy.rejects_non_allowlisted_route','proxy.rejects_supplied_root_token',
    'proxy.rejects_namespace_override','proxy.rejects_wrapping_injection','policy.revoke',
    'proxy.uses_live_server_authorization','policy.restore','agent.second_writer_rejected',
    'agent.second_writer_no_secret_output','agent.real_renewal','agent.renewal_keeps_same_token',
    'agent.graceful_stop_invalidates_sink','proxy.denies_stopped_agent','agent.real_post_login_crash',
    'agent.crash_preserves_pending','agent.pending_restart_blocked','agent.crash_has_no_published_token',
    'agent.crash_diagnostics_redacted','ssh.mount','ssh.role','helper.real_valid_binding',
    'helper.replay_denied','helper.wrong_login_user_denied','helper.denial_before_consumption',
    'helper.wrong_host_denied','helper.wrong_host_no_blind_retry','helper.wrong_role_denied',
    'helper.invalid_trust_denied','helper.invalid_trust_did_not_consume',
    'proxy.clean_shutdown_removes_only_owned_socket','processes.no_secret_logs'} | {
        f'helper.diagnostics_{i}' for i in range(1,10)}


# Historical v1 retains its exact denominator and original 2.6.2 identity.
ROLE_ID_ONLY_CASES = {
    'role_only.checkpoint_contains_no_secrets',
    'role_only.confirmed_denial_reauthenticates',
    'role_only.crash_diagnostics_redacted',
    'role_only.crash_has_no_published_token',
    'role_only.crash_issued_exactly_one_token',
    'role_only.crash_preserves_pending',
    'role_only.denial_diagnostics_redacted',
    'role_only.denial_has_no_published_token',
    'role_only.denial_preserves_pending',
    'role_only.denied_restart_blocked',
    'role_only.denied_restart_does_not_issue_token',
    'role_only.graceful_stop_invalidates_sink',
    'role_only.pending_restart_blocked',
    'role_only.pending_restart_does_not_issue_token',
    'role_only.private_sink',
    'role_only.real_login_ready',
    'role_only.real_post_login_crash',
    'role_only.real_renewal',
    'role_only.real_secret_read',
    'role_only.reauthenticated_secret_read',
    'role_only.reauthentication_publishes_new_token',
    'role_only.renewal_keeps_same_token',
    'role_only.revoke',
    'role_only.revoked_bearer_denied',
    'role_only.secret_required_denied',
    'role_only.setup',
}
EXPECTED_COMMON_V2 = EXPECTED_COMMON | ROLE_ID_ONLY_CASES


def compare(candidate, oracle):
    if not isinstance(candidate,dict) or not isinstance(oracle,dict):raise ValueError('report_object_required')
    schema = candidate.get('schema')
    if schema != oracle.get('schema') or schema not in ('heptabao.operational-process-evidence.v1', 'heptabao.operational-process-evidence.v2'):
        raise ValueError('report_schema_mismatch')
    version = VERSION if schema.endswith('.v1') else candidate.get('oracle_version')
    if (version not in SUPPORTED_VERSIONS or (schema.endswith('.v2') and oracle.get('oracle_version') != version)
            or (schema.endswith('.v1') and any(r.get('oracle_version', VERSION) != VERSION for r in (candidate, oracle)))):
        raise ValueError('oracle_version_mismatch')
    expected_common = EXPECTED_COMMON if schema.endswith('.v1') else EXPECTED_COMMON_V2
    for report,target in [(candidate,'heptabao-candidate'),(oracle,'official-openbao-'+version)]:
        if (report.get('schema')!=schema or report.get('target')!=target
                or report.get('status')!='passed' or report.get('source_dirty') is not False
                or report.get('synthetic_only') is not True or report.get('independent_qualification') is not False
                or report.get('production_authority') is not False
                or report.get('full_agent_proxy_compatibility') is not False
                or report.get('actual_pam_or_sshd_login') is not False):raise ValueError('invalid_report_scope')
        if not re.fullmatch(r'[0-9a-f]{40}', report.get('source_commit','')) or not re.fullmatch(r'[0-9a-f]{40}',report.get('source_tree','')):
            raise ValueError('source_identity_required')
        for key in ('candidate_binary_sha256', 'runner_sha256'):
            if not re.fullmatch(r'[0-9a-f]{64}', report.get(key, '')):
                raise ValueError('invalid_artifact_digest')
        if report.get('client_distribution') not in ('source', 'installed-wheel'):
            raise ValueError('unknown_client_distribution')
    for key in ('source_commit','source_tree','candidate_binary_sha256','runner_sha256','client_distribution'):
        if not candidate.get(key) or candidate.get(key)!=oracle.get(key):raise ValueError('candidate_pair_mismatch')
    identity=oracle.get('oracle_identity',{})
    pins = pinned_artifact(version=version)
    if (identity.get('version')!=version or identity.get('binary_sha256')!=pins['binary_sha256']
            or identity.get('artifact_sha256')!=pins['artifact_sha256'] or identity.get('tls_verified') is not True):
        raise ValueError('oracle_identity_mismatch')
    def rows(report,expected):
        entries=report.get('cases')
        if not isinstance(entries,list) or len(entries)!=len(expected):raise ValueError('case_denominator_changed')
        names=[]
        for row in entries:
            if not isinstance(row,dict) or row.get('passed') is not True:raise ValueError('case_not_true')
            names.append(row.get('case'))
        if set(names)!=expected or len(names)!=len(set(names)):raise ValueError('case_inventory_changed')
    rows(candidate,expected_common|CANDIDATE_ONLY);rows(oracle,expected_common)
    return {'schema':'heptabao.operational-profile-comparison.v1','matched':True,
            'oracle_version':version,'profile_schema':schema,
            'common_observations':len(expected_common),'candidate_only_observations':len(CANDIDATE_ONLY),
            'source_commit':candidate['source_commit'],'source_tree':candidate['source_tree'],
            'candidate_binary_sha256':candidate['candidate_binary_sha256'],
            'scope':'selected_AppRole_agent_Unix_proxy_SSH_helper_workflows_only',
            'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}


def main():
    parser=SafeArgumentParser(description=__doc__);parser.add_argument('--candidate',required=True)
    parser.add_argument('--oracle',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        result=compare(private_json(args.candidate),private_json(args.oracle))
        private_write(args.output,result,replace=False)
        print(json.dumps({'matched':True,'common_observations':result['common_observations']}));return 0
    except (ValueError,TypeError,KeyError):
        print(json.dumps({'matched':False,'reason':'invalid_or_incomplete_comparison'}));return 1
if __name__=='__main__':raise SystemExit(main())
