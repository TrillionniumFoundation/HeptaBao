#!/usr/bin/env python3
"""Publish only a bounded, closed-vocabulary projection of a private comparison.

No HTTP bodies, headers, paths, endpoints, credentials, arbitrary reason text or
private report are exported. Candidate health version text is deliberately
omitted: candidate identity is its observed binary digest plus the caller-supplied
source checkout binding, not proof that those bytes were built from that source.
The official oracle version is a finite verified release with exact artifact pins.
This is candidate-controlled diagnostic evidence, never compatibility admission.
Missing/rejected reports fail the diagnostic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_REPORT_BYTES = 256 * 1024
CASES = {'core': ['unknown_route_denied'],
 'kv': ['mount',
        'write_v1',
        'read_v1',
        'write_v2',
        'read_old_version',
        'cas_rejected',
        'cas_no_effect',
        'list',
        'soft_delete',
        'deleted_read',
        'deleted_metadata',
        'undelete',
        'restored_read',
        'destroy_v1',
        'destroyed_read',
        'destroyed_metadata',
        'metadata_write',
        'metadata_read'],
 'token': ['policy',
           'create',
           'read_allowed',
           'write_denied',
           'denial_no_effect',
           'revoke',
           'revoked_denied',
           'invalid_denied',
           'create_expiring',
           'expired_denied'],
 'transit': ['mount',
             'create_key',
             'read_key',
             'encrypt_v1',
             'decrypt_v1',
             'rotate',
             'read_rotated_key',
             'encrypt_v2',
             'decrypt_v2',
             'decrypt_old_after_rotation'],
 'pki': ['mount',
         'root',
         'role',
         'role_read',
         'issue',
         'lease_lookup',
         'lease_expire_issue',
         'lease_expire_lookup',
         'cert_lookup',
         'lease_revoke',
         'revoked_lease_absent',
         'crl_json'],
 'totp': ['roundtrip'],
 'userpass': ['login'],
 'approle': ['login', 'secret_id_replay_denied', 'invalid_secret_id_denied'],
 'edge_tls': ['health'],
 'system': ['init_status'],
 'operations': ['seal_status'],
 'identity': ['entity_create',
              'entity_read',
              'entity_disable',
              'entity_disabled',
              'entity_delete',
              'entity_deleted'],
 'wrapping': ['create', 'unwrap', 'replay_denied']}
SEMANTICS = frozenset(['bounded_ttl',
 'cas_required',
 'certificate',
 'code_generated',
 'crl',
 'current_data_unchanged',
 'custom_metadata',
 'data_unchanged',
 'default_policy',
 'destroyed',
 'disabled',
 'domains',
 'entity_created',
 'error_envelope',
 'errors_present',
 'exact_data',
 'exact_id',
 'exact_key_listing',
 'exact_name',
 'exact_old_data',
 'exact_payload',
 'exact_restored_data',
 'exact_roundtrip',
 'expiration',
 'generate_lease',
 'generation_preserved',
 'initialized',
 'issuing_ca',
 'key_created',
 'key_type',
 'latest_version',
 'lease_duration',
 'lease_id',
 'lease_issued',
 'max_ttl',
 'max_versions',
 'metadata',
 'no_auth',
 'no_root_policy',
 'not_destroyed',
 'old_key_retained',
 'private_key',
 'private_key_type',
 'renewable',
 'requested_policy',
 'response_redacted',
 'role_id_observed',
 'secret_id_observed',
 'serial',
 'subdomains',
 'token_issued',
 'tombstone_present',
 'ttl',
 'ttl_is_bounded',
 'unsealed',
 'validation_true',
 'version_is_one',
 'version_is_two',
 'version_unchanged',
 'versioned_ciphertext',
 'wrapper_token_present'])
REASONS = frozenset(['approle_fixture_role_create_failed',
 'auth_mount_enable_failed',
 'auth_mount_type_mismatch',
 'ca_configuration_invalid',
 'cannot_prove_synthetic_mount_absent',
 'cannot_prove_synthetic_policy_absent',
 'cannot_read_auth_mount_inventory',
 'case_status_or_semantics_mismatch',
 'cluster_identity_missing',
 'endpoint_ca_and_exactly_one_token_source_required',
 'endpoint_not_initialized_unsealed',
 'existing_output_not_private_regular_file',
 'file_requires_owner_only_regular_file',
 'file_size_limit',
 'https_origin_required',
 'identity_entity_id_missing',
 'independent_oracle_identity_file_required',
 'invalid_configuration_or_response',
 'invalid_environment_prefix',
 'invalid_frozen_ca_bytes',
 'invalid_json',
 'invalid_modules_or_token_missing_kv_dependency',
 'invalid_namespace',
 'invalid_request_method',
 'invalid_request_path',
 'invalid_timeout',
 'invalid_token_input',
 'invalid_wrapping_ttl_header',
 'module_not_selected_or_writes_not_authorized',
 'noncanonical_api_path',
 'oracle_identity_receipt_incomplete',
 'oracle_identity_receipt_mismatch',
 'oracle_identity_unsupported_version',
 'output_already_exists',
 'output_directory_requires_owner_only_mode',
 'private_file_open_failed',
 'private_files_require_posix',
 'private_output_publication_failed',
 'private_parent_directory_required',
 'private_text_requires_string',
 'private_text_requires_utf8',
 'redirect_rejected',
 'request_size_limit',
 'response_data_object_required',
 'response_object_required',
 'response_size_limit',
 'same_endpoint_or_cluster_rejected',
 'test_write_opt_in_required',
 'token_cases_require_successful_kv_fixture',
 'transport_read_failed',
 'transport_outcome_unknown',
 'unexpected_response_schema',
 'unsupported_content_type',
 'unsupported_fixture_mount_kind',
 'userpass_fixture_user_create_failed',
 'version_identity_missing',
 'writes_not_authorized'])
CASE_NAMES = frozenset(module + "." + case for module, names in CASES.items() for case in names)
SCHEMA_CASES = frozenset(module + ".response_schema" for module in CASES)
# The producer records this fixture result without selecting it for comparison.
AUXILIARY_CASES = frozenset({"totp.mount"})
TOP_KEYS = frozenset(("schema", "target", "observed_at_unix", "tool_source_sha256",
    "full_openbao_compatibility", "production_qualified", "mode", "status", "cases_match",
    "candidate", "oracle", "candidate_results", "oracle_results", "mismatched_cases",
    "scope", "uncovered", "reason", "execution_binding"))
# These are the already pinned artifacts, not operator-supplied URLs or hashes.
ORACLES = {
    "2.7.0": {( "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667",
                "9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e")},
    "2.6.2": {( "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa",
                "8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00"),
              ( "1b408e01f3565ac0cbcb88d637dca271d0515148fb72efdeff4473a34fa50c4e",
                "1c3f62018046ec72be8720b576a55105b64b4cbd634d98483a93c642e69dc153")},
}


class Rejected(ValueError):
    pass


def require(value):
    if not value:
        raise Rejected()


def keys(value, allowed, required=()):
    require(type(value) is dict and set(value) <= set(allowed) and set(required) <= set(value))


def choice(value, allowed):
    require(type(value) is str and value in allowed)
    return value


def sha(value, size=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None)
    return value


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def observe(binary, source):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    return {
        "candidate_binary_sha256": digest(binary),
        "candidate_source_sha": sha(git("rev-parse", "HEAD"), 40),
        "candidate_source_tree": sha(git("rev-parse", "HEAD^{tree}"), 40),
        "candidate_source_has_uncommitted_changes": bool(git("status", "--porcelain")),
        "candidate_source_binding_basis": "operator_supplied_build_source_checkout",
        "runner_source_sha256": digest(source / "qa/openbao-acceptance/run_official_comparison.py"),
        "diagnostic_source_sha256": digest(__file__),
        "launcher_source_sha256": digest(source / "qa/openbao-acceptance/official_openbao_launcher.py"),
    }


def private_parent(path):
    parent = path.absolute().parent
    info = parent.lstat()
    require(parent.resolve() == parent and stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_report(path):
    private_parent(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= MAX_REPORT_BYTES)
        raw = handle.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES)
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _value: require(False))


def write_report(path, value):
    private_parent(path)
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")
    require(len(raw) <= MAX_REPORT_BYTES)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as handle:
        handle.write(raw)


def case_projection(value, case_name=None):
    keys(value, {"result", "reason", "http_status", "expected_http_status", "semantics", "method", "path_template"}, {"result"})
    result = {"result": choice(value["result"], {"passed", "failed", "not_run"})}
    if "reason" in value:
        result["reason"] = choice(value["reason"], REASONS)
    if "http_status" in value:
        status = value["http_status"]
        require(status is None or (type(status) is int and 100 <= status <= 599)
                or (type(status) is str and status in {"rejected_after_ttl", "rejected_400_or_404"}))
        result["http_status"] = status
    if "expected_http_status" in value:
        expected = value["expected_http_status"]
        require(type(expected) is list and 1 <= len(expected) <= 5
                and all(type(x) is int and 100 <= x <= 599 for x in expected))
        result["expected_http_status"] = expected
    if "semantics" in value:
        keys(value["semantics"], SEMANTICS)
        require(all(type(x) is bool for x in value["semantics"].values()))
        result["semantics"] = dict(value["semantics"])
    if "method" in value:
        if value["method"] == "MULTI":
            # This exact producer case aggregates POST/GET/POST requests; MULTI
            # is a fixed aggregation marker, never a single HTTP method.
            require(type(value["method"]) is str and case_name == "totp.roundtrip"
                    and result["result"] in {"passed", "failed"}
                    and type(value.get("http_status")) is int
                    and value.get("expected_http_status") == [200]
                    and type(value.get("semantics")) is dict
                    and set(value["semantics"]) == {"key_created", "code_generated", "validation_true"})
            result.update(method="MULTI", method_kind="aggregate")
        else:
            result["method"] = choice(value["method"], {"GET", "POST", "DELETE", "LIST", "HEAD", "PUT", "PATCH"})
    # Never export even a supposedly normalized request path.
    return result


def side_projection(value):
    keys(value, {"cases", "cleanup"}, {"cases", "cleanup"})
    keys(value["cases"], CASE_NAMES | SCHEMA_CASES | AUXILIARY_CASES)
    cleanup = value["cleanup"]
    keys(cleanup, {"result", "failure_count", "scope", "run_id", "reason"}, {"result"})
    safe_cleanup = {"result": choice(cleanup["result"], {"passed", "failed", "not_run"})}
    if "failure_count" in cleanup:
        count = cleanup["failure_count"]
        require(type(count) is int and 0 <= count <= 1000)
        safe_cleanup["failure_count"] = count
    if "reason" in cleanup:
        safe_cleanup["reason"] = choice(cleanup["reason"], REASONS)
    return {"cases": {name: case_projection(case, case_name=name) for name, case in value["cases"].items()},
            "cleanup": safe_cleanup}


def project(report, observed, version):
    keys(report, TOP_KEYS, {"schema", "target", "mode", "status", "cases_match", "execution_binding",
                           "full_openbao_compatibility", "production_qualified"})
    require(report["schema"] == "heptabao.live-acceptance.v1" and report["target"] == "OpenBao " + version
            and report["mode"] == "differential" and report["full_openbao_compatibility"] is False
            and report["production_qualified"] is False and type(report["cases_match"]) is bool)
    bound = report["execution_binding"]
    bound_names = {"candidate_binary_sha256", "candidate_source_sha", "candidate_source_has_uncommitted_changes",
                   "candidate_source_binding_basis", "runner_source_sha256"}
    keys(bound, bound_names | {"build_log_sha256", "official_oracle"}, bound_names | {"official_oracle"})
    require(all(type(bound[name]) is type(observed[name]) and bound[name] == observed[name] for name in bound_names))
    oracle = bound["official_oracle"]
    keys(oracle, {"product", "version", "artifact_sha256", "binary_sha256", "provenance_url", "endpoint",
                  "cluster_id", "archive_member_matches_executable", "server_mode", "storage", "tls_verified",
                  "synthetic_only", "launcher_source_sha256"},
                 {"product", "version", "artifact_sha256", "binary_sha256", "server_mode", "storage",
                  "archive_member_matches_executable", "tls_verified", "synthetic_only", "launcher_source_sha256"})
    require(oracle["product"] == "OpenBao" and oracle["version"] == version
            and (sha(oracle["artifact_sha256"]), sha(oracle["binary_sha256"])) in ORACLES[version]
            and oracle["launcher_source_sha256"] == observed["launcher_source_sha256"]
            and oracle["server_mode"] == "server_not_dev"
            and oracle["storage"] == ("pebbledb" if version == "2.7.0" else "file")
            and all(oracle[name] is True for name in ("archive_member_matches_executable", "tls_verified", "synthetic_only")))
    for name, allowed in (("candidate", {"endpoint", "namespace_digest", "version", "cluster_id_digest"}),
                          ("oracle", {"product", "version", "artifact_sha256", "basis", "independent_binary_attestation", "endpoint", "cluster_id_digest"})):
        if name in report:
            keys(report[name], allowed)
    scope = report.get("scope", [])
    require(type(scope) is list and len(scope) <= len(CASES)
            and all(type(x) is str and x in CASES for x in scope) and len(set(scope)) == len(scope))
    mismatches = report.get("mismatched_cases", [])
    require(type(mismatches) is list and len(mismatches) <= len(CASE_NAMES)
            and all(type(x) is str and x in CASE_NAMES for x in mismatches)
            and len(set(mismatches)) == len(mismatches))
    result = {"comparison_status": choice(report["status"], {"failed", "not_run", "passed_scoped_cases"}),
              "cases_match": report["cases_match"], "scope": sorted(scope),
              "reported_mismatched_cases": sorted(mismatches),
              "official_oracle": {name: oracle[name] for name in ("product", "version", "artifact_sha256", "binary_sha256",
                 "server_mode", "storage", "archive_member_matches_executable", "tls_verified", "synthetic_only", "launcher_source_sha256")}}
    if "reason" in report:
        result["reason"] = choice(report["reason"], REASONS)
    for side in ("candidate_results", "oracle_results"):
        if side in report:
            result[side] = side_projection(report[side])
    return result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "comparison diagnostic: invalid arguments\n")


def main(argv=None):
    parser = Parser(description=__doc__)
    for name in ("report", "output", "binary", "candidate-source"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--oracle-version", required=True, choices=tuple(ORACLES))
    parser.add_argument("--process-exit", required=True, type=int)
    args = parser.parse_args(argv)
    if not 0 <= args.process_exit <= 255:
        parser.error("")
    diagnostic = {"schema": "heptabao.comparison-diagnostic.v1", "comparison_process_exit": args.process_exit,
                  "requested_oracle_version": args.oracle_version, "status": "binding_unavailable",
                  "independent_admission": False, "full_openbao_compatibility": False, "production_qualified": False}
    code = 2
    try:
        observed = observe(args.binary, args.candidate_source)
        diagnostic["observed_binding"] = observed
        diagnostic["status"] = "report_rejected"
        try:
            report = read_report(args.report)
        except FileNotFoundError:
            diagnostic["status"] = "report_missing"
        else:
            projected = project(report, observed, args.oracle_version)
            diagnostic.update(projected, status="available")
            code = 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        # Never echo exceptions or input values, including malformed private JSON.
        pass
    try:
        write_report(args.output, diagnostic)
    except (OSError, ValueError, TypeError):
        print("comparison diagnostic: output rejected")
        return 2
    print("comparison diagnostic: " + diagnostic["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
