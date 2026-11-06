"""Pure validation of exact private lifecycle observation shapes.

No observation is manufactured or obtained here. The concrete platform adapter
must bind the raw private observations to its actual command/HTTP receipts and
retain those files. These shape/consistency checks are not an authority oracle.
Only a validated safe projection may leave that private evidence boundary.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from lifecycle_contract import EndpointHandle, ManagerIdentity, ManagerRetirement, RestartObservation


class RejectedLifecycleObservation(ValueError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise RejectedLifecycleObservation(code)


def exact(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    need(type(value) is dict and set(value) == keys, code)
    return value


def positive(value: Any) -> bool:
    return type(value) is int and value > 0


def private_ref(value: Any) -> None:
    need(isinstance(value, (Path, str)) and str(value).startswith("/"), "private_original_observation_locator")
    text = str(value)
    need(len(text) <= 4096 and not text.endswith("/")
         and not any(ord(c) < 32 or ord(c) == 127 for c in text)
         and not any(part in ("", ".", "..") for part in text[1:].split("/")), "canonical_private_original_locator")


def digest(value: Any) -> None:
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "exact_sha256_shape")


def validate_manager_identity(
    manager: ManagerIdentity, endpoint: EndpointHandle, *, expected_binary_sha256: str
) -> None:
    digest(expected_binary_sha256)
    need(manager.domain == endpoint.manager_domain and manager.domain in ("gui/501", "user/501"), "same_observed_manager_domain")
    need(manager.label == endpoint.label, "same_exact_manager_label")
    need(positive(manager.pid) and manager.uid == 501 and type(manager.uid) is int, "owned_live_manager_pid")
    # This is a required future admission observation, not an assumption about
    # every launchd process. A different actual topology requires explicit review.
    need(manager.pgid == manager.pid and positive(manager.session), "observed_private_server_process_group")
    need(manager.birth_is_sole_authority is False, "birth_timestamp_not_signal_authority")
    need(type(manager.process_birth_observation) is dict and manager.process_birth_observation.get("diagnostic_only") is True, "birth_observation_diagnostic_scope")
    directory = manager.data_directory_identity
    need(type(directory) is dict and directory.get("path") == str(endpoint.data_dir), "same_private_data_path")
    for name in ("dev", "inode"):
        need(positive(directory.get(name)), "data_directory_numeric_identity")
    need(directory.get("uid") == 501 and directory.get("mode") == 0o700, "private_data_directory_identity")
    executable = manager.executable_identity
    need(type(executable) is dict and executable.get("sha256") == expected_binary_sha256 and positive(executable.get("bytes")), "actual_normal_executable_binding")
    plist = manager.plist_file_identity
    need(type(plist) is dict and plist.get("uid") == 501 and plist.get("mode") == 0o600 and plist.get("nlink") == 1, "owned_original_plist_identity")
    need(positive(plist.get("dev")) and positive(plist.get("inode")), "original_plist_numeric_identity")
    private_ref(manager.observation_private_ref)


def validate_manager_retirement(retirement: ManagerRetirement, original: ManagerIdentity) -> None:
    need(retirement.original == original, "same_original_manager_retired")
    need(retirement.stop_operation == "launchctl_bootout_exact_label", "only_exact_owned_manager_stop")
    need(retirement.server_waitpid_performed_by_this_controller is False, "launchd_server_not_our_waitpid_child")
    need(retirement.outcome_unknown is False, "manager_stop_outcome_known")
    need(len(retirement.command_children) > 0, "actual_stop_command_receipts_required")
    stop_count = 0
    for child in retirement.command_children:
        need(positive(child.pid) and child.pgid == child.pid and child.session == child.pid, "original_short_child_identity")
        need(type(child.original_wait_count) is int and child.original_wait_count == 1, "original_short_child_wait_once")
        need(list(child.remaining_live_members) == [] and list(child.custody_gaps) == [], "original_short_child_no_live_or_gaps")
        need(type(child.returncode) is int, "actual_short_child_exit_code")
        if child.operation == "launchctl_bootout_exact_label":
            stop_count += 1
            need(child.returncode == 0, "exact_bootout_succeeded")
        elif child.operation == "launchctl_print_exact_label":
            need(child.returncode in (0, 113), "exact_label_query_exit_class")
        else:
            need(child.operation in ("ps_numeric_census", "diskutil_info", "seed_export", "seed_stage") and child.returncode == 0, "known_retirement_child_operation")
        private_ref(child.original_receipt_private_ref)
    need(stop_count == 1, "single_original_bootout")
    label = exact(retirement.label_absence_observation, {
        "schema", "domain", "label", "query_argv", "returncode", "classification", "raw_private_ref",
    }, "label_absence_shape")
    need(label["schema"] == "heptabao.exact-launchd-label-absence.v1", "label_absence_schema")
    need(label["domain"] == original.domain and label["label"] == original.label, "same_label_absence_target")
    need(label["query_argv"] == ["/bin/launchctl", "print", original.domain + "/" + original.label], "exact_label_query_argv")
    need(type(label["returncode"]) is int and label["returncode"] == 113 and label["classification"] == "exact_label_absent", "explicit_label_not_found_not_generic_error")
    private_ref(label["raw_private_ref"])
    process = exact(retirement.original_process_retirement_observation, {
        "schema", "original_pid", "original_pgid", "numeric_census_complete",
        "original_pid_rows", "live_original_group_rows", "getpgid_errno", "raw_private_ref",
    }, "original_process_retirement_shape")
    need(process["schema"] == "heptabao.managed-process-retirement.v1", "original_process_retirement_schema")
    need(process["original_pid"] == original.pid and process["original_pgid"] == original.pgid, "original_numeric_process_target")
    need(process["numeric_census_complete"] is True and process["original_pid_rows"] == [] and process["live_original_group_rows"] == [], "complete_numeric_census_no_original_or_live_group")
    need(type(process["getpgid_errno"]) is int and process["getpgid_errno"] == 3, "original_pid_esrch_observed")
    private_ref(process["raw_private_ref"])
    writer = exact(retirement.writer_release_observation, {
        "basis", "direct_writer_fence_observed",
    }, "writer_release_scope_shape")
    need(writer == {
        "basis": "manager_and_original_process_retired",
        "direct_writer_fence_observed": False,
    }, "stop_is_not_an_independent_storage_fence")
    if retirement.exclusive_writer_fence_observation is not None:
        fence = exact(retirement.exclusive_writer_fence_observation, {
            "schema", "operation", "actual_tool_exit_code", "original_writer_fence_held", "receipt_private_ref",
        }, "actual_seed_fence_shape")
        need(fence["schema"] == "heptabao.actual-seed-fence-observation.v1" and fence["operation"] == "export", "actual_seed_export_fence_only")
        need(type(fence["actual_tool_exit_code"]) is int and fence["actual_tool_exit_code"] == 0 and fence["original_writer_fence_held"] is True, "actual_seed_fence_succeeded")
        private_ref(fence["receipt_private_ref"])
    private_ref(retirement.original_receipt_private_ref)


def validate_seal_response(value: Mapping[str, Any], *, method: str, path: str, sealed: bool, progress: int) -> int:
    response = exact(value, {"schema", "method", "path", "http_status", "body", "raw_private_ref"}, "seal_response_shape")
    need(response["schema"] == "heptabao.actual-private-seal-response.v1", "seal_response_schema")
    need(response["method"] == method and response["path"] == path, "exact_seal_operation")
    need(type(response["http_status"]) is int and response["http_status"] == 200, "successful_seal_operation")
    body = response["body"]
    need(type(body) is dict, "original_seal_json_object")
    need(body.get("type") == "shamir" and body.get("initialized") is True, "real_initialized_shamir_profile")
    need(type(body.get("t")) is int and body["t"] == 2 and type(body.get("n")) is int and body["n"] == 3, "actual_two_of_three_profile")
    need(body.get("sealed") is sealed and type(body.get("progress")) is int and body["progress"] == progress, "actual_threshold_progress")
    need(positive(body.get("seal_generation")), "actual_seal_generation")
    private_ref(response["raw_private_ref"])
    return body["seal_generation"]


def validate_restart_observation(
    observation: RestartObservation, endpoint: EndpointHandle, *, expected_binary_sha256: str
) -> None:
    validate_manager_identity(observation.before, endpoint, expected_binary_sha256=expected_binary_sha256)
    validate_manager_identity(observation.after, endpoint, expected_binary_sha256=expected_binary_sha256)
    validate_manager_retirement(observation.retirement, observation.before)
    need(observation.after.pid != observation.before.pid, "distinct_new_manager_pid_not_reused_old_identifier")
    need(observation.before.data_directory_identity == observation.after.data_directory_identity, "same_original_data_directory_reopened")
    need(observation.before.plist_file_identity == observation.after.plist_file_identity, "same_original_plist_restarted")
    need(len(observation.start_command_children) == 1, "single_actual_bootstrap_command")
    start = observation.start_command_children[0]
    need(start.operation == "launchctl_bootstrap_original_plist"
         and type(start.returncode) is int and start.returncode == 0
         and type(start.original_wait_count) is int and start.original_wait_count == 1, "original_bootstrap_child_completed_once")
    need(positive(start.pid) and start.pid == start.pgid == start.session and list(start.remaining_live_members) == [] and list(start.custody_gaps) == [], "bootstrap_child_retired_with_no_gaps")
    private_ref(start.original_receipt_private_ref)
    tls = exact(observation.tls_observation, {
        "schema", "origin", "verify_mode", "check_hostname", "peer_leaf_sha256", "protocol", "raw_private_ref",
    }, "tls_observation_shape")
    digest(endpoint.leaf_sha256)
    need(tls["schema"] == "heptabao.actual-managed-tls-observation.v1" and tls["origin"] == endpoint.origin, "same_actual_tls_origin")
    need(tls["verify_mode"] == "CERT_REQUIRED" and tls["check_hostname"] is True, "strict_tls_chain_and_hostname")
    need(tls["peer_leaf_sha256"] == endpoint.leaf_sha256 and tls["protocol"] in ("TLSv1.2", "TLSv1.3"), "actual_exact_leaf_and_protocol")
    private_ref(tls["raw_private_ref"])
    generations = [
        validate_seal_response(observation.sealed_before_unseal_observation, method="GET", path="sys/seal-status", sealed=True, progress=0),
        validate_seal_response(observation.one_share_still_sealed_observation, method="POST", path="sys/unseal", sealed=True, progress=1),
        validate_seal_response(observation.two_shares_unsealed_observation, method="POST", path="sys/unseal", sealed=False, progress=0),
    ]
    need(len(set(generations)) == 1 and observation.seal_identity_equal is True, "same_original_seal_across_restart_and_unseal")
    private_ref(observation.original_receipt_private_ref)
