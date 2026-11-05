#!/usr/bin/env python3
"""Create only new public reconciliation files; never run QA or read private credentials."""
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os

CONFIG = json.loads("{\"files\":{\"local-r8-evidence/authbus-owned-source-actual-r2-public-receipt.json\":[78725,\"20740bac22ae330a02e573bfe504feec4c5bce8699997eeb3c73377d31d35370\"],\"local-r8-evidence/authbus-owned-source-r2-controller-public-receipt.json\":[2115,\"d0c98be6fcc5e41e6c83f28089fcf1030be808f9d22fba1acbaf049a162439ea\"],\"HeptaBao/qa/openbao-acceptance/native_v6_authbus_owned_source_live.py\":[64050,\"fb44eab74e56b5d098a8fe0656ff764332fcccca9fe6ab0c7bcc4f2dfe21c121\"],\"HeptaBao/qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs\":[30284,\"dc3120ba49f6088197dd4175054dd3c1d908efc79916599e9cee7ac85a46c4af\"],\"run_authbus_owned_source_actual_r2b.py\":[10329,\"e499bd67cae460aa1895805043194d22141f8890d6a08806fd3d9c93770d92db\"],\"HeptaBao/tools/authbus/authbus_coordinator.py\":[39815,\"81bfbacfd14df399c1e8eef963447803cee8e01aebc2474c0f39c2595e7fce47\"],\"HeptaBao/qa/openbao-acceptance/owned_process.py\":[28442,\"0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0\"],\"HeptaBao/qa/single-node/smoke.py\":[16470,\"ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971\"]},\"source\":{\"exportReceiptSha256\":\"41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907\",\"privateCandidateSha256\":\"f2c164581d5afb0c9f95b9a71aedaa3f2a889817dabe1201169f7b5ce6f5dbe6\",\"profileIdSha256\":\"7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d\",\"credentialDigest\":\"71c3e21e28368490383dc3628f561e42fef261b0f4ef78263e4dcf3873dc381b\",\"identityDigest\":\"c84e09f9ec9749c94545ddf65091f448ff795b318fde24a3780b6f000ff4ee9d\"},\"configSha256\":\"791d2d5e7166d02b871a8aa21b0194ca65456c0019757451bfe46d0fe8127d55\",\"inspectorSha256\":\"703cb463ce43488ff29f8a8394fab4bd591c69bc2a06c1c5ddc64d0abc1e14de\",\"sourceRechecks\":{\"source_initial_recheck\":\"b024efdb3087b80bd068469886e4fe4638b7b5da8f85fad97a15a5b3f4872dcc\",\"operator_authorize_exact_a\":\"fb9aed9b8d786fddce92ff875d40088ed747a2f7b14343a13aa0abab9edc2f59\",\"actual_manifest_cas_race\":\"4396843dcdd96407d29af711485dccd8847e39946fa75792c1660dbf8ed43f5e\",\"actual_central_process_crash\":\"04fc2232234a91efcf7ad9d0f9d435082508eeae5247f83ee7bddd5f0f39e21e\",\"source_final_recheck\":\"2a5dbb05d5378c7b8c634cab90bcfe27cf579f1c1bc7d39e93cfaa09d7e763b0\"}}")

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "local-r8-evidence"
JSON_PATH = OUT / "authbus-owned-source-r2-reconciliation-r1.json"
MD_PATH = OUT / "authbus-owned-source-r2-reconciliation-r1.md"
DRIVER = "local-r8-evidence/authbus-owned-source-actual-r2-public-receipt.json"
WRAPPER = "local-r8-evidence/authbus-owned-source-r2-controller-public-receipt.json"
REPEAT = "actual_manifest_cas_race.captured_actual_token"


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_inputs():
    result = {}
    for name, (size, digest) in CONFIG["files"].items():
        path = ROOT / name
        require(path.resolve(strict=True) == path and path.is_file()
                and not path.is_symlink(), "input_path")
        raw = path.read_bytes()
        require(len(raw) == size and sha(raw) == digest, "input_original_bytes_changed")
        result[name] = raw
    return result


def build(inputs):
    r, c = json.loads(inputs[DRIVER]), json.loads(inputs[WRAPPER])
    checks = r["checks"]
    names = [row["case"] for row in checks]
    counts = Counter(names)
    require(len(checks) == 293 and len(counts) == 292
            and all(row.get("passed") is True for row in checks)
            and {name: count for name, count in counts.items() if count != 1} == {REPEAT: 2},
            "event_293_292_contract_changed")
    require([i for i, row in enumerate(checks) if row["case"] == REPEAT] == [72, 73]
            and all(checks[i] == {"case": REPEAT, "passed": True} for i in (72, 73)),
            "repeat_occurrence_changed")
    driver_source = inputs["HeptaBao/qa/openbao-acceptance/native_v6_authbus_owned_source_live.py"].decode()
    for anchor in (
        "competitor = BoundBao(config); secondary.append(competitor)",
        "tokens = [item.token for item in [client, *secondary] if item.token is not None]",
        "check(name + '.captured_actual_token', isinstance(token, str) and len(token) >= 8)",
        "all_tokens = list(dict.fromkeys(issued))",
    ):
        require(driver_source.count(anchor) == 1, "frozen_source_anchor_changed")
    require(inputs["run_authbus_owned_source_actual_r2b.py"].decode().count("len(set(names)) == len(names)") == 1,
            "wrapper_unique_predicate_changed")

    predicates = [
        {"name": "checks_nonempty", "expression": "bool(checks)", "actual": bool(checks)},
        {"name": "all_events_passed", "expression": "all(item.get('passed') is True for item in checks)",
         "actual": all(row.get("passed") is True for row in checks)},
        {"name": "case_names_unique", "expression": "len(set(names)) == len(names)",
         "actual": len(set(names)) == len(names), "operands": {"distinct_names": len(set(names)), "events": len(names)}},
        {"name": "child_exit_zero", "expression": "code == 0", "actual": c["exit_code"] == 0, "observed": c["exit_code"]},
        {"name": "not_timed_out", "expression": "not timed_out", "actual": not c["timed_out"], "observed": c["timed_out"]},
        {"name": "source_unchanged_after", "expression": "source_unchanged", "actual": c["source_unchanged_after"]},
        {"name": "driver_ok", "expression": "receipt.get('ok') is True", "actual": r.get("ok") is True},
        {"name": "driver_schema_exact", "expression": "receipt.get('schema') == 'native-v6-authbus-real-owned-source-live-v1'",
         "actual": r.get("schema") == "native-v6-authbus-real-owned-source-live-v1", "observed": r.get("schema")},
        {"name": "no_production_cutover", "expression": "receipt.get('production_cutover') is False",
         "actual": r.get("production_cutover") is False, "observed": r.get("production_cutover")},
        {"name": "no_provider_called", "expression": "receipt.get('provider_called') is False",
         "actual": r.get("provider_called") is False, "observed": r.get("provider_called")},
    ]
    require([p["name"] for p in predicates if p["actual"] is not True] == ["case_names_unique"],
            "another_wrapper_leaf_failed")
    valid = bool(checks) and all(row.get("passed") is True for row in checks) and len(set(names)) == len(names)
    recomputed_ok = (c["exit_code"] == 0 and not c["timed_out"] and c["source_unchanged_after"]
                     and valid and r.get("ok") is True
                     and r.get("schema") == "native-v6-authbus-real-owned-source-live-v1"
                     and r.get("production_cutover") is False and r.get("provider_called") is False)
    require(valid is False and recomputed_ok is False and c["ok"] is False,
            "wrapper_failure_must_remain")
    require(c["public_receipt_sha256"] == CONFIG["files"][DRIVER][1]
            and c["public_receipt_bytes"] == len(inputs[DRIVER])
            and c["observed_checks"] == c["passed_checks"] == 293
            and c["mutation_outcome_unknown"] is False and c["driver_error_code"] is None,
            "wrapper_binding_or_outcome_changed")

    captures = [(i, row) for i, row in enumerate(checks) if row["case"].endswith(".captured_actual_token")]
    require(len(captures) == 15 and [i for i, (_, row) in enumerate(captures) if row["case"] == REPEAT] == [4, 5],
            "capture_count_or_order_changed")
    vectors = []
    specs = [
        ("revoke.token_live_before.", 200, {str(i) for i in range(15)}),
        ("revoke.token.", 204, {str(i) for i in range(15)}),
        ("revoke.token_denied.", 403, {str(i) for i in range(15)}),
        ("revoke.persisted_token.", 403, {str(i) for i in range(15)}),
    ]
    roles = {"authbus-owned-producer", "authbus-owned-follower", "authbus-owned-writer"}
    specs.extend((prefix, status, roles) for prefix, status in (
        ("revoke.sid.", 204), ("revoke.sid_login_denied.", 400), ("revoke.persisted_sid_login_denied.", 400)))
    for prefix, status, expected_ids in specs:
        rows = [{"raw_check_index": i, **row} for i, row in enumerate(checks) if row["case"].startswith(prefix)]
        require(len(rows) == len(expected_ids)
                and {row["case"][len(prefix):] for row in rows} == expected_ids
                and all(row["passed"] is True and row["status"] == row["expected"] == status for row in rows),
                "revocation_vector_changed")
        vectors.append({"prefix": prefix, "count": len(rows), "expected_status": status, "rows": rows})
    actions = {row["case"]: row for row in r["central_actions"]}
    require(len(actions) == len(r["central_actions"]) == 8, "central_action_count")
    race = actions["actual_manifest_cas_race"]
    require(race["completedAuthRoutes"] == ["auth/approle/login", "auth/approle/login"]
            and race["actualCompetingManifestCas"] is True and race["ok"] is True
            and race["result"]["deferred"] == 1
            and race["actualCasConflictReplies"] == [{
                "method": "POST", "routeSha256": "3a11a54039de227ba2c6940725bf3e7c5681f773dd3febb22aef8d871502e5d2",
                "status": 400, "originalExactErrorContract": True,
                "errorSha256": "3841110dcf649dc9a4441c9302297b9fdb6ae9dbd2fe240bb3c4ab92993eb3d5"}],
            "actual_race_evidence_changed")

    source = r["source"]
    require(all(source.get(key) == value for key, value in CONFIG["source"].items())
            and source["physicalHost"] == "main" and source["hostId"] == "desktop"
            and source["sourceOwnershipQualified"] is True and source["fixtureCopyExactBytes"] is True
            and source["sourceCandidateTransferredOffOwnerHost"] is False
            and source["snapshotNotARefreshLease"] is True and source["providerLivenessVerified"] is False,
            "real_source_binding_or_scope_changed")
    require(len(r["source_rechecks"]) == 2, "outer_recheck_count")
    rechecks = [
        {"case": "source_initial_recheck", **r["source_rechecks"][0]},
        {"case": "operator_authorize_exact_a", **actions["operator_authorize_exact_a"]["sourceReadBeforeAuthorization"]},
        {"case": "actual_manifest_cas_race", **race["sourceReadBeforeManifest"]},
        {"case": "actual_central_process_crash", **actions["actual_central_process_crash"]["sourceReadBeforeManifest"]},
        {"case": "source_final_recheck", **r["source_rechecks"][1]},
    ]
    expected_recheck = {key: CONFIG["source"][key] for key in ("profileIdSha256", "credentialDigest", "identityDigest")}
    expected_recheck.update(configSha256=CONFIG["configSha256"], inspectorSha256=CONFIG["inspectorSha256"])
    for row in rechecks:
        require(all(row.get(key) == value for key, value in expected_recheck.items())
                and row["receiptSha256"] == CONFIG["sourceRechecks"][row["case"]]
                and row["ownerStillExact"] is True and row["originalOperationDeadlineReused"] is True
                and row["providerLivenessVerified"] is False and row["snapshotNotARefreshLease"] is True,
                "source_recheck_changed")
    require(r["sourceStillExactAtFinalRecheck"] is True and r["originalOperationBudgetSeconds"] == 360
            and r["originalOperationElapsedSeconds"] == 88.408 and c["elapsed_seconds"] == 88.675,
            "final_source_or_deadline_changed")
    by_case = {row["case"]: row for row in checks}
    final_checks = [by_case[key] for key in (
        "source.original_plugin_unchanged", "source.central_code_unchanged",
        "source.export_bytes_unchanged", "evidence.no_secret_profile_or_identity_in_public_receipts")]
    require(all(row["passed"] is True for row in final_checks), "final_source_or_redaction_failed")

    good_clients = [row for row in r["clients"] if row["ok"] is True]
    require(len(r["clients"]) == 8 and len(good_clients) == 6
            and {row["case"] for row in r["clients"] if row["ok"] is False}
            == {"follower_bad_binding", "original_follower_sid_revoked"}, "client_outcome_changed")
    tls = [row for client in good_clients for row in client["observations"]]
    require(len(tls) == 37 and all(row["tlsAuthorized"] is True and row["isSessionReused"] is False
            and row["peerCertificateSha256"] == r["server_cert_der_sha256"] for row in tls),
            "actual_tls_evidence_changed")
    renew = actions["central_actual_renewal_api"]
    require(renew["completedAuthRoutes"] == ["auth/approle/login", "auth/token/renew-self"]
            and renew["result"] == {"actualRenewSelfSameBearer": True, "forcedLocalDueClock": True,
                "originalLeaseOnlyShortenedBeforeRenew": True, "realLeaseExpiryWaited": False,
                "sameBearerLiveReadBeforeAndAfter": True}, "renewal_scope_changed")
    excluded = ("ha_cluster_qualified", "oauth_refresh_ownership_qualified", "provider_liveness_verified",
                "oauth_refreshed", "enforced_scheduler_qualified", "production_coordinator_replacement",
                "production_cutover", "production_mutation", "j3160_contacted", "provider_called")
    require(all(r.get(key) is False for key in excluded) and r["realCredentialVersionsUsed"] == 1
            and r["single_node_native_fixture"] is True
            and r["revokedTokenScope"] == "captured_fixture_approle_bearers", "scope_exclusions_changed")
    accepted_names = (
        "central.no_implicit_source_authority", "central.no_implicit_publication",
        "central.actual_cas_rejection", "central.conflict_published_no_credential",
        "central.conflict_completed_no_unknown_pending", "central.write_ahead_journal_survived",
        "central.actual_commit_without_success_receipt", "central.original_credential_payload_exact",
        "central.full_document_content_address", "central.current_or_historical_manifest_recovery",
        "central.recovery_did_not_replay_manifest", "central.pending_cleared_after_immutable_receipt",
        "original_follower.actual_sdk_exact_a", "backup.actual_sdk_restored_same_real_source",
        "rollback.no_auth_and_real_local_value_retained", "rollback.same_binding_bytes_and_actual_sdk",
        "central.renew_same_bearer_real_api", "central.same_event_not_republished",
        "revoke.original_plugin_exact_sid_denial")
    accepted = [{"raw_check_index": names.index(name), **by_case[name]} for name in accepted_names]
    require(all(row["passed"] is True for row in accepted), "scoped_case_failed")
    return {
        "schema": "heptabao.authbus-owned-source-r2-public-reconciliation.v1",
        "status": "reconciled_scoped_evidence_original_wrapper_failed",
        "review_recorded_utc": datetime.now(timezone.utc).isoformat(),
        "review_method": "read_only_public_receipts_and_exact_frozen_source",
        "generator_sha256": sha(Path(__file__).read_bytes()),
        "inputs": {name: {"bytes": size, "sha256": digest} for name, (size, digest) in CONFIG["files"].items()},
        "original_driver_ok": True, "original_wrapper_accepted": False,
        "original_wrapper_contract_passed": False, "original_receipts_modified": False,
        "original_failure_preserved": True, "new_execution_performed": False,
        "private_candidate_or_token_read_by_reviewer": False,
        "original_wrapper_leaf_predicates": predicates,
        "original_wrapper_composites": {"valid": valid, "recomputed_ok": recomputed_ok, "recorded_ok": c["ok"]},
        "only_failed_wrapper_leaf_predicate": "case_names_unique",
        "additional_binding_checks": {"wrapper_binds_exact_driver_bytes_and_sha256": True,
            "wrapper_counts_match_raw": True, "driver_error_code": c["driver_error_code"],
            "mutation_outcome_unknown": c["mutation_outcome_unknown"]},
        "events": {"observed": 293, "passed": 293, "distinct_case_labels": 292,
                   "labels_unique": False, "293_unique_cases_claimed": False},
        "expected_repeated_event": {"case": REPEAT, "count": 2,
            "raw_check_indices_zero_based": [72, 73], "occurrence_indices_zero_based": [0, 1],
            "roles_in_capture_order_inferred_from_frozen_code": ["primary_client", "competing_client"],
            "capture_ordinals_among_all_captures_zero_based": [4, 5],
            "cause": "capture() serializes [client, *secondary]; collect_process() emits the same label once per bearer.",
            "actual_completed_auth_routes": race["completedAuthRoutes"],
            "actual_competing_manifest_cas": race["actualCompetingManifestCas"],
            "actual_conflict_replies": race["actualCasConflictReplies"],
            "generic_duplicate_acceptance_allowed": False},
        "distinct_bearer_inference": {
            "is_inference_from_bound_public_receipt_and_frozen_code": True,
            "all_capture_events": 15, "deduplication_expression": "all_tokens = list(dict.fromkeys(issued))",
            "post_dedup_live_revoke_deny_cold_deny_indices": list(range(15)),
            "conclusion": "All 15 captured bearer strings were distinct under the bound implementation, including both race captures.",
            "raw_tokens_or_token_fingerprints_inspected": False,
            "token_content_transferred_to_reconciliation": False},
        "revocation_vectors": vectors,
        "source_binding": {**CONFIG["source"], "physical_host": "main", "source_host_id": "desktop",
            "fixture_producer_host_id": source["fixtureProducerHostId"],
            "source_ownership_qualified_in_original_receipt": True,
            "source_candidate_transferred_off_owner_host": False,
            "source_export_receipt_sha256_is_from_bound_driver": True,
            "source_export_receipt_separately_reopened_by_reviewer": False,
            "candidate_private_contents_reopened_by_reviewer": False, "snapshot_not_a_refresh_lease": True},
        "recorded_source_rechecks": rechecks, "recorded_final_source_recheck": rechecks[-1],
        "source_still_exact_at_final_recheck": True, "final_source_and_redaction_checks": final_checks,
        "execution_source_binding": {**{key: r[key] for key in (
            "driver_sha256", "consumer_sha256", "central_source_sha256", "plugin_source_sha256", "binary_sha256")},
            **{key: c[key] for key in (
            "binary_source_commit", "binary_source_tree", "source_packet_sha256", "source_unchanged_after")}},
        "scoped_functional_evidence_supported": True, "scoped_functional_cases": accepted,
        "scope": {"physical_host": "main", "single_node_native_fixture": True, "real_credential_versions": 1,
            **{key: r[key] for key in ("actual_original_producer_and_consumer",
                "actual_independent_service_credential_publication", "actual_sdk_qualified", "actual_service_https_qualified")},
            "positive_plugin_invocations": 6, "expected_negative_plugin_invocations": 2,
            "authorized_non_resumed_positive_client_tls_observations": 37,
            "actual_renewal_result": renew["result"], "sdk_backup": r["backup"],
            "recorded_server_cycles": r["server_cycles"], "original_operation_budget_seconds": 360,
            "original_operation_elapsed_seconds": 88.408, "outer_elapsed_seconds": 88.675,
            "excluded_original_flags": {key: r[key] for key in excluded}},
        "cleanup": {"captured_fixture_approle_bearers_revoked_and_cold_denied": 15,
            "fixture_secret_ids_destroyed_and_cold_denied": 3, "original_popen_kill_and_wait_supported": True,
            "process_stop_basis_is_control_flow_inference": True,
            "basis": "run() finally calls instance.stop(); it kills and waits its original Popen and requires -9. A cleanup exception makes driver ok false; the bound driver exited zero with ok true.",
            "owned_process_branch": "standalone_compatibility_without_Owner_receipt",
            "independent_kernel_birth_cleanup_qualified": False,
            "independent_final_host_process_inventory_present": False,
            "whole_host_zero_residue_claimed": False,
            "fixture_root_token_or_unseal_key_revocation_claimed": False,
            "provider_credential_revocation_claimed": False, "private_fixture_or_backup_deletion_claimed": False},
        "acceptance_policy": {"does_not_override_original_wrapper_contract": True,
            "does_not_delete_or_rename_raw_events": True, "does_not_claim_all_five_migration_gates_complete": True,
            "does_not_allow_production_cutover": True,
            "expected_repeat_bound_only_to_this_driver_and_these_receipts": True}
    }


def new_file(path, raw):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    require(all(not path.exists() and not path.is_symlink() for path in (JSON_PATH, MD_PATH)),
            "reconciliation_outputs_must_be_new")
    inputs = read_inputs()
    record = build(inputs)
    require(read_inputs() == inputs, "inputs_changed_during_review")
    raw_json = (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    md = f"""# AuthBus owned-source R2 公有证据核对

真实 driver 成功；原 wrapper 因事件标签不唯一保持失败。本记录只解释并绑定已有证据，没有重跑，也没有改动原回执。

## 原件及结果

| 原件 | 字节数 | SHA-256 |
|---|---:|---|
| [driver 公有回执](authbus-owned-source-actual-r2-public-receipt.json) | 78,725 | 20740bac22ae330a02e573bfe504feec4c5bce8699997eeb3c73377d31d35370 |
| [wrapper 公有回执](authbus-owned-source-r2-controller-public-receipt.json) | 2,115 | d0c98be6fcc5e41e6c83f28089fcf1030be808f9d22fba1acbaf049a162439ea |

driver exit=0、ok=true；293 条事件通过，292 个不同标签。wrapper ok=false 原样保留。逐项重算外层表达式，唯一失败叶子条件是名称唯一性；valid 和总 ok 因此为 false。全部实际值及冻结代码绑定见 [reconciliation JSON]({JSON_PATH.name})，SHA-256：{sha(raw_json)}。

## 两次捕获的依据

唯一重复是 actual_manifest_cas_race.captured_actual_token，原数组零基索引 72、73。冻结 driver 在 CAS race 中建立独立 competitor，capture() 按 [client, *secondary] 保存 bearer；收集时没有给标签加 ordinal。实际 action 记录两次 AppRole 登录及真实 HTTP 400 CAS 冲突。

全程 15 次捕获，经 dict.fromkeys(issued) 按内容去重后，仍实际执行完整的 15 组撤销前 200、撤销 204、即时拒绝 403、冷重启拒绝 403。这支持两个 race bearer 不同的**推断**，它们对应全部捕获的零基 ordinal 4、5。未读取 token 或 candidate 私密内容；没有删除第二条事件，没有放宽为接受任意重复标签。

## 可以承认的范围

main 上单节点新 native fixture 使用一个真实 owned source A，完成独立 coordinator、原 producer/follower SDK、AppRole、真实 TLS、KV/CAS、Policy 拒绝、崩溃恢复、SDK SQLite 备份恢复、CA 绑定回滚，以及同一 bearer 的实际 renew API。15 个捕获 bearer 与三个 fixture SecretID 全部完成撤销及冷重启拒绝。六次成功 plugin 调用记录了 37 条授权成功且未复用 session 的 TLS 观察。

来源 export receipt 固定 SHA 为 41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907；绑定 driver 中记录五次 owner 重验。最终重验 receipt SHA 为 2a5dbb05d5378c7b8c634cab90bcfe27cf579f1c1bc7d39e93cfaa09d7e763b0，owner、凭证、身份、配置及 inspector 摘要保持一致。本次没有另行打开来源 export receipt；JSON 区分了直接读取的公有原件与原件内记录的来源证据。

## 清理和未覆盖范围

最终原 Popen 的 kill/wait 成功，由冻结 finally -> instance.stop() 控制流与 driver exit 0 支持。该运行走 owned_process standalone 兼容分支，没有独立 Owner 收据、kernel birth 验证或最终主机进程清单，因此不声明全主机零残留或严格进程身份清理资格。fixture root token、unseal key、原 provider credential 及私有备份均未被本记录声明为已撤销或删除。

本记录不覆盖 OAuth refresh 所有权、provider 当前存活、真实 A→B 轮换、强制 scheduler、多机 HA、逐台生产切流、全部生产备份迁移或旧服务清理。原 wrapper 不因本记录变成通过。

## 生成与保全

authbus_owned_source_r2_reconcile.py 只读固定 SHA 公有原件及源码，断言准确 293/292、唯一重复索引、15 组 bearer 和三组 SecretID 向量，用 O_EXCL 写新文件。它不执行 QA、网络操作或凭证读取，不覆盖现有记录，并在写入前后重验所有原件字节。
"""
    raw_md = md.encode()
    new_file(JSON_PATH, raw_json)
    new_file(MD_PATH, raw_md)
    require(read_inputs() == inputs, "original_inputs_changed_after_output")
    for path, raw in ((JSON_PATH, raw_json), (MD_PATH, raw_md)):
        require(path.read_bytes() == raw, "output_readback_changed")
    print(json.dumps({"status": "created", "original_wrapper_accepted": False,
        "observed_events": 293, "passed_events": 293, "distinct_case_labels": 292,
        "original_inputs_unchanged": True, "new_execution_performed": False,
        "files": [{"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
                  for path, raw in ((JSON_PATH, raw_json), (MD_PATH, raw_md))]}, sort_keys=True))


if __name__ == "__main__":
    main()

