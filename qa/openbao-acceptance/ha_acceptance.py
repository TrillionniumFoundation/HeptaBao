#!/usr/bin/env python3
"""Observe >=3 real HTTPS nodes and verify an operator-controlled leader restart.

No process is killed by this tool. Baseline is NOT a failover pass. Verification
requires a separate operator fault receipt and live leader/data observations.
"""
from __future__ import annotations

import json
import re
import secrets
import time

from bao_http import BaoError, Client, SafeArgumentParser, digest, private_json, private_write
from migrate_kv2 import api, expect, verify_mount


def observe(clients):
    if len(clients) < 3 or len({c.address for c in clients}) != len(clients):
        raise BaoError("at_least_three_distinct_https_nodes_required")
    if len({c.namespace for c in clients}) != 1:
        raise BaoError("ha_nodes_must_use_same_namespace")
    health = [c.health() for c in clients]
    if len({h["cluster_id"] for h in health}) != 1:
        raise BaoError("ha_cluster_identity_mismatch")
    leaders = []
    addresses = set()
    for index, client in enumerate(clients):
        body = expect(client.request("GET", "/v1/sys/leader")).body
        if body.get("ha_enabled") is not True or type(body.get("is_self")) is not bool:
            raise BaoError("real_ha_not_enabled")
        if not isinstance(body.get("leader_address"), str) or not body["leader_address"]:
            raise BaoError("leader_identity_missing")
        addresses.add(body["leader_address"])
        if body["is_self"]:
            leaders.append(index)
    if len(leaders) != 1 or len(addresses) != 1:
        raise BaoError("no_unique_consistent_cluster_leader")
    return {"cluster_id": health[0]["cluster_id"], "leader_index": leaders[0],
            "leader_node": clients[leaders[0]].address,
            "nodes": [client.address for client in clients], "versions": [h["version"] for h in health]}


def read_all(clients, mount, key, value, version):
    for client in clients:
        data = expect(client.request("GET", api(mount, "data", key))).data()
        if data.get("data") != value or data.get("metadata", {}).get("version") != version:
            raise BaoError("ha_acknowledged_data_readback_mismatch")


def verify_fault_receipt(fault, baseline, now):
    if (not isinstance(fault, dict) or fault.get("action") != "controlled_leader_stop_restart"
            or fault.get("cluster_id") != baseline["cluster_id"]
            or fault.get("stopped_node") != baseline["leader_node"]):
        raise BaoError("fault_receipt_identity_mismatch")
    times = [baseline["observed_at"], fault.get("stopped_at"), fault.get("restarted_at"), fault.get("rejoined_at"), now]
    if any(type(value) not in (int, float) for value in times) or any(a >= b for a, b in zip(times, times[1:])):
        raise BaoError("fault_receipt_time_order_invalid")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--node-prefix", action="append", default=[])
    parser.add_argument("--phase", choices=("observe", "baseline", "verify"), default="observe")
    parser.add_argument("--receipt")
    parser.add_argument("--fault-receipt")
    parser.add_argument("--mount", default="secret")
    parser.add_argument("--allow-test-writes", action="store_true")
    args = parser.parse_args(argv)
    report = {"schema": "heptabao.ha-observation.v1", "phase": args.phase, "status": "not_run",
              "ha_qualified": False, "independent_fault_attestation": False,
              "failover": "not_run", "replicated_data": "not_run",
              "uncovered": ["quorum_loss", "split_brain", "membership_change", "snapshot_restore",
                            "network_partition", "power_loss", "linearizability_campaign"]}
    code = 2
    try:
        if len(args.node_prefix) < 3:
            raise BaoError("not_run_three_real_nodes_not_supplied")
        clients = [Client.from_env(prefix) for prefix in args.node_prefix]
        observation = observe(clients)
        report["node_count"] = len(clients)
        report["cluster_id_digest"] = digest(observation["cluster_id"])
        report["versions"] = observation["versions"]
        report["one_live_leader_observed"] = True
        if args.phase == "observe":
            report["reason"] = "leader_and_health_only_no_fault_or_data_test"
        else:
            if not args.allow_test_writes or not args.receipt:
                raise BaoError("baseline_verify_require_receipt_and_test_write_opt_in")
            leader = clients[observation["leader_index"]]
            verify_mount(leader, args.mount)
            if args.phase == "baseline":
                nonce = secrets.token_hex(16)
                key = "hbha-" + nonce + "/probe"
                value = {"synthetic": nonce, "stage": "before_failover"}
                response = expect(leader.request("POST", api(args.mount, "data", key), {"data": value, "options": {"cas": 0}}))
                if response.data().get("version") != 1:
                    raise BaoError("baseline_version_not_one")
                read_all(clients, args.mount, key, value, 1)
                receipt = {"schema": "heptabao.ha-baseline.v1", **observation, "observed_at": time.time(),
                           "mount": args.mount, "namespace": leader.namespace, "synthetic_key": key}
                private_write(args.receipt, receipt, replace=False)
                report.update(status="baseline_recorded", replicated_data="baseline_readback_passed",
                              next_step="operator_stop_recorded_leader_observe_new_leader_restart_old_node_then_verify")
                # Successful setup, explicitly no failover pass.
                code = 0
            else:
                if not args.fault_receipt:
                    raise BaoError("controlled_fault_receipt_required")
                baseline = private_json(args.receipt)
                if (not isinstance(baseline, dict) or baseline.get("schema") != "heptabao.ha-baseline.v1"
                        or baseline.get("nodes") != observation["nodes"]
                        or baseline.get("cluster_id") != observation["cluster_id"]
                        or baseline.get("mount") != args.mount or baseline.get("namespace") != leader.namespace
                        or not re.fullmatch(r"hbha-[0-9a-f]{32}/probe", baseline.get("synthetic_key", ""))):
                    raise BaoError("baseline_identity_or_scope_mismatch")
                verify_fault_receipt(private_json(args.fault_receipt), baseline, time.time())
                if observation["leader_node"] == baseline["leader_node"]:
                    raise BaoError("leader_change_not_observed")
                key = baseline["synthetic_key"]
                nonce = key.removeprefix("hbha-").removesuffix("/probe")
                read_all(clients, args.mount, key, {"synthetic": nonce, "stage": "before_failover"}, 1)
                value = {"synthetic": nonce, "stage": "after_failover"}
                response = expect(leader.request("POST", api(args.mount, "data", key), {"data": value, "options": {"cas": 1}}))
                if response.data().get("version") != 2:
                    raise BaoError("post_failover_version_not_two")
                read_all(clients, args.mount, key, value, 2)
                expect(leader.request("DELETE", api(args.mount, "metadata", key)), (204,))
                for client in clients:
                    expect(client.request("GET", api(args.mount, "data", key)), (404,))
                report.update(status="passed_observed_failover_and_readback", failover="operator_attested_and_leader_change_observed",
                              replicated_data="before_and_after_data_verified_on_all_rejoined_nodes", synthetic_cleanup="passed")
                code = 0
    except BaoError as error:
        report["reason"] = error.code
        report["status"] = "not_run" if error.code.startswith("not_run_") else "failed"
    except (OSError, TypeError, ValueError, AttributeError, KeyError):
        report["status"], report["reason"] = "failed", "invalid_configuration_receipt_or_response"
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
