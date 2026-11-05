#!/usr/bin/env python3
"""One owned Mac-native / Python TCP comparison, preserving LAN98=36/98.

Run only on the already authorized main controller. Preparation is outside the
listener window. Every start is submitted once; all agents stop themselves.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import sys
import time


SSH = ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectionAttempts=1",
       "-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2"]


def encode(value):
    return base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode("ascii")


def load_agent():
    path = Path(__file__).resolve().with_name("native_lan_tcp_diagnostic_agent.py")
    raw = path.read_bytes()
    spec = importlib.util.spec_from_file_location("heptabao_tcp_diagnostic_agent", path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module, raw


def wait_unreaped(process, deadline):
    while time.monotonic() < deadline:
        observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None:
            return True
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    return False


def run_bounded(agent, argv, output, label, *, input_bytes=None, seconds=15):
    result = {"label": label, "submission_count": 1, "automatic_retry": False, "timeout_seconds": seconds}
    started = time.monotonic()
    child, owner = None, None
    try:
        with (output / (label + ".stdout.jsonl")).open("xb") as stdout, (output / (label + ".stderr.log")).open("xb") as stderr:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes else subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, env=agent.ENV, start_new_session=True)
            owner = agent.process_identity(child.pid)
            agent.need(owner is not None, "ssh_owned_identity_missing")
            if input_bytes is not None:
                child.stdin.write(input_bytes)
                child.stdin.close()
            result["completed_before_deadline"] = wait_unreaped(child, started + seconds)
    finally:
        if child is not None:
            result["local_ssh_cleanup"] = agent.stop_unreaped_owned(child, owner or agent.process_identity(child.pid))
            result["exit_code"] = child.returncode
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
        result["completed_before_deadline"] = result.get("completed_before_deadline", False) and result["elapsed_seconds"] < seconds
    stdout = (output / (label + ".stdout.jsonl")).read_bytes()
    stderr = (output / (label + ".stderr.log")).read_bytes()
    agent.need(len(stdout) <= 1024 ** 2 and len(stderr) <= 65536, "bounded_controller_ssh_output_required")
    result.update(stdout_sha256=agent.digest(stdout), stderr_sha256=agent.digest(stderr),
                  stdout_bytes=len(stdout), stderr_bytes=len(stderr))
    return result, [json.loads(line) for line in stdout.splitlines() if line.strip()]


def ssh_command(alias, action, payload, *, prepare=False):
    argv = ["python3", "-B", "-" if prepare else payload["root"] + "/agent.py", action, encode(payload)]
    return SSH + [alias, shlex.join(argv)]


def projection(receipts):
    """Results remain measurements; this function never returns a HA pass."""
    mac = receipts["macbook-pro"]
    controls = mac.get("python_controls", [])
    matched = {}
    for alias in ("rog", "pocket4"):
        target = {"rog": "192.168.0.10:46231", "pocket4": "192.168.0.9:46231"}[alias]
        candidates = [row for row in controls if row.get("target") == target]
        control = candidates[0] if len(candidates) == 1 else {}
        accepts = [row for row in receipts[alias].get("accepted", []) if row.get("from_expected_mac")]
        matched[alias] = {
            "python_connected_once": control.get("submission_count") == 1 and control.get("connected") is True,
            "python_source_port_observed_by_listener": control.get("connected") is True and sum(
                row["source_port"] == control.get("source_port") for row in accepts) == 1,
            "other_mac_accepts": sum(row["source_port"] != control.get("source_port") for row in accepts),
        }
    return {"native_stage_counts": mac.get("native_stage_counts", {}), "per_target": matched,
            "remote_accepts_attributed_to_native_pid": False,
            "attribution_limit": "Other accepts are from the Mac IP in the owned window; no packet/PID attribution is inferred.",
            "process_specific_policy_cause_proven": False, "expected_tls_eof_is_ha_pass": False,
            "launcher_lifecycle_matches_original_daemon": False,
            "parent_lifetime_is_an_independent_variable": True,
            "ha_qualification": False, "original_lan98_passed": 36, "original_lan98_required": 98}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    agent, source = load_agent()
    agent.need(platform.system() == "Linux" and platform.node() == "qian-qi", "exact_main_controller_required")
    config = json.loads(args.input.read_text())
    agent.need(config["source_commit"] == "0f1c996136aae94e99c2b709a5797ffea479f6cd"
               and config["source_tree"] == "8befd5cedfb7ccafee5f707e5985d49eeb78fb60"
               and set(config["nodes"]) == set(agent.IPS), "exact_original_product_cohort_required")
    output = args.output
    agent.need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
               and not output.exists() and not output.is_symlink(), "new_controller_output_required")
    parent = output.parent.stat()
    agent.need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "owned_output_parent_required")
    output.mkdir(mode=0o700)
    os.umask(0o077)
    report = {"schema": "heptabao.native-lan-tcp-diagnostic-controller.v1", "status": "running",
              "driver_sha256": agent.digest(Path(__file__).read_bytes()), "agent_sha256": agent.digest(source),
              "input_sha256": agent.digest(args.input.read_bytes()), "source_commit": config["source_commit"],
              "source_tree": config["source_tree"], "native_binary_sha256": agent.ORIGINAL_BINARY_SHA,
              "actual_controller_hostname": platform.node(), "run_id": config["run_id"],
              "commands": [], "remote": {}, "production_authority": False, "ha_qualification": False,
              "original_lan98_passed": 36, "original_lan98_required": 98, "mutations_retried": False,
              "started_wall_time_ns": time.time_ns()}
    def save():
        pending = output / "summary.next"
        agent.new_file(pending, agent.canonical(report))
        os.replace(pending, output / "summary.json")
    payloads = {alias: {"alias": alias, "root": value["root"], "run_id": config["run_id"],
                        "agent_sha256": agent.digest(source)} for alias, value in config["nodes"].items()}
    save()
    active = {}
    try:
        # No listeners run during preparation. Each new-root mutation is one
        # SSH submission. Unknown outcomes are preserved and never restarted.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for alias, payload in payloads.items():
                expanded = {**payload, "agent_base64": base64.b64encode(source).decode("ascii")}
                futures[alias] = pool.submit(run_bounded, agent, ssh_command(alias, "prepare", expanded, prepare=True),
                                             output, alias + "-prepare", input_bytes=source, seconds=15)
            for alias, future in futures.items():
                command, messages = future.result()
                report["commands"].append(command)
                report["remote"][alias] = {"prepare": messages}
                save()
                agent.need(command["exit_code"] == 0 and command["completed_before_deadline"]
                           and len(messages) == 1 and messages[0].get("prepared") is True,
                           "single_prepare_failed_or_unknown_no_retry")
        started = time.monotonic()
        active_until = started + 35
        report["active_controller_deadline_seconds"] = 35
        def start(alias):
            label = alias + "-run"
            stream = (output / (label + ".stdout.jsonl")).open("xb")
            errors = (output / (label + ".stderr.log")).open("xb")
            # Intent is persisted before every actual child submission.
            row = {"label": label, "submission_count": 1, "automatic_retry": False, "state": "intent_saved"}
            report["commands"].append(row)
            save()
            child = subprocess.Popen(ssh_command(alias, "run", payloads[alias]), stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=errors, env=agent.ENV, start_new_session=True)
            stream.close()
            errors.close()
            # Record the returned Popen before any subsequent observation can
            # fail. A started SSH child is never lost from final reconciliation.
            active[alias] = (child, None, row)
            owner = agent.process_identity(child.pid)
            active[alias] = (child, owner, row)
            row.update(state="submitted", local_ssh_pid=child.pid)
            save()
        start("rog")
        start("pocket4")
        ready_until = started + 3
        ready = set()
        while time.monotonic() < ready_until:
            for alias in ("rog", "pocket4"):
                raw = (output / (alias + "-run.stdout.jsonl")).read_bytes()
                agent.need(len(raw) <= 65536, "bounded_ready_output_required")
                for line in raw.splitlines():
                    if not line.endswith(b"}"):
                        continue
                    if json.loads(line).get("ready") is True:
                        ready.add(alias)
            if len(ready) == 2:
                break
            time.sleep(0.03)
        agent.need(len(ready) == 2 and time.monotonic() < ready_until, "linux_ready_original_deadline_failed")
        start("macbook-pro")
        mac, _, row = active["macbook-pro"]
        report["mac_completed_before_control_window_end"] = wait_unreaped(mac, started + 23)
        save()
        for alias in ("rog", "pocket4"):
            child, _, row = active[alias]
            row["completed_before_active_deadline"] = wait_unreaped(child, active_until)
        agent.need(time.monotonic() < active_until, "original_active_controller_deadline_expired")
    except BaseException as error:
        report.update(status="failed_or_unknown", failure_code=str(error) if isinstance(error, agent.Refusal) else type(error).__name__)
    finally:
        for alias, (child, owner, row) in active.items():
            try:
                row["local_ssh_cleanup"] = agent.stop_unreaped_owned(child, owner or agent.process_identity(child.pid))
                row["exit_code"] = child.returncode
                row["state"] = "finished" if child.returncode == 0 else "failed_or_unknown"
            except BaseException as error:
                row["cleanup_error"] = str(error) if isinstance(error, agent.Refusal) else type(error).__name__
            save()
        # Collection is read-only. An absent summary stays absent: neither a
        # diagnostic start nor a connect is retried to produce a nicer receipt.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {alias: pool.submit(run_bounded, agent, ssh_command(alias, "collect", payload), output,
                                         alias + "-collect", seconds=10) for alias, payload in payloads.items()}
            for alias, future in futures.items():
                try:
                    command, messages = future.result()
                    report["commands"].append(command)
                    if command["exit_code"] == 0 and len(messages) == 1 and "summary" in messages[0]:
                        report["remote"].setdefault(alias, {})["collected"] = messages[0]
                except BaseException as error:
                    report["remote"].setdefault(alias, {})["collection_error"] = type(error).__name__
                save()
        receipts = {alias: value["collected"]["summary"] for alias, value in report["remote"].items() if "collected" in value}
        if set(receipts) == set(agent.IPS):
            report["comparison"] = projection(receipts)
            mac = receipts["macbook-pro"]
            complete = (not report.get("failure_code") and report.get("mac_completed_before_control_window_end") is True
                        and all(row.get("local_ssh_cleanup", {}).get("leader_reaped") is True
                                and row.get("local_ssh_cleanup", {}).get("owned_live_group_empty") is True
                                for row in report["commands"])
                        and all(value["status"] == "observed" and value["watchdog_identity_no_longer_running"] for value in receipts.values())
                        and all(receipts[alias].get("socket_closed") is True and receipts[alias].get("listener_original_deadline_observed") is True
                                for alias in ("rog", "pocket4"))
                        and mac.get("native_within_original_deadline") is True and mac.get("native_tls_listener_ready") is True
                        and mac.get("native_exited_early") is False and mac.get("original_binary_configs_and_copied_inputs_unchanged") is True
                        and mac.get("native_cleanup", {}).get("owned_live_group_empty") is True
                        and len(mac.get("python_controls", [])) == 2
                        and all(value.get("response_within_original_deadline") is True for value in mac["python_controls"]))
        else:
            complete = False
        report.update(status="observed_scoped_tcp_comparison" if complete else "failed_or_unknown",
                      diagnostic_complete=complete, finished_wall_time_ns=time.time_ns())
        save()
    print(json.dumps({"status": report["status"], "summary": str(output / "summary.json"),
                      "diagnostic_complete": report["diagnostic_complete"], "ha_qualification": False}), flush=True)
    return 0 if report["diagnostic_complete"] else 1


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise InterruptedError("owned_controller_interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
