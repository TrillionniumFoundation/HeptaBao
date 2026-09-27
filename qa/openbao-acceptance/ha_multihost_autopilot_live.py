#!/usr/bin/env python3
"""Exercise bounded Autopilot cleanup on four private physical Linux hosts.

The fixture uses four pre-enrolled mTLS identities, removes one stopped voter
only after the persisted sixty-second grace, proves the remaining three-voter
quorum continues, and requires an explicit authenticated join before the old
host can participate again. It never changes firewall or system-service state,
never retries a mutation, and is scoped evidence rather than production or
OpenBao compatibility admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import ssl
import subprocess
import time
import urllib.error

from ha_multihost_live import (
    FixtureError,
    FixtureInterrupted,
    Node,
    REMOTE_EVIDENCE_FILES,
    api,
    checked_run,
    compress_candidate,
    copy_candidate_source,
    install_candidate,
    install_signal_handlers,
    openssl,
    parse_binary_source,
    parse_node,
    read_exact,
    remote_start,
    remote_stop,
    report_is_secret_safe,
    restore_signal_handlers,
    secret_safe_report,
    sha256_file,
    ssh,
    upload,
    wait_absent,
    wait_leader,
    wait_listener,
    write_once,
)

BASE_RUNNER_PATH = Path(__file__).resolve(strict=True).with_name("ha_multihost_live.py")
if not BASE_RUNNER_PATH.is_file() or BASE_RUNNER_PATH.is_symlink():
    raise RuntimeError("base multi-host runner dependency is unavailable")


REQUIRED_CHECKS = frozenset({
    "candidate_binary_digest",
    "node_1_private_root_and_ports", "node_1_binary_digest",
    "node_2_private_root_and_ports", "node_2_binary_digest",
    "node_3_private_root_and_ports", "node_3_binary_digest",
    "node_4_private_root_and_ports", "node_4_binary_digest",
    "seed_fresh_uninitialized", "seed_initialized_once", "seed_unsealed",
    "seed_cluster_identity", "seed_data_archive_nonempty",
    "node_2_cold_clone_installed", "node_3_cold_clone_installed",
    "node_4_cold_clone_installed", "four_host_raft_elected_before_unseal",
    "node_1_unsealed", "node_2_unsealed", "node_3_unsealed", "node_4_unsealed",
    "four_distinct_remote_hosts", "initial_four_voters_committed",
    "baseline_write_read_on_all_hosts",
    "unsafe_minimum_rejected", "too_short_dead_threshold_rejected",
    "autopilot_cleanup_policy_committed", "victim_selected_nonleader",
    "victim_stopped", "dead_voter_unhealthy_not_fabricated",
    "dead_voter_retained_during_grace",
    "dead_voter_removed_after_real_contact_threshold",
    "safe_three_voters_preserved", "survivors_write_after_cleanup",
    "removed_node_restarted_and_unsealed", "removed_node_never_self_rejoined",
    "removed_node_not_automatic_member",
    "explicit_rejoin_acknowledged_as_learner", "rejoined_node_caught_up",
    "rejoined_node_promoted_after_stabilization", "four_voters_restored",
    "explicit_remove_rejoined_node", "minimum_three_voters_preserved",
    "cannot_remove_below_minimum", "failover_after_autopilot_changes",
    "old_leader_restarted_and_unsealed",
    "autopilot_policy_persists_across_restart",
    "post_cleanup_write_read_all_survivors", "cleanup_baseline",
    "cleanup_after-cleanup", "synthetic_application_data_cleaned",
    "source_and_binary_unchanged", "report_excludes_runtime_secrets",
    "autopilot_multihost.complete",
})


def members(configuration: dict) -> set[int]:
    return {int(row["node_id"]) for row in configuration["servers"]}


def voters(configuration: dict) -> set[int]:
    return {int(row["node_id"]) for row in configuration["servers"] if row["voter"]}


def read_configuration(context: ssl.SSLContext, nodes: list[Node], token: str,
                       seconds: float = 45) -> tuple[Node, dict]:
    deadline = time.monotonic() + seconds
    last_leader: Node | None = None
    while time.monotonic() < deadline:
        remaining = max(3.0, deadline - time.monotonic())
        try:
            leader = wait_leader(context, nodes, token, seconds=min(remaining, 8.0))
            last_leader = leader
            status, response = api(
                context, leader, "GET", "sys/storage/raft/configuration",
                token=token, timeout=10,
            )
        except (FixtureError, OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
            continue
        value = response.get("data", {}).get("config", {})
        if (status == 200 and value.get("committed") is True
                and value.get("joint") is False
                and isinstance(value.get("index"), int)):
            return leader, value
        if status not in (200, 429, 503):
            raise FixtureError("configuration_read_failed")
        time.sleep(0.1)
    if last_leader is None:
        raise FixtureError("configuration_leader_unavailable")
    raise FixtureError("configuration_not_stable_committed")


def change_once(context: ssl.SSLContext, nodes: list[Node], token: str,
                action: str, node_id: int, **extra) -> tuple[int, dict]:
    leader, configuration = read_configuration(context, nodes, token)
    return api(
        context, leader, "POST", f"sys/storage/raft/{action}",
        {"server_id": str(node_id), "expected_index": configuration["index"], **extra},
        token=token, timeout=15,
    )


def wait_member(context: ssl.SSLContext, nodes: list[Node], token: str,
                node_id: int, *, present: bool, voter: bool | None = None,
                seconds: float = 80) -> tuple[Node, dict]:
    deadline = time.monotonic() + seconds
    last: tuple[Node, dict] | None = None
    while time.monotonic() < deadline:
        last = read_configuration(context, nodes, token)
        configuration = last[1]
        condition = (node_id in members(configuration)) is present
        if condition and voter is not None:
            condition = (node_id in voters(configuration)) is voter
        if condition:
            return last
        time.sleep(0.2)
    raise FixtureError("membership_transition_unobserved")


def wait_unhealthy(context: ssl.SSLContext, nodes: list[Node], token: str,
                   node_id: int, seconds: float = 15) -> tuple[Node, dict]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        leader = wait_leader(context, nodes, token, seconds=10)
        status, response = api(
            context, leader, "GET", "sys/storage/raft/autopilot/state",
            token=token, timeout=10,
        )
        data = response.get("data", {})
        server = data.get("servers", {}).get(str(node_id), {})
        if status == 200 and server.get("healthy") is False and data.get("healthy") is False:
            return leader, data
        time.sleep(0.2)
    raise FixtureError("dead_voter_health_transition_unobserved")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-source", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--node", action="append", required=True)
    parser.add_argument("--api-port", type=int, default=46240)
    parser.add_argument("--raft-port", type=int, default=46241)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--allow-private-tailnet", action="store_true")
    args = parser.parse_args()
    if not args.allow_private_tailnet:
        parser.error("explicit private tailnet scope is required")
    if len(args.node) != 4 or len(set(args.node)) != 4:
        parser.error("exactly four distinct nodes are required")
    if (re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None
            or re.fullmatch(r"[0-9a-f]{40}", args.source_tree) is None):
        parser.error("source commit and tree must be exact SHA-1 values")
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256) is None:
        parser.error("invalid binary SHA-256")
    if not (1024 <= args.api_port <= 65535 and 1024 <= args.raft_port <= 65535
            and args.api_port != args.raft_port):
        parser.error("invalid distinct private ports")
    if not args.work_root.is_absolute() or args.work_root.name in ("", ".", ".."):
        parser.error("work-root must be an absolute new canonical path")
    try:
        parent = args.work_root.parent.resolve(strict=True)
    except OSError:
        parser.error("work-root parent must already exist")
    work = parent / args.work_root.name
    parent_mode = parent.stat()
    if (str(work) != str(args.work_root) or work.exists() or not parent.is_dir()
            or parent_mode.st_uid != os.getuid() or parent_mode.st_mode & 0o022):
        parser.error("work-root parent must be canonical, owner-controlled and not broadly writable")
    os.umask(0o077)
    work.mkdir(mode=0o700)
    nodes = [parse_node(value, index + 1, args.api_port, args.raft_port)
             for index, value in enumerate(args.node)]
    if (len({node.alias for node in nodes}) != 4
            or len({node.ip for node in nodes}) != 4
            or len({(node.alias, node.root) for node in nodes}) != 4):
        parser.error("node aliases, IPs and per-host roots must be unique")

    checks: list[dict] = []
    events: list[dict] = []
    started: set[Node] = set()
    runner_path = Path(__file__).resolve(strict=True)
    initial_runner_sha256 = sha256_file(runner_path)
    initial_base_runner_sha256 = sha256_file(BASE_RUNNER_PATH)
    report = {
        "schema": "heptabao.multihost-autopilot.v1",
        "status": "failed",
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "binary_sha256": args.expected_binary_sha256,
        "runner_sha256": initial_runner_sha256,
        "base_runner_sha256": initial_base_runner_sha256,
        "required_check_count": len(REQUIRED_CHECKS),
        "host_count": 4,
        "transport": "private-tailnet-mtls",
        "checks": checks,
        "events": events,
        "qualification": False,
        "independent_qualification": False,
        "full_openbao_compatibility": False,
        "production_authority": False,
        "uncovered": [
            "mixed_version_autopilot", "WAN_faults", "physical_power_loss",
            "disk_full", "clock_discontinuity", "long_horizon_histories",
            "production_pki_and_custody",
        ],
    }

    def check(name: str, condition: bool, **metadata) -> None:
        row = {"case": name, "passed": condition is True, **metadata}
        checks.append(row)
        if condition is not True:
            raise FixtureError(name)

    def event(name: str, **metadata) -> None:
        events.append({"event": name, "time": time.time(), **metadata})

    local_binary = work / "heptabao-server"
    ca_key, ca_cert = work / "ca.key", work / "ca.crt"
    root_token = ""
    unseal_key = ""
    stage = "candidate_input"
    handlers = install_signal_handlers()
    try:
        try:
            source_alias, source_path = parse_binary_source(args.binary_source)
        except argparse.ArgumentTypeError as error:
            raise FixtureError("invalid_binary_source") from error
        stage = "candidate_copy"
        copy_candidate_source(source_alias, source_path, local_binary)
        local_binary.chmod(0o500)
        digest = sha256_file(local_binary)
        check("candidate_binary_digest", digest == args.expected_binary_sha256)
        payload = work / "heptabao-server.gz"
        compress_candidate(local_binary, payload)
        report["candidate_payload_sha256"] = sha256_file(payload)
        report["candidate_payload_bytes"] = payload.stat().st_size

        stage = "fixture_ca"
        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", str(ca_key), "-out", str(ca_cert),
            "-subj", "/CN=HeptaBao Synthetic Multi-Host Autopilot CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )
        ca_key.chmod(0o600)
        context = ssl.create_default_context(cafile=str(ca_cert))
        peers: dict[str, dict] = {}
        node_files: dict[Node, Path] = {}
        remote_hosts: dict[int, str] = {}
        stage = "remote_node_setup"
        for node in nodes:
            stage = f"remote_node_{node.node_id}_preflight"
            remote = ssh(node, f"""
set -eu
umask 077
test ! -e {shlex.quote(node.root)}
command -v setsid >/dev/null
python3 - <<PY2
import socket
ip={node.ip!r}
for port in ({node.api_port}, {node.raft_port}):
    s=socket.socket(); s.bind((ip,port)); s.close()
PY2
mkdir -m 700 {shlex.quote(node.root)}
hostname
""")
            remote_hosts[node.node_id] = remote.strip().splitlines()[-1]
            check(f"node_{node.node_id}_private_root_and_ports", True)
            stage = f"remote_node_{node.node_id}_certificates"
            node_dir = work / node.name
            node_dir.mkdir(mode=0o700)
            node_files[node] = node_dir
            key, csr, cert, ext = (
                node_dir / name for name in ("tls.key", "tls.csr", "tls.crt", "tls.ext")
            )
            openssl(
                "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(csr),
                "-subj", f"/CN={node.server_name}",
            )
            key.chmod(0o600)
            ext.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth,clientAuth\n"
                f"subjectAltName=DNS:{node.server_name},IP:{node.ip}\n"
            )
            openssl(
                "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert),
                "-days", "2", "-sha256", "-extfile", str(ext),
            )
            cert.chmod(0o600)
            fingerprint = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(cert.read_text())
            ).hexdigest()
            peers[str(node.node_id)] = {
                "node_name": node.name,
                "address": f"{node.ip}:{node.raft_port}",
                "api_address": node.api_origin,
                "server_name": node.server_name,
                "certificate_sha256": fingerprint,
            }
            server = {
                "listen": f"{node.ip}:{node.api_port}",
                "data_dir": f"{node.root}/data",
                "audit_file": f"{node.root}/audit.jsonl",
                "tls_cert_file": f"{node.root}/tls.crt",
                "tls_key_file": f"{node.root}/tls.key",
                "max_connections": 64,
                "timeout_seconds": 12,
                "rate_limit_per_second": 2000,
                "rate_limit_burst": 4000,
                "rate_limit_entries": 512,
                "lifecycle_interval_seconds": 1,
            }
            server_path = node_dir / "server.json"
            server_path.write_text(json.dumps(server, sort_keys=True))
            server_path.chmod(0o600)
            stage = f"remote_node_{node.node_id}_candidate_install"
            install_candidate(node, payload, digest)
            stage = f"remote_node_{node.node_id}_configuration_upload"
            upload(node, ca_cert, f"{node.root}/ca.crt", 0o600)
            upload(node, cert, f"{node.root}/tls.crt", 0o600)
            upload(node, key, f"{node.root}/tls.key", 0o600)
            upload(node, server_path, f"{node.root}/server.json", 0o600)
            stage = f"remote_node_{node.node_id}_binary_readback"
            remote_digest = ssh(
                node,
                "sha256sum " + shlex.quote(node.root + "/heptabao-server")
                + " | cut -d ' ' -f1",
            ).strip()
            check(f"node_{node.node_id}_binary_digest", remote_digest == digest)

        stage = "single_node_initialization"
        seed = nodes[0]
        seed_pid = remote_start(seed, ha=False)
        started.add(seed)
        event("seed_started", node=seed.node_id, pid=seed_pid)
        status, _ = wait_listener(context, seed)
        check("seed_fresh_uninitialized", status == 501)
        status, initialized = api(
            context, seed, "POST", "sys/init",
            {"secret_shares": 1, "secret_threshold": 1},
        )
        root_token = initialized.get("root_token", "")
        keys = initialized.get("keys_base64", [])
        check(
            "seed_initialized_once",
            status == 200 and isinstance(root_token, str) and bool(root_token)
            and isinstance(keys, list) and len(keys) == 1,
        )
        unseal_key = keys[0]
        status, _ = api(context, seed, "POST", "sys/unseal", {"key": unseal_key})
        check("seed_unsealed", status == 200)
        status, health = api(context, seed, "GET", "sys/health")
        cluster_id = health.get("cluster_id")
        check(
            "seed_cluster_identity",
            status == 200 and isinstance(cluster_id, str) and bool(cluster_id),
        )
        remote_stop(seed)
        started.discard(seed)
        event("seed_stopped_for_cold_clone", node=seed.node_id)

        stage = "encrypted_state_clone"
        seed_tar = work / "seed-data.tgz"
        with seed_tar.open("wb") as stream:
            checked_run(
                ["ssh", seed.alias, "tar", "-C", seed.root, "-czf", "-", "data"],
                timeout=180, stdout=stream,
            )
        check("seed_data_archive_nonempty", seed_tar.stat().st_size > 0)
        for node in nodes[1:]:
            upload(node, seed_tar, f"{node.root}/seed-data.tgz", 0o600)
            ssh(node, f"""
set -eu
root={shlex.quote(node.root)}
test ! -e "$root/data"
tar -xzf "$root/seed-data.tgz" -C "$root"
rm "$root/seed-data.tgz"
test -d "$root/data"
""")
            check(f"node_{node.node_id}_cold_clone_installed", True)

        stage = "ha_configuration"
        replication = work / "replication.key"
        replication.write_bytes(secrets.token_bytes(32))
        replication.chmod(0o600)
        for node in nodes:
            ha = {
                "node_id": node.node_id,
                "cluster_id": cluster_id,
                "raft_dir": f"{node.root}/raft",
                "listen": f"{node.ip}:{node.raft_port}",
                "ca_file": f"{node.root}/ca.crt",
                "cert_file": f"{node.root}/tls.crt",
                "key_file": f"{node.root}/tls.key",
                "replication_key_file": f"{node.root}/replication.key",
                "peers": peers,
                "bootstrap": node.node_id == 1,
                "initial_voters": [1, 2, 3, 4],
                "peer_timeout_ms": 1500,
                "forward_timeout_ms": 8000,
                "max_inflight": 32,
            }
            ha_path = node_files[node] / "ha.json"
            ha_path.write_text(json.dumps(ha, sort_keys=True))
            ha_path.chmod(0o600)
            upload(node, replication, f"{node.root}/replication.key", 0o600)
            upload(node, ha_path, f"{node.root}/ha.json", 0o600)

        stage = "ha_startup"
        for node in nodes[1:] + nodes[:1]:
            pid = remote_start(node, ha=True)
            started.add(node)
            event("ha_node_started", node=node.node_id, pid=pid)
        for node in nodes:
            wait_listener(context, node)
        deadline = time.monotonic() + 45
        active = 0
        while time.monotonic() < deadline:
            active = 0
            for node in nodes:
                try:
                    _, body = api(context, node, "GET", "sys/health", timeout=2)
                    active += body.get("ha_active") is True
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    pass
            if active == 1:
                break
            if active > 1:
                raise FixtureError("multiple_leaders_before_unseal")
            time.sleep(0.1)
        check("four_host_raft_elected_before_unseal", active == 1)
        for node in nodes:
            status, _ = api(
                context, node, "POST", "sys/unseal", {"key": unseal_key}, timeout=10
            )
            check(f"node_{node.node_id}_unsealed", status == 200)
        leader = wait_leader(context, nodes, root_token)
        check("four_distinct_remote_hosts", len(set(remote_hosts.values())) == 4)
        leader, initial_configuration = read_configuration(
            context, nodes, root_token, seconds=60,
        )
        check(
            "initial_four_voters_committed",
            members(initial_configuration) == {1, 2, 3, 4}
            and voters(initial_configuration) == {1, 2, 3, 4},
        )

        stage = "baseline_replication"
        nonce = secrets.token_hex(12)
        baseline_path = f"mh-auto-{nonce}/baseline"
        baseline_value = secrets.token_hex(16)
        write_once(context, leader, root_token, baseline_path, baseline_value)
        for node in nodes:
            read_exact(context, node, root_token, baseline_path, baseline_value)
        check("baseline_write_read_on_all_hosts", True)

        stage = "autopilot_policy"
        status, _ = api(
            context, leader, "POST", "sys/storage/raft/autopilot/configuration",
            {"min_quorum": 2}, token=root_token,
        )
        check("unsafe_minimum_rejected", status == 400)
        status, _ = api(
            context, leader, "POST", "sys/storage/raft/autopilot/configuration",
            {"dead_server_last_contact_threshold": "1s"}, token=root_token,
        )
        check("too_short_dead_threshold_rejected", status == 400)
        policy = {
            "cleanup_dead_servers": True,
            "last_contact_threshold": "2s",
            "dead_server_last_contact_threshold": "60s",
            "server_stabilization_time": "3s",
            "min_quorum": 3,
        }
        status, _ = api(
            context, leader, "POST", "sys/storage/raft/autopilot/configuration",
            policy, token=root_token,
        )
        status_read, readback = api(
            context, leader, "GET", "sys/storage/raft/autopilot/configuration",
            token=root_token,
        )
        data = readback.get("data", {})
        check(
            "autopilot_cleanup_policy_committed",
            status == 204 and status_read == 200
            and data.get("cleanup_dead_servers") is True
            and data.get("dead_server_last_contact_threshold") == "60s"
            and data.get("server_stabilization_time") == "3s"
            and data.get("min_quorum") == 3,
        )

        stage = "dead_voter_cleanup"
        victim = nodes[3] if nodes[3] != leader else nodes[2]
        check("victim_selected_nonleader", victim != leader)
        victim_pid = remote_stop(victim)
        started.discard(victim)
        event("autopilot_victim_stopped", node=victim.node_id, pid=victim_pid)
        check("victim_stopped", victim_pid is not None)
        _, state = wait_unhealthy(context, [node for node in nodes if node != victim],
                                  root_token, victim.node_id)
        check(
            "dead_voter_unhealthy_not_fabricated",
            state["servers"][str(victim.node_id)]["healthy"] is False
            and state["healthy"] is False,
        )
        _, grace_configuration = read_configuration(
            context, [node for node in nodes if node != victim], root_token
        )
        check(
            "dead_voter_retained_during_grace",
            victim.node_id in voters(grace_configuration),
        )
        survivors = [node for node in nodes if node != victim]
        leader, cleaned = wait_member(
            context, survivors, root_token, victim.node_id,
            present=False, seconds=82,
        )
        check(
            "dead_voter_removed_after_real_contact_threshold",
            victim.node_id not in members(cleaned),
        )
        survivor_ids = {node.node_id for node in survivors}
        check("safe_three_voters_preserved", voters(cleaned) == survivor_ids)
        after_path = f"mh-auto-{nonce}/after-cleanup"
        after_value = secrets.token_hex(16)
        write_once(context, leader, root_token, after_path, after_value)
        for node in survivors:
            read_exact(context, node, root_token, after_path, after_value)
        check("survivors_write_after_cleanup", True)

        stage = "removed_node_restart"
        pid = remote_start(victim, ha=True)
        started.add(victim)
        event("removed_victim_restarted", node=victim.node_id, pid=pid)
        wait_listener(context, victim)
        status, _ = api(
            context, victim, "POST", "sys/unseal", {"key": unseal_key}, timeout=10
        )
        check("removed_node_restarted_and_unsealed", status == 200)
        deadline = time.monotonic() + 5
        self_active = False
        while time.monotonic() < deadline:
            try:
                health_status, health = api(
                    context, victim, "GET", "sys/health", timeout=2
                )
                if health_status == 200 and health.get("ha_active") is True:
                    self_active = True
                    break
            except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                pass
            time.sleep(0.2)
        check("removed_node_never_self_rejoined", not self_active)
        leader, configuration = read_configuration(context, survivors, root_token)
        check("removed_node_not_automatic_member", victim.node_id not in members(configuration))

        stage = "explicit_rejoin"
        status, _ = change_once(
            context, survivors, root_token, "join", victim.node_id, non_voter=False
        )
        _, joined = wait_member(
            context, nodes, root_token, victim.node_id,
            present=True, voter=False, seconds=20,
        )
        check(
            "explicit_rejoin_acknowledged_as_learner",
            status == 200 and victim.node_id in members(joined)
            and victim.node_id not in voters(joined),
        )
        read_exact(context, victim, root_token, after_path, after_value, seconds=45)
        check("rejoined_node_caught_up", True)
        _, promoted = wait_member(
            context, nodes, root_token, victim.node_id,
            present=True, voter=True, seconds=30,
        )
        check("rejoined_node_promoted_after_stabilization", victim.node_id in voters(promoted))
        check("four_voters_restored", voters(promoted) == {1, 2, 3, 4})

        stage = "return_to_minimum"
        status, _ = change_once(context, nodes, root_token, "remove-peer", victim.node_id)
        _, reduced = wait_member(
            context, survivors, root_token, victim.node_id,
            present=False, seconds=20,
        )
        check("explicit_remove_rejoined_node", status == 200 and victim.node_id not in members(reduced))
        remote_stop(victim)
        started.discard(victim)
        check("minimum_three_voters_preserved", voters(reduced) == survivor_ids)
        leader, configuration = read_configuration(context, survivors, root_token)
        target = next(node for node in survivors if node != leader)
        status, _ = api(
            context, leader, "POST", "sys/storage/raft/remove-peer",
            {"server_id": str(target.node_id), "expected_index": configuration["index"]},
            token=root_token, timeout=15,
        )
        check("cannot_remove_below_minimum", status == 409)

        stage = "post_cleanup_failover"
        old_leader = leader
        killed = remote_stop(old_leader)
        started.discard(old_leader)
        event("leader_stopped_after_autopilot", node=old_leader.node_id, pid=killed)
        successor = wait_leader(
            context, [node for node in survivors if node != old_leader],
            root_token, previous=old_leader,
        )
        check("failover_after_autopilot_changes", successor != old_leader)
        remote_start(old_leader, ha=True)
        started.add(old_leader)
        wait_listener(context, old_leader)
        status, _ = api(
            context, old_leader, "POST", "sys/unseal", {"key": unseal_key}, timeout=10
        )
        check("old_leader_restarted_and_unsealed", status == 200)
        read_exact(context, old_leader, root_token, after_path, after_value, seconds=45)
        current = wait_leader(context, survivors, root_token)
        status, policy_readback = api(
            context, current, "GET", "sys/storage/raft/autopilot/configuration",
            token=root_token,
        )
        policy_data = policy_readback.get("data", {})
        check(
            "autopilot_policy_persists_across_restart",
            status == 200 and policy_data.get("cleanup_dead_servers") is True
            and policy_data.get("dead_server_last_contact_threshold") == "60s"
            and policy_data.get("min_quorum") == 3,
        )
        post_path = f"mh-auto-{nonce}/post-autopilot"
        post_value = secrets.token_hex(16)
        write_once(context, current, root_token, post_path, post_value)
        for node in survivors:
            read_exact(context, node, root_token, post_path, post_value)
        check("post_cleanup_write_read_all_survivors", True)

        stage = "application_cleanup"
        for name, path in (("baseline", baseline_path), ("after-cleanup", after_path)):
            status, _ = api(
                context, current, "DELETE", f"secret/metadata/{path}",
                token=root_token, timeout=12,
            )
            check(f"cleanup_{name}", status == 204)
        status, _ = api(
            context, current, "DELETE", f"secret/metadata/{post_path}",
            token=root_token, timeout=12,
        )
        if status != 204:
            raise FixtureError("post_autopilot_cleanup_failed")
        for node in survivors:
            for path in (baseline_path, after_path, post_path):
                wait_absent(context, node, root_token, path)
        check("synthetic_application_data_cleaned", True)

        stage = "final_integrity"
        remote_digests = {
            str(node.node_id): ssh(
                node,
                "sha256sum " + shlex.quote(node.root + "/heptabao-server")
                + " | cut -d ' ' -f1",
            ).strip()
            for node in nodes
        }
        unchanged = (
            sha256_file(local_binary) == args.expected_binary_sha256
            and sha256_file(runner_path) == initial_runner_sha256
            and sha256_file(BASE_RUNNER_PATH) == initial_base_runner_sha256
            and set(remote_digests.values()) == {args.expected_binary_sha256}
        )
        check("source_and_binary_unchanged", unchanged)
        check("report_excludes_runtime_secrets", report_is_secret_safe(report, (root_token, unseal_key)))
        observed = [row.get("case") for row in checks]
        check(
            "autopilot_multihost.complete",
            len(observed) == len(set(observed))
            and set(observed) == REQUIRED_CHECKS - {"autopilot_multihost.complete"}
            and all(row.get("passed") is True for row in checks),
        )
        final_names = [row.get("case") for row in checks]
        if len(final_names) != len(set(final_names)) or set(final_names) != REQUIRED_CHECKS:
            raise FixtureError("autopilot_multihost_check_denominator_mismatch")
        final_leader = wait_leader(context, survivors, root_token)
        report.update({
            "status": "passed",
            "cluster_id_sha256": hashlib.sha256(cluster_id.encode()).hexdigest(),
            "victim_node_id": victim.node_id,
            "final_leader": final_leader.node_id,
            "remote_hosts": remote_hosts,
            "root_locations": {str(node.node_id): node.root for node in nodes},
            "binary_identical_on_all_hosts": True,
            "source_and_binary_unchanged": unchanged,
            "remote_binary_sha256": remote_digests,
            "mutating_requests_retried": False,
            "synthetic_cleanup": True,
            "dead_cleanup_threshold_seconds": 60,
            "minimum_voters": 3,
        })
    except FixtureInterrupted:
        report["failure_code"] = f"{stage}_controller_interrupted"
    except FixtureError as error:
        report["failure_code"] = str(error)
    except subprocess.SubprocessError:
        report["failure_code"] = f"{stage}_subprocess_failure"
    except (OSError, ssl.SSLError, urllib.error.URLError,
            TimeoutError, ValueError, KeyError, json.JSONDecodeError) as error:
        report["failure_code"] = f"{stage}_{type(error).__name__}"
    finally:
        restore_signal_handlers(handlers)
        for node in reversed(nodes):
            try:
                if node in started:
                    pid = remote_stop(node)
                    event("final_process_stop", node=node.node_id, pid=pid)
            except Exception:
                report.setdefault("cleanup_failure", []).append(node.node_id)
        for node in nodes:
            local = work / f"remote-{node.node_id}"
            local.mkdir(exist_ok=True)
            try:
                names = ssh(node, f"""
set -eu
root={shlex.quote(node.root)}
test -d "$root" || exit 0
for name in {' '.join(shlex.quote(name) for name in REMOTE_EVIDENCE_FILES)}; do
  test -f "$root/$name" && printf '%s\n' "$name"
done
""", timeout=12).splitlines()
            except (OSError, subprocess.SubprocessError):
                continue
            for name in names:
                if name not in REMOTE_EVIDENCE_FILES:
                    continue
                try:
                    checked_run([
                        "scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                        "-o", "ConnectionAttempts=1", "-p",
                        f"{node.alias}:{node.root}/{name}", str(local / name),
                    ], timeout=30)
                except subprocess.SubprocessError:
                    pass
        report = secret_safe_report(report, (root_token, unseal_key))
        root_token = ""
        unseal_key = ""
        summary = work / "summary.json"
        summary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        summary.chmod(0o600)
        print(json.dumps({
            "status": report["status"], "checks": len(checks),
            "failure_code": report.get("failure_code"),
        }, sort_keys=True))
    return 0 if (
        report["status"] == "passed"
        and len(checks) == len(REQUIRED_CHECKS)
        and {row.get("case") for row in checks} == REQUIRED_CHECKS
        and all(row.get("passed") is True for row in checks)
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
