#!/usr/bin/env python3
"""Run the native V6 physical profile with direct LAN API and Raft traffic.

Accepts the same source, build receipt, node and port bindings as the existing
native physical runner; --allow-private-lan is mandatory. SSH only installs
owned fixtures and controls their exact processes. No forwarding, route or
firewall changes are made. All 34 MiB, original-budget, mutation-once, failure,
cold-recovery and owned-cleanup checks remain mandatory.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import ssl
import sys

import native_v6_ha_multihost_live as native
import native_ha_foreground_watchdog as foreground

base = native.base
PEER_PREFLIGHT = Path(__file__).resolve().parents[2] / "tools/physical_ha_peer_preflight.py"
DIRECT_CHECKS = frozenset(
    (native.REQUIRED_CHECKS - {"complete_loopback_mesh"})
    | {"direct_lan_endpoints_configured"}
    | {f"direct_lan_mtls_{source}_to_{target}"
       for source in (1, 2, 3) for target in (1, 2, 3) if source != target}
    | {f"direct_lan_api_leaf_{node}" for node in (1, 2, 3)}
)


class DirectLanTransport:
    """Keep declared addresses intact; never create a tunnel child."""

    def configure_server(self, node, config):
        return config

    def configure(self, node, config):
        return config

    def start(self, nodes, work, event):
        for node in nodes:
            # Refuse an occupied or foreign-address endpoint before starting
            # the fixture; this grants no ownership of an existing listener.
            script = (
                "import socket\n"
                f"host={node.ip!r}\n"
                f"for port in {(node.api_port, node.raft_port)!r}:\n"
                "    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:\n"
                "        endpoint.bind((host, port))\n"
            )
            base.ssh(node, "python3 - <<'PY2'\n" + script + "PY2\n", timeout=15)
        event("direct_lan_endpoints_available", physical_hosts=3, tunnel_children=0)

    def stop(self, event):
        event("direct_lan_no_tunnel_children", tunnel_children=0)


class DirectLanRun(native.NativeRun):
    required_checks = DIRECT_CHECKS

    def __init__(self, *args):
        super().__init__(*args)
        self.foreground_sessions = {}
        self.foreground_helper = Path(foreground.__file__).resolve()
        self.foreground_nodes = []
        for path in (Path(__file__).resolve(), PEER_PREFLIGHT, self.foreground_helper):
            self.source_files[str(path)] = base.sha256_file(path)
        self.report.update({
            "schema": "heptabao.native-v6-direct-lan-ha.v1",
            "runner_sha256": base.sha256_file(Path(__file__)),
            "transport": "direct-private-lan-api-and-raft-mtls",
            "ssh_role": "owned-file-and-process-control-only",
            "tunnel_children": 0,
            "direct_peer_probe_scope": "six_real_mtls_handshakes_with_raft_alpn_and_leaf_pins",
            "scope": "synthetic-native-v6-direct-lan-original-budgets",
            "foreground_sessions": [],
            "foreground_scope": "actual-Darwin-native-only; Linux and standalone-V5 unchanged",
            "foreground_changes_product": False,
            "foreground_proves_original_network_cause": False,
        })

    def prepare(self):
        super().prepare()
        self.foreground_nodes = [node for node in self.nodes
                                 if self.hosts[node.alias]["system"] == "Darwin"]
        if len(self.foreground_nodes) != 1:
            raise base.FixtureError("foreground_requires_one_actual_darwin_node")
        for node in self.foreground_nodes:
            base.upload(node, self.foreground_helper,
                        node.root + "/native_ha_foreground_watchdog.py", 0o600)
            self.verify_foreground_helper(node)

    def verify_foreground_helper(self, node):
        # This is read-only source/interpreter inventory; no child or service is
        # started and no existing config, endpoint, permission or trust changes.
        script = (
            "import hashlib,json,os,pathlib,platform,sys\n"
            f"p=pathlib.Path({self.args.darwin_watchdog_python!r}).resolve(strict=True)\n"
            "assert p==pathlib.Path(sys.executable).resolve(strict=True)\n"
            "info=p.stat();assert info.st_size<=16*1024*1024\n"
            f"assert hashlib.sha256(p.read_bytes()).hexdigest()=={self.args.darwin_watchdog_python_sha256!r}\n"
            f"helper=pathlib.Path({node.root + '/native_ha_foreground_watchdog.py'!r})\n"
            "assert helper.is_file() and not helper.is_symlink() and helper.stat().st_size<=1024*1024\n"
            f"assert hashlib.sha256(helper.read_bytes()).hexdigest()=={self.source_files[str(self.foreground_helper)]!r}\n"
            "assert all(hasattr(os,k) for k in ('waitid','P_PID','WEXITED','WNOHANG','WNOWAIT',"
            "'CLD_EXITED','CLD_KILLED','CLD_DUMPED'))\n"
            "print(json.dumps({'executable':sys.executable,'realpath':str(p),'bytes':info.st_size,"
            "'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'version':platform.python_version(),"
            "'scope':'interpreter-binary-only-not-recursive-stdlib'}))\n"
        )
        result = json.loads(base.ssh(node, shlex.quote(self.args.darwin_watchdog_python)
                            + " -B - <<'PY2'\n" + script + "PY2\n", timeout=15))
        self.report["foreground_python_identity"] = result

    def owned_process_action(self, node, action, *, native=True):
        if action == "start" and native and node in self.foreground_nodes:
            if node.alias in self.foreground_sessions:
                raise base.FixtureError("foreground_unknown_start_must_not_repeat")
            session = foreground.ForegroundSession(
                node, self.run_id, self.work, self.expected[str(node.node_id)],
                self.foreground_helper, source_commit=self.args.source_commit,
                source_tree=self.args.source_tree, actual_host=self.hosts[node.alias],
                python_path=self.args.darwin_watchdog_python,
                python_sha256=self.args.darwin_watchdog_python_sha256)
            self.foreground_sessions[node.alias] = session
            self.report["foreground_sessions"].append(session.receipt)
            try:
                return session.start()
            except foreground.Refusal as error:
                raise base.FixtureError(str(error)) from error
        if action == "stop" and node.alias in self.foreground_sessions:
            session = self.foreground_sessions[node.alias]
            try:
                pid = session.stop()
            except foreground.Refusal as error:
                raise base.FixtureError(str(error)) from error
            del self.foreground_sessions[node.alias]
            return pid
        return super().owned_process_action(node, action, native=native)

    def request(self, *args, **kwargs):
        for session in self.foreground_sessions.values():
            try:
                session.assert_running()
            except foreground.Refusal as error:
                raise base.FixtureError(str(error)) from error
        return super().request(*args, **kwargs)

    def finish_application(self, leader):
        for node in self.foreground_nodes:
            self.verify_foreground_helper(node)
        return super().finish_application(leader)

    def transport_ready(self):
        self.check("direct_lan_endpoints_configured", all(
            node.api_connect_port is None for node in self.nodes),
            physical_hosts=3, tunnel_children=0,
            endpoints={str(node.node_id): {"api": node.api_origin,
                       "raft": f"{node.ip}:{node.raft_port}"} for node in self.nodes})

    def bootstrap_v5(self):
        leader = super().bootstrap_v5()
        self.stage = "direct_lan_peer_and_api_tls"
        manifest = self.work / "direct-peer-preflight-manifest.json"
        native.write_private(manifest, native.canonical({
            "cluster_id": self.cluster_id, "synthetic_only": True,
            "allow_production": False, "v6_ha_admitted": False,
        }) + b"\n")
        helper_sha = self.source_files[str(PEER_PREFLIGHT)]
        observations = []
        for node in self.nodes:
            helper = node.root + "/direct-peer-preflight.py"
            marker = node.root + "/direct-peer-preflight-manifest.json"
            base.upload(node, PEER_PREFLIGHT, helper, 0o600)
            base.upload(node, manifest, marker, 0o600)
            script = (
                "import hashlib,json,pathlib,runpy\n"
                f"helper=pathlib.Path({helper!r})\n"
                f"assert hashlib.sha256(helper.read_bytes()).hexdigest()=={helper_sha!r}\n"
                "module=runpy.run_path(str(helper))\n"
                f"config,_,root=module['load_fixture'](pathlib.Path({node.root!r}),"
                f"pathlib.Path({marker!r}))\n"
                "rows=[]\n"
                "for target in sorted(int(peer) for peer in config['peers']):\n"
                "    if target==config['node_id']: continue\n"
                "    row={'source':config['node_id'],'target':target,'passed':False}\n"
                "    try:\n"
                "        row['tls_version']=module['probe_peer'](config,root,target,2.0)\n"
                "        row['passed']=True\n"
                "    except module['Refusal'] as error: row['reason']=error.label\n"
                "    rows.append(row)\n"
                "print(json.dumps(rows,sort_keys=True))\n"
            )
            rows = json.loads(base.ssh(node, "python3 - <<'PY2'\n" + script + "PY2\n", timeout=15))
            if (not isinstance(rows, list) or len(rows) != 2
                    or {row.get("target") for row in rows}
                    != {peer.node_id for peer in self.nodes if peer != node}
                    or any(row.get("source") != node.node_id for row in rows)):
                raise base.FixtureError("direct_lan_probe_inventory_differs")
            observations.extend(rows)
        self.report["direct_peer_tls_observations"] = observations
        for row in observations:
            self.check(f"direct_lan_mtls_{row['source']}_to_{row['target']}",
                       row["passed"] is True, tls_version=row.get("tls_version"),
                       refusal=row.get("reason"))
        for node in self.nodes:
            # The HTTPS caller also pins the exact API leaf, in addition to
            # the ordinary CA and SAN checks used by all real API requests.
            context = ssl.create_default_context(cafile=str(self.work / "ca.crt"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((node.ip, node.api_port), timeout=2.0) as tcp:
                with context.wrap_socket(tcp, server_hostname=node.server_name) as tls:
                    leaf = tls.getpeercert(binary_form=True)
                    actual = hashlib.sha256(leaf).hexdigest() if leaf else None
            self.check(f"direct_lan_api_leaf_{node.node_id}",
                       actual == self.peers[str(node.node_id)]["certificate_sha256"],
                       observed_leaf_sha256=actual)
        return leader

    def check(self, name, condition, **details):
        super().check(name, condition, **details)
        # The parent calls this final case only after every required case and
        # owned cleanup passed. This flag is limited to this direct LAN profile;
        # full OpenBao compatibility and production authority remain false.
        if name == "native.complete" and condition is True:
            self.report["direct_lan_qualification"] = True


def parsed_arguments(argv=None):
    owner = argparse.ArgumentParser(add_help=False)
    owner.add_argument("--darwin-watchdog-python", required=True)
    owner.add_argument("--darwin-watchdog-python-sha256", required=True)
    owner_args, rest = owner.parse_known_args(argv)
    if (not Path(owner_args.darwin_watchdog_python).is_absolute()
            or re.fullmatch(r"[0-9a-f]{64}", owner_args.darwin_watchdog_python_sha256) is None):
        raise SystemExit("foreground owner requires the actual Darwin interpreter path and SHA256")
    args, nodes, _, sources, receipts, expected = native.parsed_arguments(rest)
    args.darwin_watchdog_python = owner_args.darwin_watchdog_python
    args.darwin_watchdog_python_sha256 = owner_args.darwin_watchdog_python_sha256
    if not args.allow_private_lan or args.allow_private_tailnet:
        raise SystemExit("direct native HA requires --allow-private-lan")
    ranges = tuple(ipaddress.ip_network(value) for value in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if any(not any(ipaddress.ip_address(node.ip) in network for network in ranges)
           for node in nodes):
        raise SystemExit("direct native HA requires three declared RFC1918 IPv4 endpoints")
    nodes = [replace(node, api_connect_port=None) for node in nodes]
    return args, nodes, DirectLanTransport(), sources, receipts, expected


def main(argv=None):
    return native.execute_fixture(*parsed_arguments(argv), run_type=DirectLanRun)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
