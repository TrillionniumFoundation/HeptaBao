#!/usr/bin/env python3
"""Execute real Mac/ROG/Pocket4 HA with a complete loopback SSH mesh.

Run on the coordinator with the same arguments as ha_multihost_live.py.
All three node roots must be NEW; existing fixtures/services are never stopped.
The tested lifecycle includes leader SIGKILL, new election, quorum loss,
ReadIndex-backed readback, snapshot catch-up and all-voter persistent restart.
Only the controller's three SSH children and its newly created node PIDs are
stopped. Physical voters remain separate; direct-LAN qualification is excluded.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import ha_multihost_live as base

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from physical_ha_loopback_mesh import mesh_plan


class CompleteLoopbackMesh:
    runner_path = __file__

    def __init__(self, local_base=55200, reverse_base=55300, api_base=55400):
        self.local_base = local_base
        self.reverse_base = reverse_base
        self.api_base = api_base
        self.processes = []

    def prepare_nodes(self, nodes):
        ports = [self.api_base+i for i in (1, 2, 3)]
        used = [nodes[0].api_port, nodes[0].raft_port,
                *[self.local_base+i for i in (1, 2, 3)],
                *[self.reverse_base+i for i in (1, 2, 3)]]
        if any(not 1024 <= port <= 65535 for port in ports) or set(ports) & set(used):
            raise base.FixtureError("invalid_loopback_api_ports")
        return [replace(node, api_connect_port=self.api_base+node.node_id) for node in nodes]

    def configure_server(self, node, config):
        return {**config, "listen": f"127.0.0.1:{node.api_port}"}

    def configure(self, node, config):
        changed = copy.deepcopy(config)
        changed["listen"] = f"127.0.0.1:{node.raft_port}"
        for peer_id, peer in changed["peers"].items():
            target_port = node.raft_port if int(peer_id) == node.node_id else self.reverse_base+int(peer_id)
            peer["address"] = f"127.0.0.1:{target_port}"
        return changed

    def start(self, nodes, work, event):
        if (len(nodes) != 3 or {node.node_id for node in nodes} != {1, 2, 3}
                or len({node.raft_port for node in nodes}) != 1):
            raise base.FixtureError("exact_three_node_mesh_required")
        plan = mesh_plan([node.alias for node in nodes], nodes[0].raft_port,
                         self.local_base, self.reverse_base)
        (work/"loopback-mesh-plan.json").write_text(json.dumps(plan, indent=2)+"\n")
        # Refuse occupied endpoints before starting any of this controller's SSH
        # children. A later race still fails via ExitOnForwardFailure=yes.
        for node in nodes:
            for port in (self.local_base+node.node_id, self.api_base+node.node_id):
                with socket.socket() as endpoint:
                    endpoint.bind(("127.0.0.1", port))
            ports = [self.reverse_base+peer for peer in (1, 2, 3) if peer != node.node_id]
            base.ssh(node, "python3 - <<'PY2'\nimport socket\n"
                     + f"for port in {ports!r}:\n"
                     + "    s=socket.socket(); s.bind(('127.0.0.1',port)); s.close()\nPY2\n",
                     timeout=15)
        for command in plan["commands"]:
            node = next(n for n in nodes if n.node_id == command["node_id"])
            command["args"][-1:-1] = ["-L", f"127.0.0.1:{self.api_base+node.node_id}:127.0.0.1:{node.api_port}"]
            output_path = work/f"ssh-mesh-node-{command['node_id']}.log"
            with output_path.open("xb") as output:
                child = subprocess.Popen([command["executable"], *command["args"]],
                                         stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                         start_new_session=True, close_fds=True)
            self.processes.append((command["node_id"], child))
            time.sleep(1)
            if child.poll() is not None:
                raise base.FixtureError(f"loopback_mesh_node_{command['node_id']}_ssh_failed")
            event("loopback_mesh_ssh_started", node=command["node_id"], pid=child.pid)
        if any(child.poll() is not None for _, child in self.processes):
            raise base.FixtureError("loopback_mesh_lost_before_raft_start")
        (work/"loopback-mesh-plan.json").write_text(json.dumps(plan, indent=2)+"\n")

    def stop(self, event):
        failed = False
        for node_id, child in reversed(self.processes):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        failed = True
            event("loopback_mesh_ssh_stopped", node=node_id, pid=child.pid,
                  exited=child.poll() is not None)
        if failed:
            raise base.FixtureError("owned_mesh_cleanup_failed")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mesh-local-port-base", type=int, default=55200)
    parser.add_argument("--mesh-reverse-port-base", type=int, default=55300)
    parser.add_argument("--mesh-api-port-base", type=int, default=55400)
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    return base.main(mesh=CompleteLoopbackMesh(args.mesh_local_port_base, args.mesh_reverse_port_base,
                                             args.mesh_api_port_base),
                     full_restart=True)


if __name__ == "__main__":
    raise SystemExit(main())
