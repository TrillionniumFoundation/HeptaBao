"""Isolated macOS HA fixture supervision with the original SSH parent kept alive.

The normal product does not use this helper. No macOS TCC/VPN/firewall change,
new API authority, request retry or storage permission is granted here.
The remote service remains a child of the foreground SSH command until its
precisely scoped fixture stop completes; detached launchd agents are excluded.
"""
from __future__ import annotations

import re
import select
import shlex
import subprocess


class HeldMacFixtureError(RuntimeError):
    """Static, credential-free fixture failure classification."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def validate(alias: str, root: str, sha256: str) -> None:
    if alias != "mac-ts":
        raise HeldMacFixtureError("mac_ssh_alias_not_admitted")
    if (not isinstance(root, str)
            or not root.startswith("/Volumes/T5/hepta-vnext/HeptaBao-")
            or len(root) > 200
            or any(part in ("", ".", "..") for part in root.split("/")[1:])
            or any(ord(c) < 33 or ord(c) > 126 for c in root)):
        raise HeldMacFixtureError("mac_fixture_root_not_admitted")
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
        raise HeldMacFixtureError("mac_binary_digest_not_admitted")


def startup_script(root: str, digest: str, *, ha: bool) -> str:
    validate("mac-ts", root, digest)
    quoted_root = shlex.quote(root)
    extra = ' --ha-config "$root/ha.json"' if ha else ""
    required_ha = 'test -f "$root/ha.json"' if ha else ":"
    # Bash owns the child and waits in the SAME SSH session. No nohup, setsid,
    # exec-detach, start_new_session or launchd policy alteration.
    return f"""set -eu
umask 077
root={quoted_root}
test -x "$root/heptabao-server"
test -f "$root/server.json"
{required_ha}
test ! -e "$root/process.pid"
actual=$(shasum -a 256 "$root/heptabao-server")
actual=${{actual%% *}}
test "$actual" = {digest}
"$root/heptabao-server" --config "$root/server.json"{extra} >>"$root/process.log" 2>&1 </dev/null &
pid=$!
printf '%s\\n' "$pid" > "$root/process.pid.tmp"
mv "$root/process.pid.tmp" "$root/process.pid"
printf '%s %s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pid" >> "$root/pids.log"
sleep 0.4
kill -0 "$pid"
parent=$(ps -p "$pid" -o ppid= | tr -d ' ')
test "$parent" = "$$"
printf '%s %s\\n' "$pid" "$parent"
wait "$pid" || :
"""


class HeldMacSshParent:
    """One Mac fixture child, its original SSH process and one final wait."""

    def __init__(self, alias: str, root: str, sha256: str):
        validate(alias, root, sha256)
        self.alias = alias
        self.root = root
        self.sha256 = sha256
        self.process = None
        self.pid = None
        self.parent = None

    def start(self, *, ha: bool, deadline_seconds: float = 15) -> int:
        if self.process is not None or self.pid is not None:
            raise HeldMacFixtureError("mac_fixture_duplicate_start")
        if not 0 < deadline_seconds <= 30:
            raise HeldMacFixtureError("mac_fixture_unbounded_start")
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "-T", self.alias, "bash", "-s"]
        p = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            p.stdin.write(startup_script(self.root, self.sha256, ha=ha))
            p.stdin.close()
            p.stdin = None
            ready, _, _ = select.select([p.stdout], [], [], deadline_seconds)
            if not ready:
                raise HeldMacFixtureError("mac_held_ssh_parent_timeout")
            row = p.stdout.readline().strip().split()
            if len(row) != 2:
                raise HeldMacFixtureError("mac_held_ssh_parent_missing")
            pid, parent = (int(row[0]), int(row[1]))
            if pid <= 1 or parent <= 1 or p.poll() is not None:
                raise HeldMacFixtureError("mac_held_ssh_parent_invalid")
        except BaseException:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
            p.stdout.close()
            p.stderr.close()
            raise
        self.process = p
        self.pid = pid
        self.parent = parent
        return pid

    def settle_after_verified_remote_stop(self) -> None:
        # The caller first stops the exact fixture-owned PID using the preexisting
        # executable/config identity guard. This never kills a remote PID.
        p = self.process
        if p is None:
            raise HeldMacFixtureError("mac_fixture_ssh_owner_missing")
        self.process = None
        try:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
                raise HeldMacFixtureError("mac_fixture_ssh_parent_failed_to_exit")
        finally:
            p.stdout.close()
            p.stderr.close()
