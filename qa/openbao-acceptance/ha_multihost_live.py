#!/usr/bin/env python3
"""Run a private synthetic three-host HeptaBao HA lifecycle over a tailnet or LAN.

The runner creates new owner-only roots, transfers one checksum-bound candidate,
uses a fixture-only CA, performs no firewall or system-service changes, attempts
every mutation once, and stops only PIDs whose executable and config paths match
the generated fixture. It is scoped evidence, not production qualification.
"""
from __future__ import annotations

import argparse
import gzip
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import shlex
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from fixture_mounts import completed_kv2_mount_metadata, provision_secret_kv2

MAX_BODY = 32 * 1024 * 1024
TAILNET = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_LAN = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
FORBIDDEN_REPORT_KEYS = frozenset({
    "root_token", "unseal_key", "replication_key", "ca_private_key",
    "tls_private_key", "private_key", "client_token", "service_account_token",
    "password", "bearer", "token",
})
SAFE_RESPONSE_ERRORS = {
    "HA cluster has no elected leader": "ha_no_elected_leader",
    "HA committed application state is absent": "ha_committed_application_absent",
    "HA control state is unavailable": "ha_control_unavailable",
    "HA leader forwarding failed": "ha_leader_forwarding_failed",
    "HA leader state is unavailable": "ha_leader_state_unavailable",
    "HA linearizable state is unavailable": "ha_linearizable_unavailable",
    "HA local identity is unavailable": "ha_local_identity_unavailable",
    "HA process lock is unavailable": "ha_process_lock_unavailable",
    "forwarded request reached a standby node": "forwarded_request_reached_standby",
    "server is sealed": "server_sealed",
}
REMOTE_EVIDENCE_FILES = (
    "process.log", "pids.log", "server.json", "ha.json", "audit.jsonl",
    "process.identity.json",
)
REQUIRED_CHECKS = frozenset({
    'candidate_binary_digest',
    'node_1_private_root_and_ports',
    'node_1_binary_digest',
    'node_2_private_root_and_ports',
    'node_2_binary_digest',
    'node_3_private_root_and_ports',
    'node_3_binary_digest',
    'seed_fresh_uninitialized',
    'seed_initialized_once',
    'seed_unsealed',
    'seed_cluster_identity',
    'seed_data_archive_nonempty',
    'node_2_cold_clone_installed',
    'node_3_cold_clone_installed',
    'three_host_raft_elected_before_unseal',
    'node_1_unsealed',
    'node_2_unsealed',
    'node_3_unsealed',
    'three_distinct_remote_hosts',
    'baseline_write_read_on_all_hosts',
    'remote_standby_write_forwarded',
    'leader_snapshot_trigger',
    'offline_follower_restarted_and_unsealed',
    'remote_snapshot_catchup',
    'leader_changed_after_remote_sigkill',
    'post_failover_write_on_survivors',
    'old_leader_restarted_and_unsealed',
    'old_leader_caught_up',
    'explicit_step_down_accepted_once',
    'three_leadership_epochs_preserve_data',
    'single_survivor_loses_authority',
    'quorum_loss_write_denied_without_data',
    'quorum_peer_restarted',
    'denied_quorum_write_has_no_effect',
    'final_peer_restarted',
    'all_hosts_rejoined_after_quorum_recovery',
    'cleanup_baseline',
    'cleanup_forwarded',
    'cleanup_snapshot-0',
    'cleanup_snapshot-1',
    'cleanup_snapshot-2',
    'cleanup_snapshot-3',
    'cleanup_snapshot-4',
    'cleanup_snapshot-5',
    'cleanup_snapshot-6',
    'cleanup_snapshot-7',
    'cleanup_after-snapshot',
    'cleanup_after-failover',
    'cleanup_after-stepdown',
    'cleanup_quorum-recovered',
    'synthetic_application_data_cleaned',
    'source_and_binary_unchanged',
    'report_excludes_runtime_secrets',
    'multihost.complete',
})


class FixtureError(RuntimeError):
    pass


class FixtureInterrupted(FixtureError):
    pass


def response_failure_code(status: int, body: dict) -> str:
    """Return a bounded, secret-independent classification for diagnostics."""
    errors = body.get("errors")
    if (isinstance(errors, list) and len(errors) == 1
            and isinstance(errors[0], str)):
        return SAFE_RESPONSE_ERRORS.get(errors[0], f"http_{status}_unclassified")
    return f"http_{status}_without_single_error"


def interrupted(_signum, _frame):
    raise FixtureInterrupted("controller_interrupted")


def install_signal_handlers():
    return {
        kind: signal.signal(kind, interrupted)
        for kind in (signal.SIGTERM, signal.SIGINT)
    }


def restore_signal_handlers(handlers) -> None:
    for kind, handler in handlers.items():
        signal.signal(kind, handler)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@dataclass(frozen=True)
class Node:
    node_id: int
    alias: str
    ip: str
    root: str
    api_port: int
    raft_port: int
    api_connect_port: int | None = None

    @property
    def name(self) -> str:
        return f"node-{self.node_id}"

    @property
    def server_name(self) -> str:
        return f"node-{self.node_id}.heptabao.synthetic"

    @property
    def api_origin(self) -> str:
        if self.api_connect_port is not None:
            return f"https://127.0.0.1:{self.api_connect_port}"
        return f"https://{self.ip}:{self.api_port}"


def checked_run(argv: list[str], *, input_bytes: bytes | None = None,
                timeout: float = 120, stdout=None) -> subprocess.CompletedProcess:
    target = subprocess.PIPE if stdout is None else stdout
    return subprocess.run(argv, input=input_bytes, stdout=target,
                          stderr=subprocess.PIPE, timeout=timeout, check=True)


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def admitted_storage_prefix(alias: str, path: str, *, binary_source: bool = False) -> bool:
    """Preserve canonical checks while respecting known host storage boundaries."""
    if alias == "desktop-ts":
        return path.startswith("/data/")
    if alias == "x230-ts":
        return path.startswith("/home/qian/")
    if alias in ("mac-ts", "macbook-pro"):
        return path.startswith("/Volumes/T5/")
    # Local Data is the existing desktop producer location. Other hosts retain
    # their original home admission; this does not grant a host or ABI identity.
    return path.startswith("/home/") or (binary_source and alias == "local" and path.startswith("/data/"))


def parse_binary_source(value: str) -> tuple[str, str]:
    alias, separator, path = value.partition(":")
    if (not separator or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", alias) is None
            or not admitted_storage_prefix(alias, path, binary_source=True) or "//" in path
            or any(part in ("", ".", "..") for part in Path(path).parts[1:])
            or any(character.isspace() or ord(character) < 0x20 for character in path)):
        raise argparse.ArgumentTypeError(
            "binary source must use its host admitted absolute private storage"
        )
    return alias, path


def parse_node_binary(value: str, commit: str, tree: str) -> tuple[str, tuple[str, str, str]]:
    """Bind one native artifact to the same frozen source as the other voters."""
    parts = value.split(",")
    if (len(parts) != 5 or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", parts[0]) is None
            or re.fullmatch(r"[0-9a-f]{64}", parts[2]) is None
            or parts[3] != commit or parts[4] != tree):
        raise argparse.ArgumentTypeError("native binary must bind node, source, SHA256 and exact source commit/tree")
    alias, path = parse_binary_source(parts[1])
    return parts[0], (alias, path, parts[2])


def parse_build_receipt(value: str) -> tuple[str, tuple[str, str, str]]:
    parts = value.split(",")
    if (len(parts) != 3 or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", parts[0]) is None
            or re.fullmatch(r"[0-9a-f]{64}", parts[2]) is None):
        raise argparse.ArgumentTypeError("receipt must name a node, canonical source and SHA256")
    alias, path = parse_binary_source(parts[1])
    return parts[0], (alias, path, parts[2])


def validate_build_receipt(receipt: dict, commit: str, tree: str, binary_digest: str) -> str:
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "heptabao.native-build.v1"
            or receipt.get("source_commit") != commit
            or receipt.get("source_tree") != tree
            or receipt.get("binary_sha256") != binary_digest
            or type(receipt.get("build_exit_code")) is not int
            or receipt["build_exit_code"] != 0
            or receipt.get("source_freeze_verified") is not True
            or not isinstance(receipt.get("native_abi"), str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", receipt["native_abi"]) is None):
        raise FixtureError("native_build_receipt_binding_invalid")
    return receipt["native_abi"]


def remote_binary_digest(node: Node) -> str:
    return ssh(node, f"""
python3 - {shlex.quote(node.root + '/heptabao-server')} <<'PY2'
import hashlib, sys
with open(sys.argv[1], 'rb') as source:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        digest.update(chunk)
    print(digest.hexdigest())
PY2
""").strip()


def copy_candidate_source(alias: str, path: str, destination: Path, *, executable: bool = True) -> None:
    if alias != "local":
        checked_run([
            "scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1", "-p", f"{alias}:{path}", str(destination),
        ], timeout=300)
        return
    source = Path(path)
    try:
        resolved = source.resolve(strict=True)
        info = source.lstat()
    except OSError as error:
        raise FixtureError("local_candidate_source_unavailable") from error
    if (resolved != source or source.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o022
            or not os.access(source, os.R_OK | (os.X_OK if executable else 0))):
        raise FixtureError("unsafe_local_candidate_source")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with source.open("rb") as input_stream, os.fdopen(
        os.open(destination, flags, 0o500), "wb"
    ) as output_stream:
        shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
        output_stream.flush()
        os.fsync(output_stream.fileno())


def report_key_names(value) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str):
                names.add(key.lower())
            names.update(report_key_names(nested))
    elif isinstance(value, list):
        for nested in value:
            names.update(report_key_names(nested))
    return names


def report_is_secret_safe(report: dict, runtime_secrets=()) -> bool:
    if report_key_names(report) & FORBIDDEN_REPORT_KEYS:
        return False
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    return all(not secret or secret not in encoded for secret in runtime_secrets)


def secret_safe_report(report: dict, runtime_secrets=()) -> dict:
    if report_is_secret_safe(report, runtime_secrets):
        return report
    return {
        "schema": "heptabao.multihost-ha.v1",
        "status": "failed",
        "source_commit": report.get("source_commit"),
        "source_tree": report.get("source_tree"),
        "binary_sha256": report.get("binary_sha256"),
        "runner_sha256": report.get("runner_sha256"),
        "failure_code": "report_redaction_failed",
        "qualification": False,
        "independent_qualification": False,
        "full_openbao_compatibility": False,
        "production_authority": False,
    }


def ssh(node: Node, script: str, *, timeout: float = 60) -> str:
    result = checked_run([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        node.alias, "bash", "-s",
    ], input_bytes=script.encode(), timeout=timeout)
    return result.stdout.decode(errors="replace")


def compress_candidate(source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with source.open("rb") as input_stream, os.fdopen(
        os.open(destination, flags, 0o600), "wb"
    ) as raw_output:
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=6, fileobj=raw_output, mtime=0
        ) as compressed:
            shutil.copyfileobj(input_stream, compressed, 1024 * 1024)
        raw_output.flush()
        os.fsync(raw_output.fileno())


def install_candidate(node: Node, payload: Path, expected_sha256: str) -> None:
    archive = node.root + "/heptabao-server.gz"
    upload(node, payload, archive, 0o600)
    ssh(node, f"""
set -eu
root={shlex.quote(node.root)}
expected={shlex.quote(expected_sha256)}
python3 - "$root" "$expected" <<'PY2'
from pathlib import Path
import gzip, hashlib, os, shutil, stat, sys
root = Path(sys.argv[1])
expected = sys.argv[2]
archive = root / "heptabao-server.gz"
temporary = root / "heptabao-server.copying"
final = root / "heptabao-server"
if (root.resolve(strict=True) != root or not archive.is_file()
        or archive.is_symlink() or final.exists() or temporary.exists()
        or archive.stat().st_uid != os.getuid()
        or archive.stat().st_mode & 0o077):
    raise SystemExit(71)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
with gzip.open(archive, "rb") as source, os.fdopen(
    os.open(temporary, flags, 0o500), "wb"
) as output:
    shutil.copyfileobj(source, output, 1024 * 1024)
    output.flush()
    os.fsync(output.fileno())
with temporary.open("rb") as stream:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    actual = digest.hexdigest()
if actual != expected:
    temporary.unlink(missing_ok=True)
    raise SystemExit(72)
os.chmod(temporary, 0o500)
os.replace(temporary, final)
archive.unlink()
directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
if (not final.is_file() or final.is_symlink()
        or not stat.S_ISREG(final.stat().st_mode)):
    raise SystemExit(73)
PY2
""", timeout=180)


def upload(node: Node, source: Path, destination: str, mode: int) -> None:
    temporary = destination + ".copying"
    checked_run([
        "scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1", "-p", str(source),
        f"{node.alias}:{temporary}",
    ], timeout=300)
    ssh(node, f"""
set -eu
umask 077
test -f {shlex.quote(temporary)}
chmod {mode:o} {shlex.quote(temporary)}
mv {shlex.quote(temporary)} {shlex.quote(destination)}
""")


REMOTE_PROCESS_SCRIPT = r"""
from pathlib import Path
import hashlib, json, os, platform, signal, stat, subprocess, sys, time

action, raw_root, has_ha = sys.argv[1:]
root = Path(raw_root)
if root.resolve(strict=True) != root or root.is_symlink():
    raise SystemExit(70)
info = root.stat()
if info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit(71)
exe = str(root / 'heptabao-server')
config = str(root / 'server.json')
pid_path = root / 'process.pid'
identity_path = root / 'process.identity.json'
argv = [exe, '--config', config]
if has_ha == '1':
    argv += ['--ha-config', str(root / 'ha.json')]

def observe(pid):
    if platform.system() == 'Linux':
        proc = Path('/proc') / str(pid)
        try:
            text = (proc / 'stat').read_text()
            fields = text[text.rfind(')') + 2:].split()
            if fields[0] == 'Z':
                return None
            actual_exe = os.readlink(proc / 'exe')
            actual_argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            return {'platform': 'Linux', 'pid': pid, 'start': fields[19],
                    'executable': actual_exe,
                    'arguments': [item.decode() for item in actual_argv]}
        except FileNotFoundError:
            return None
    if platform.system() != 'Darwin':
        raise SystemExit(72)
    env = dict(os.environ, LC_ALL='C')
    def field(name):
        result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', name + '='],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        return result.stdout.decode().strip() if result.returncode == 0 else ''
    actual_exe, start, command, state = field('comm'), field('lstart'), field('command'), field('state')
    if not start or state.startswith('Z'):
        return None
    return {'platform': 'Darwin', 'pid': pid, 'start': start,
            'executable': actual_exe, 'command': command}

def expected(observed):
    if observed is None or observed['executable'] != exe:
        return False
    if observed['platform'] == 'Linux':
        return observed['arguments'] in ([exe, '--config', config], [exe, '--config', config, '--ha-config', str(root / 'ha.json')])
    return observed['command'] in (' '.join([exe, '--config', config]), ' '.join([exe, '--config', config, '--ha-config', str(root / 'ha.json')]))

def write_owned(path, payload):
    temporary = path.with_name(path.name + '.copying')
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(temporary, flags, 0o600), 'w') as output:
        output.write(payload); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)

if action == 'start':
    if pid_path.exists() or identity_path.exists():
        raise SystemExit(73)
    if not all(Path(item).is_file() and not Path(item).is_symlink()
               for item in (exe, config, *([argv[-1]] if has_ha == '1' else []))):
        raise SystemExit(74)
    with (root / 'process.log').open('ab') as output:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                 start_new_session=True, close_fds=True)
    time.sleep(0.4)
    observed = observe(child.pid)
    if child.poll() is not None or not expected(observed) or os.getpgid(child.pid) != child.pid:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
        raise SystemExit(75)
    write_owned(identity_path, json.dumps(observed, sort_keys=True) + '\n')
    write_owned(pid_path, str(child.pid) + '\n')
    with (root / 'pids.log').open('a') as output:
        output.write(str(time.time()) + ' ' + str(child.pid) + ' started\n')
    print(child.pid)
elif action == 'stop':
    if not pid_path.exists():
        if identity_path.exists():
            raise SystemExit(76)
        print('none'); raise SystemExit(0)
    for path in (pid_path, identity_path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise SystemExit(77)
    raw_pid = pid_path.read_text().strip()
    if not raw_pid.isdecimal() or int(raw_pid) <= 0:
        raise SystemExit(78)
    pid = int(raw_pid)
    prior = json.loads(identity_path.read_text())
    observed = observe(pid)
    if observed is not None:
        if prior != observed or not expected(observed) or os.getpgid(pid) != pid:
            raise SystemExit(79)
        # Bind Linux signal delivery to the observed task, not a reusable PID.
        # macOS has no equivalent here and retains its explicit bounded ps scope.
        if observed['platform'] == 'Linux':
            if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                raise SystemExit(82)
            try:
                descriptor = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                descriptor = None
            if descriptor is not None:
                try:
                    bound = observe(pid)
                    if bound is not None and (bound != prior or not expected(bound)):
                        raise SystemExit(79)
                    if bound is not None:
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                        except ProcessLookupError:
                            pass
                finally:
                    os.close(descriptor)
        else:
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and observe(pid) == prior:
            time.sleep(0.05)
        if observe(pid) == prior:
            raise SystemExit(80)
    pid_path.unlink(); identity_path.unlink()
    with (root / 'pids.log').open('a') as output:
        output.write(str(time.time()) + ' ' + str(pid) + ' stopped\n')
    print(pid)
else:
    raise SystemExit(81)
"""


def remote_start(node: Node, *, ha: bool) -> int:
    output = ssh(node, f"python3 - start {shlex.quote(node.root)} {'1' if ha else '0'} <<'PY2'\n"
                 + REMOTE_PROCESS_SCRIPT + "\nPY2\n")
    try:
        return int(output.strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise FixtureError("remote_start_pid_missing") from error


def remote_stop(node: Node) -> int | None:
    output = ssh(node, f"python3 - stop {shlex.quote(node.root)} 0 <<'PY2'\n"
                 + REMOTE_PROCESS_SCRIPT + "\nPY2\n")
    value = output.strip().splitlines()[-1] if output.strip() else "none"
    return None if value == "none" else int(value)


def api(context: ssl.SSLContext, node: Node, method: str, path: str,
        body=None, token: str = "", timeout: float = 8.0, *,
        wrap_ttl: str | None = None) -> tuple[int, dict]:
    if not path or path.startswith("/") or ".." in path.split("/") or "://" in path:
        raise FixtureError("invalid_api_path")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if wrap_ttl is not None:
        if not isinstance(wrap_ttl, str) or re.fullmatch(r"[0-9]{1,10}", wrap_ttl) is None:
            raise FixtureError("invalid_fixture_wrap_ttl")
        headers["X-Vault-Wrap-TTL"] = wrap_ttl
    request = urllib.request.Request(
        f"{node.api_origin}/v1/{path}",
        data=None if body is None else json.dumps(body, separators=(",", ":")).encode(),
        headers=headers, method=method,
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise FixtureError("api_response_too_large")
        parsed = json.loads(raw) if raw else {}
        if not isinstance(parsed, dict):
            raise FixtureError("api_response_not_object")
        return int(response.status), parsed


def wait_listener(context: ssl.SSLContext, node: Node, seconds: float = 45) -> tuple[int, dict]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return api(context, node, "GET", "sys/health", timeout=1.5)
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
    raise FixtureError(f"node_{node.node_id}_listener_timeout")


def leader_once(context: ssl.SSLContext, nodes: list[Node], token: str) -> Node | None:
    active: list[Node] = []
    for node in nodes:
        try:
            status, health = api(context, node, "GET", "sys/health", timeout=2)
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            continue
        if status == 200:
            if (health.get("ha_active") is not True
                    or health.get("ha_application_ready") is not True
                    or health.get("standby") is not False):
                raise FixtureError("health_success_without_active_authority")
            active.append(node)
    if len(active) > 1:
        raise FixtureError("multiple_active_leaders")
    if not active:
        return None
    status, body = api(context, active[0], "GET", "sys/leader", token=token)
    if status == 200 and body.get("is_self") is True:
        return active[0]
    return None


def wait_leader(context: ssl.SSLContext, nodes: list[Node], token: str,
                *, previous: Node | None = None, seconds: float = 45) -> Node:
    deadline = time.monotonic() + seconds
    candidate: Node | None = None
    stable_since = 0.0
    while time.monotonic() < deadline:
        observed = leader_once(context, nodes, token)
        now = time.monotonic()
        if observed is not None and (previous is None or observed != previous):
            if observed == candidate:
                if now - stable_since >= 2.2:
                    return observed
            else:
                candidate, stable_since = observed, now
        else:
            candidate, stable_since = None, 0.0
        time.sleep(0.1)
    raise FixtureError("stable_leader_timeout")


def parsed_local_frontier(body: dict) -> tuple[int, int] | None:
    """Passive local metadata, never an application-read capability."""
    committed = body.get("raft_committed_index")
    applied = body.get("raft_applied_index")
    if (body.get("ha_enabled") is not True
            or type(committed) is not int or type(applied) is not int
            or not 0 < applied <= committed <= (1 << 64) - 1):
        return None
    return committed, applied


def capture_committed_frontier(context: ssl.SSLContext, node: Node) -> int:
    status, body = api(context, node, "GET", "sys/leader", timeout=4)
    observed = parsed_local_frontier(body)
    if status != 200 or body.get("is_self") is not True or observed is None:
        raise FixtureError("leader_frontier_anchor_unavailable")
    return observed[0]


def wait_local_frontier(context: ssl.SSLContext, node: Node, required: int,
                        *, seconds: float = 45, record=None) -> tuple[int, int]:
    """Wait for this voter itself, not a forwarded secret read, to catch up."""
    if type(required) is not int or not 0 < required <= (1 << 64) - 1:
        raise FixtureError("invalid_required_raft_frontier")
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            status, body = api(context, node, "GET", "sys/leader", timeout=min(4, remaining))
            observed = parsed_local_frontier(body) if status == 200 else None
            if observed is not None:
                last = observed
                if observed[1] >= required and time.monotonic() < deadline:
                    return observed
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    if record is not None:
        record("local_raft_frontier_timeout", node=node.node_id, required_index=required,
               committed_index=last[0] if last else None,
               applied_index=last[1] if last else None)
    raise FixtureError(f"node_{node.node_id}_raft_frontier_timeout")


def record_health_failure(context: ssl.SSLContext, node: Node, record) -> None:
    """One ordinary health observation; only bounded flags enter the report.

    This is diagnostic after an already-failed lifecycle. It cannot rescue the
    failed check, retry a transfer or turn a local leader into read authority.
    """
    try:
        status, body = api(context, node, "GET", "sys/health", timeout=4)
        flags = {name: value if type(value) is bool else None
                 for name in ("initialized", "sealed", "standby", "ha_active",
                              "ha_application_ready", "recovery_required")
                 for value in (body.get(name),)}
        record("failed_transfer_health_observation", node=node.node_id, status=status,
               failure_code=response_failure_code(status, body), **flags)
    except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
        record("failed_transfer_health_observation", node=node.node_id,
               status="transport_or_deadline")


def write_once(context: ssl.SSLContext, node: Node, token: str,
               path: str, value: str) -> int:
    status, body = api(context, node, "POST", f"secret/data/{path}",
                       {"data": {"value": value}, "options": {"cas": 0}}, token, 12)
    version = body.get("data", {}).get("version")
    if status != 200 or version != 1:
        code = response_failure_code(status, body)
        raise FixtureError(f"write_not_acknowledged_exactly_once_{code}")
    return version


def wait_linearizable_read_window(context: ssl.SSLContext, node: Node,
                                  token: str, path: str, value: str,
                                  seconds: float = 45,
                                  stable_seconds: float = 1.5) -> None:
    """Observe the complete protected read path before a one-shot mutation."""
    deadline = time.monotonic() + seconds
    stable_since: float | None = None
    successes = 0
    while time.monotonic() < deadline:
        try:
            status, body = api(
                context, node, "GET", f"secret/data/{path}",
                token=token, timeout=4,
            )
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            stable_since, successes = None, 0
            time.sleep(0.25)
            continue
        if status == 200:
            data = body.get("data", {})
            if (data.get("data", {}).get("value") != value
                    or data.get("metadata", {}).get("version") != 1):
                raise FixtureError("readiness_read_is_stale_or_wrong")
            now = time.monotonic()
            stable_since = now if stable_since is None else stable_since
            successes += 1
            if successes >= 4 and now - stable_since >= stable_seconds:
                return
        elif status in (429, 503):
            stable_since, successes = None, 0
        else:
            raise FixtureError("readiness_read_unexpected_status")
        time.sleep(0.5)
    raise FixtureError("linearizable_readiness_timeout")


def read_exact(context: ssl.SSLContext, node: Node, token: str,
               path: str, value: str, seconds: float = 35,
               request_timeout: float = 4) -> None:
    deadline = time.monotonic() + seconds
    last_failure = "no_response"
    while time.monotonic() < deadline:
        try:
            status, body = api(
                context, node, "GET", f"secret/data/{path}",
                token=token, timeout=request_timeout,
            )
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            last_failure = "transport_or_deadline"
            time.sleep(0.1)
            continue
        if status == 200:
            data = body.get("data", {})
            if data.get("data", {}).get("value") != value or data.get("metadata", {}).get("version") != 1:
                raise FixtureError("successful_read_is_stale_or_wrong")
            return
        last_failure = response_failure_code(status, body)
        if status not in (429, 503):
            raise FixtureError(f"acknowledged_value_not_visible_{last_failure}")
        time.sleep(0.1)
    raise FixtureError(f"readback_timeout_{last_failure}")


def wait_absent(context: ssl.SSLContext, node: Node, token: str, path: str,
                seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            status, _ = api(context, node, "GET", f"secret/data/{path}", token=token, timeout=4)
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
            continue
        if status == 404:
            return
        if status not in (429, 503):
            raise FixtureError("rejected_write_has_effect")
        time.sleep(0.1)
    raise FixtureError("absence_not_observed")


def openssl(*args: str) -> None:
    checked_run(["openssl", *args], timeout=60)


def create_fixture_ca(key: Path, certificate: Path) -> None:
    # Some OpenSSL-compatible hosts omit these identifiers unless explicitly
    # requested. Strict verifiers must stay enabled on every orchestrator.
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", str(key), "-out", str(certificate),
            "-subj", "/CN=HeptaBao Synthetic Multi-Host HA CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-addext", "authorityKeyIdentifier=keyid:always")
    key.chmod(0o600)
    certificate.chmod(0o600)


def create_fixture_node_certificate(node: Node, directory: Path,
                                    ca_key: Path, ca_cert: Path) -> tuple[Path, Path]:
    key, csr, cert, ext = (directory / name for name in ("tls.key", "tls.csr", "tls.crt", "tls.ext"))
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(csr),
            "-subj", f"/CN={node.server_name}")
    key.chmod(0o600)
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
        f"subjectAltName=DNS:{node.server_name},IP:{node.ip}"
        + (",IP:127.0.0.1" if node.api_connect_port is not None else "") + "\n"
    )
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert),
            "-days", "2", "-sha256", "-extfile", str(ext))
    cert.chmod(0o600)
    return key, cert


def provision_seed_kv2(context: ssl.SSLContext, node: Node, token: str) -> dict:
    """Submit the fresh fixture mount once, then verify its public inventory."""
    def submit(method, path, body=None, **request_options):
        return api(context, node, method, path, body, token, **request_options)
    provision_secret_kv2(submit, error_type=FixtureError, timeout=12)
    status, body = api(context, node, "GET", "sys/mounts", token=token, timeout=12)
    mounts = body.get("data") if isinstance(body, dict) else None
    mount = mounts.get("secret/") if isinstance(mounts, dict) else None
    options = mount.get("options") if isinstance(mount, dict) else None
    if (type(status) is not int or status != 200 or not isinstance(mount, dict)
            or mount.get("type") != "kv" or not isinstance(options, dict)
            or options.get("version") != "2"):
        raise FixtureError("fixture_exact_kv2_inventory_failed")
    metadata = completed_kv2_mount_metadata()
    metadata["inventory_confirmed"] = True
    return metadata


def parse_node(text: str, node_id: int, api_port: int, raft_port: int,
               *, allow_private_lan: bool = False) -> Node:
    parts = text.split(",", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("node must be alias,ip,absolute-root")
    alias, raw_ip, root = parts
    if (re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", alias) is None
            or not admitted_storage_prefix(alias, root) or "//" in root
            or any(part in ("", ".", "..") for part in Path(root).parts[1:])
            or any(character.isspace() or ord(character) < 0x20 for character in root)):
        raise argparse.ArgumentTypeError("invalid node alias or canonical private root")
    address = ipaddress.ip_address(raw_ip)
    if allow_private_lan:
        if (not isinstance(address, ipaddress.IPv4Address)
                or not any(address in network for network in PRIVATE_LAN)):
            raise argparse.ArgumentTypeError("nodes must use private LAN RFC1918 IPv4 addresses")
    elif address not in TAILNET:
        raise argparse.ArgumentTypeError("nodes must use private tailnet CGNAT addresses")
    return Node(node_id, alias, str(address), root.rstrip("/"), api_port, raft_port)


def snapshot_strategy(extension):
    # Native large-record snapshot catch-up is an operator-scoped fixture:
    # compact via the Raft maintenance route. Never smuggle >20MiB state
    # through the separate HTTP backup-export snapshot endpoint.
    if extension is not None and getattr(extension, "snapshot_via_compact", False) is True:
        return ("POST", "sys/storage/raft/compact", {}, 60)
    return ("GET", "sys/storage/raft/snapshot", None, 20)


def stop_owned_processes(nodes, started, report, event) -> None:
    """A completed runtime profile remains failed until owned cleanup succeeds."""
    for node in reversed(nodes):
        try:
            if node in started:
                pid = remote_stop(node)
                event("final_process_stop", node=node.node_id, pid=pid)
        except Exception:
            report.setdefault("cleanup_failure", []).append(node.node_id)
    if report.get("cleanup_failure"):
        report["status"] = "failed"
        report.setdefault("failure_code", "owned_process_cleanup_failed")


def remote_evidence_inventory(node) -> list[str]:
    # A successfully stopped process removes its identity file. Its absence
    # cannot turn earlier existing evidence into a failed shell invocation.
    return ssh(node, f"""
set -eu
root={shlex.quote(node.root)}
test -d "$root" || exit 0
for name in {' '.join(shlex.quote(name) for name in REMOTE_EVIDENCE_FILES)}; do
  if test -f "$root/$name"; then
    printf '%s\n' "$name"
  fi
done
:
""", timeout=12).splitlines()


def main(*, extension=None, mesh=None, full_restart=False) -> int:
    # The baseline retains its original fixed denominator. A separately named
    # composed profile must satisfy both sets; it cannot borrow baseline success.
    required_checks = REQUIRED_CHECKS
    if extension is not None:
        if not extension.required_checks or extension.required_checks & REQUIRED_CHECKS:
            raise FixtureError("invalid_lifecycle_extension_denominator")
        required_checks = REQUIRED_CHECKS | extension.required_checks
    if mesh is not None:
        required_checks = required_checks | {"complete_loopback_raft_mesh_started"}
    if full_restart:
        required_checks = required_checks | {
            "all_voters_restarted_from_persisted_state",
            "full_restart_readindex_preserves_acknowledged_data",
            "full_restart_new_write_replicated",
            "cleanup_after-full-restart",
        }
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-source", required=True,
                        help="ssh-alias:/absolute/path/to/heptabao-server")
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--node-binary", action="append", default=[],
                        help="node-alias,source-alias:absolute-path,SHA256,source-commit,source-tree")
    parser.add_argument("--native-build-receipt", action="append", default=[],
                        help="node-alias,source-alias:absolute-receipt-path,SHA256; required for every native voter")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--node", action="append", required=True)
    parser.add_argument("--api-port", type=int, default=46230)
    parser.add_argument("--raft-port", type=int, default=46231)
    parser.add_argument("--work-root", type=Path, required=True)
    network_scope = parser.add_mutually_exclusive_group(required=True)
    network_scope.add_argument("--allow-private-tailnet", action="store_true")
    network_scope.add_argument("--allow-private-lan", action="store_true")
    args = parser.parse_args()
    if len(args.node) != 3 or len(set(args.node)) != 3:
        parser.error("exactly three distinct nodes are required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit) or not re.fullmatch(r"[0-9a-f]{40}", args.source_tree):
        parser.error("source commit and tree must be exact SHA-1 values")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256):
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
    nodes = [parse_node(value, index + 1, args.api_port, args.raft_port,
                        allow_private_lan=args.allow_private_lan)
             for index, value in enumerate(args.node)]
    if len({node.ip for node in nodes}) != 3 or len({node.root for node in nodes}) != 3:
        parser.error("node IPs and roots must be unique")
    if mesh is not None:
        nodes = mesh.prepare_nodes(nodes)
    native_sources = {}
    try:
        for specification in args.node_binary:
            alias, native = parse_node_binary(specification, args.source_commit, args.source_tree)
            if alias in native_sources or alias not in {node.alias for node in nodes}:
                parser.error("native binary must name one unique configured node")
            native_sources[alias] = native
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    expected_digests = {str(node.node_id): native_sources.get(
        node.alias, (None, None, args.expected_binary_sha256))[2] for node in nodes}
    receipt_sources = {}
    try:
        for specification in args.native_build_receipt:
            alias, receipt = parse_build_receipt(specification)
            if alias in receipt_sources or alias not in {node.alias for node in nodes}:
                parser.error("native build receipt must name one unique configured node")
            receipt_sources[alias] = receipt
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    if native_sources or receipt_sources:
        if set(receipt_sources) != {node.alias for node in nodes}:
            parser.error("every native voter requires its own hash-bound source/build receipt")
        required_checks = required_checks | {f"node_{node.node_id}_native_build_receipt" for node in nodes}
    checks: list[dict] = []
    events: list[dict] = []
    started: set[Node] = set()
    acknowledged: dict[str, str] = {}
    runner_path = Path(__file__ if extension is None else extension.runner_path).resolve(strict=True)
    shared_runner_path = Path(__file__).resolve(strict=True)
    initial_runner_sha256 = sha256_file(runner_path)
    initial_shared_runner_sha256 = sha256_file(shared_runner_path)
    report = {
        "schema": "heptabao.multihost-ha.v1",
        "status": "failed",
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "binary_sha256": args.expected_binary_sha256,
        "expected_node_binary_sha256": expected_digests,
        "source_binding": "all native artifacts bound to the exact source commit and tree",
        "process_identity_scope": "Linux start ticks and pidfd signal or macOS BSD ps; macOS PID check is non-atomic",
        "native_build_receipts_verified": False,
        "native_build_check_count": len(receipt_sources),
        "runner_sha256": initial_runner_sha256,
        "required_check_count": len(required_checks),
        "host_count": 3,
        "transport": "private-lan-mtls" if args.allow_private_lan else "private-tailnet-mtls",
        "checks": checks,
        "events": events,
        "qualification": False,
        "independent_qualification": False,
        "full_openbao_compatibility": False,
        "production_authority": False,
        "uncovered": ["physical_power_loss", "disk_full", "WAN_faults",
                      "long_horizon_linearizability", "production_custody"],
    }

    if extension is not None:
        report.update({"schema": extension.schema, "scope": extension.scope,
                       "shared_runner_sha256": initial_shared_runner_sha256,
                       "baseline_check_count": len(REQUIRED_CHECKS),
                       "extension_check_count": len(extension.required_checks)})
    if mesh is not None:
        report["transport"] = "coordinator-mediated-ssh-with-end-to-end-mtls"
        report["direct_lan_qualification"] = False
        report["mesh_runner_sha256"] = sha256_file(Path(mesh.runner_path))
    report["full_cluster_restart_requested"] = full_restart is True

    phase_dir = work / "phases"
    phase_dir.mkdir(mode=0o700)
    phase_counter = 0

    def checkpoint() -> None:
        nonlocal phase_counter
        runtime = (root_token, unseal_key)
        if extension is not None:
            runtime += extension.runtime_secrets()
        safe = secret_safe_report(report, runtime)
        phase_counter += 1
        path = phase_dir / f"{phase_counter:05d}.json"
        with path.open("x") as output:
            output.write(json.dumps(safe, indent=2, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())

    def check(name: str, condition: bool, **metadata) -> None:
        row = {"case": name, "passed": condition is True, **metadata}
        checks.append(row)
        checkpoint()
        if condition is not True:
            raise FixtureError(name)

    def event(name: str, **metadata) -> None:
        events.append({"event": name, "time": time.time(), **metadata})
        checkpoint()

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
        stage = "native_build_receipt_binding"
        verified_abis = {}
        for node in nodes:
            if node.alias not in receipt_sources:
                continue
            alias, path, receipt_digest = receipt_sources[node.alias]
            destination = work / ("native-build-" + node.alias + ".json")
            copy_candidate_source(alias, path, destination, executable=False)
            destination.chmod(0o600)
            if (destination.stat().st_size > 64 * 1024
                    or sha256_file(destination) != receipt_digest):
                raise FixtureError("native_build_receipt_digest_mismatch_" + node.alias)
            verified_abis[node.alias] = validate_build_receipt(
                json.loads(destination.read_text()), args.source_commit, args.source_tree,
                expected_digests[str(node.node_id)])
            check(f"node_{node.node_id}_native_build_receipt", True,
                  receipt_sha256=receipt_digest, native_abi=verified_abis[node.alias])
        if receipt_sources:
            report["native_build_receipts_verified"] = True
            report["native_build_abis"] = verified_abis
        stage = "candidate_copy"
        copy_candidate_source(source_alias, source_path, local_binary)
        local_binary.chmod(0o500)
        digest = sha256_file(local_binary)
        check("candidate_binary_digest", digest == args.expected_binary_sha256)
        payload = work / "heptabao-server.gz"
        compress_candidate(local_binary, payload)
        report["candidate_payload_sha256"] = sha256_file(payload)
        report["candidate_payload_bytes"] = payload.stat().st_size
        node_payloads = {node.alias: payload for node in nodes}
        native_copies = {}
        for alias, (native_alias, native_path, native_digest) in native_sources.items():
            native_copy = work / ("native-" + alias)
            copy_candidate_source(native_alias, native_path, native_copy)
            native_copy.chmod(0o500)
            if sha256_file(native_copy) != native_digest:
                raise FixtureError("native_candidate_digest_mismatch_" + alias)
            native_payload = work / ("native-" + alias + ".gz")
            compress_candidate(native_copy, native_payload)
            node_payloads[alias] = native_payload
            native_copies[alias] = native_copy

        stage = "fixture_ca"
        create_fixture_ca(ca_key, ca_cert)
        context = ssl.create_default_context(cafile=str(ca_cert))
        peers: dict[str, dict] = {}
        node_files: dict[Node, Path] = {}
        remote_hosts: dict[int, str] = {}
        remote_platforms: dict[int, str] = {}
        stage = "remote_node_setup"
        for node in nodes:
            remote = ssh(node, f"""
set -eu
umask 077
test ! -e {shlex.quote(node.root)}
command -v python3 >/dev/null
python3 - <<'PY2'
import socket
ip={node.ip!r}
for port in ({node.api_port}, {node.raft_port}):
    s=socket.socket(); s.bind((ip,port)); s.close()
PY2
mkdir -m 700 {shlex.quote(node.root)}
hostname
uname -s
""")
            remote_hosts[node.node_id] = remote.strip().splitlines()[-2]
            remote_platforms[node.node_id] = remote.strip().splitlines()[-1]
            check(f"node_{node.node_id}_private_root_and_ports", True)
            node_dir = work / node.name
            node_dir.mkdir(mode=0o700)
            node_files[node] = node_dir
            key, cert = create_fixture_node_certificate(node, node_dir, ca_key, ca_cert)
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
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
            if mesh is not None:
                server = mesh.configure_server(node, server)
            server_path = node_dir / "server.json"
            server_path.write_text(json.dumps(server, sort_keys=True))
            server_path.chmod(0o600)
            install_candidate(node, node_payloads[node.alias], expected_digests[str(node.node_id)])
            upload(node, ca_cert, f"{node.root}/ca.crt", 0o600)
            upload(node, cert, f"{node.root}/tls.crt", 0o600)
            upload(node, key, f"{node.root}/tls.key", 0o600)
            upload(node, server_path, f"{node.root}/server.json", 0o600)
            remote_digest = remote_binary_digest(node)
            check(f"node_{node.node_id}_binary_digest",
                  remote_digest == expected_digests[str(node.node_id)], sha256=remote_digest)

        if mesh is not None:
            stage = "loopback_mesh_startup"
            mesh.start(nodes, work, event)
            check("complete_loopback_raft_mesh_started", True)

        stage = "single_node_initialization"
        seed = nodes[0]
        seed_pid = remote_start(seed, ha=False)
        started.add(seed)
        event("seed_started", node=seed.node_id, pid=seed_pid)
        status, _ = wait_listener(context, seed)
        check("seed_fresh_uninitialized", status == 501)
        status, initialized = api(context, seed, "POST", "sys/init",
                                  {"secret_shares": 1, "secret_threshold": 1})
        root_token = initialized.get("root_token", "")
        keys = initialized.get("keys_base64", [])
        check("seed_initialized_once", status == 200 and isinstance(root_token, str)
              and bool(root_token) and isinstance(keys, list) and len(keys) == 1)
        unseal_key = keys[0]
        status, _ = api(context, seed, "POST", "sys/unseal", {"key": unseal_key})
        check("seed_unsealed", status == 200)
        report["fixture_mount_setup"] = provision_seed_kv2(context, seed, root_token)
        status, health = api(context, seed, "GET", "sys/health")
        cluster_id = health.get("cluster_id")
        check("seed_cluster_identity", status == 200 and isinstance(cluster_id, str) and bool(cluster_id))
        remote_stop(seed)
        started.discard(seed)
        event("seed_stopped_for_cold_clone", node=seed.node_id)

        stage = "encrypted_state_clone"
        seed_tar = work / "seed-data.tgz"
        with seed_tar.open("wb") as stream:
            checked_run(["ssh", seed.alias, "tar", "-C", seed.root, "-czf", "-", "data"],
                        timeout=180, stdout=stream)
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
                "peer_timeout_ms": 1500,
                "forward_timeout_ms": 8000,
                "max_inflight": 32,
            }
            if mesh is not None:
                ha = mesh.configure(node, ha)
            ha_path = node_files[node] / "ha.json"
            ha_path.write_text(json.dumps(ha, sort_keys=True))
            ha_path.chmod(0o600)
            upload(node, replication, f"{node.root}/replication.key", 0o600)
            upload(node, ha_path, f"{node.root}/ha.json", 0o600)

        stage = "ha_startup"
        for node in [nodes[1], nodes[2], nodes[0]]:
            pid = remote_start(node, ha=True)
            started.add(node)
            event("ha_node_started", node=node.node_id, pid=pid)
        for node in nodes:
            wait_listener(context, node)
        deadline = time.monotonic() + 45
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
        check("three_host_raft_elected_before_unseal", active == 1)
        for node in nodes:
            status, _ = api(context, node, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
            check(f"node_{node.node_id}_unsealed", status == 200)
        initial = wait_leader(context, nodes, root_token)
        epochs = [initial.node_id]
        event("initial_leader", node=initial.node_id)
        check("three_distinct_remote_hosts", len(set(remote_hosts.values())) == 3,
              hostnames=remote_hosts)

        stage = "baseline_replication"
        nonce = secrets.token_hex(12)
        def new_value(label: str) -> tuple[str, str]:
            path = f"mh-{nonce}/{label}"
            value = secrets.token_hex(16)
            acknowledged[path] = value
            return path, value

        path, value = new_value("baseline")
        write_once(context, initial, root_token, path, value)
        for node in nodes:
            read_exact(context, node, root_token, path, value)
        check("baseline_write_read_on_all_hosts", True)

        standby = next(node for node in nodes if node != initial)
        path, value = new_value("forwarded")
        write_once(context, standby, root_token, path, value)
        for node in nodes:
            read_exact(context, node, root_token, path, value)
        check("remote_standby_write_forwarded", True)
        readiness_path, readiness_value = path, value
        if extension is not None:
            stage = "acl_live_authority"
            extension.setup(context, nodes, initial, standby, root_token, check)

        stage = "snapshot_catchup"
        offline = next(node for node in nodes if node not in (initial, standby))
        stopped_pid = remote_stop(offline)
        started.discard(offline)
        event("standby_stopped_for_snapshot_catchup", node=offline.node_id, pid=stopped_pid)
        # Losing one voter can transiently close ReadIndex/application readiness
        # while the remaining majority exchanges a fresh heartbeat. Observe that
        # readiness with read-only probes before issuing any non-retryable write.
        initial = wait_leader(context, [initial, standby], root_token)
        wait_linearizable_read_window(
            context, initial, root_token, readiness_path, readiness_value,
        )
        event("snapshot_majority_ready", node=initial.node_id)
        if extension is not None and hasattr(extension, "majority_after_offline"):
            stage = "offline_majority_extension"
            extension.majority_after_offline(initial, offline)
        for index in range(8):
            path, value = new_value(f"snapshot-{index}")
            write_once(context, initial, root_token, path, value)
        method, endpoint, payload, request_timeout = snapshot_strategy(extension)
        status, snapshot = api(context, initial, method, endpoint, payload,
                               token=root_token, timeout=request_timeout)
        check("leader_snapshot_trigger", status == 200 and isinstance(snapshot, dict))
        path, value = new_value("after-snapshot")
        write_once(context, initial, root_token, path, value)
        snapshot_frontier = capture_committed_frontier(context, initial)
        event("snapshot_catchup_frontier", source=initial.node_id,
              target=offline.node_id, required_index=snapshot_frontier)
        remote_start(offline, ha=True); started.add(offline)
        wait_listener(context, offline)
        status, _ = api(context, offline, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
        check("offline_follower_restarted_and_unsealed", status == 200)
        # Rejoining can transfer leadership while snapshot installation and peer
        # forwarding settle. Observe the current authority before testing the
        # recovered node; the read is repeatable, but no mutation is retried.
        initial = wait_leader(context, nodes, root_token, seconds=60)
        event("snapshot_rejoin_leader_ready", node=initial.node_id)
        frontier_timeout = 150 if (extension is not None and getattr(
            extension, "snapshot_via_compact", False) is True) else 45
        local_frontier = wait_local_frontier(
            context, offline, snapshot_frontier, seconds=frontier_timeout, record=event)
        read_exact(
            context, offline, root_token, path, value,
            seconds=90, request_timeout=12,
        )
        check("remote_snapshot_catchup", True, required_index=snapshot_frontier,
              local_committed_index=local_frontier[0], local_applied_index=local_frontier[1])
        if extension is not None:
            stage = "acl_snapshot_authority"
            extension.after_snapshot(offline)

        stage = "leader_failover"
        killed = remote_stop(initial)
        started.discard(initial)
        event("leader_sigkill", node=initial.node_id, pid=killed)
        # Do not immediately flood both surviving voters with authenticated
        # health/ReadIndex probes. The production election timeout maximum is
        # two seconds; leave three full maxima for the two-voter majority to
        # elect and publish local control state, then take one passive local
        # leader observation before entering the ordinary stable-leader gate.
        time.sleep(6.0)
        for survivor in [node for node in nodes if node != initial]:
            try:
                status, local = api(
                    context, survivor, "GET", "sys/leader", timeout=4,
                )
                event(
                    "post_kill_passive_leader_observation",
                    node=survivor.node_id,
                    status=status,
                    is_self=local.get("is_self") is True,
                    committed_index=local.get("raft_committed_index"),
                    applied_index=local.get("raft_applied_index"),
                )
            except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                event(
                    "post_kill_passive_leader_observation",
                    node=survivor.node_id,
                    status="transport_or_deadline",
                )
        successor = wait_leader(
            context, [node for node in nodes if node != initial],
            root_token, previous=initial, seconds=60,
        )
        epochs.append(successor.node_id)
        check("leader_changed_after_remote_sigkill", successor != initial)
        for old_path, old_value in acknowledged.items():
            read_exact(context, successor, root_token, old_path, old_value)
        path, value = new_value("after-failover")
        write_once(context, successor, root_token, path, value)
        for node in nodes:
            if node != initial:
                read_exact(context, node, root_token, path, value)
        check("post_failover_write_on_survivors", True)
        if extension is not None:
            stage = "acl_failover_authority"
            extension.after_failover([node for node in nodes if node != initial], successor)

        rejoin_frontier = capture_committed_frontier(context, successor)
        event("old_leader_catchup_frontier", source=successor.node_id,
              target=initial.node_id, required_index=rejoin_frontier)
        remote_start(initial, ha=True); started.add(initial)
        wait_listener(context, initial)
        status, _ = api(context, initial, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
        check("old_leader_restarted_and_unsealed", status == 200)
        local_frontier = wait_local_frontier(context, initial, rejoin_frontier, record=event)
        read_exact(context, initial, root_token, path, value, 45)
        check("old_leader_caught_up", True, required_index=rejoin_frontier,
              local_committed_index=local_frontier[0], local_applied_index=local_frontier[1])
        if extension is not None:
            stage = "acl_rejoined_authority"
            extension.after_rejoin(initial)

        stage = "leadership_transfer"
        current = wait_leader(context, nodes, root_token)
        transfer_frontier = capture_committed_frontier(context, current)
        event("leadership_transfer_frontier", source=current.node_id,
              required_index=transfer_frontier)
        status, body = api(context, current, "POST", "sys/step-down", {}, root_token, 15)
        check("explicit_step_down_accepted_once", status == 204 and body == {})
        try:
            next_leader = wait_leader(context, nodes, root_token, previous=current)
        except FixtureError:
            # Preserve the original failure. These passive observations cannot
            # retry a transfer, elect a node or grant application authority.
            for observer in nodes:
                try:
                    status, local = api(context, observer, "GET", "sys/leader", timeout=4)
                    frontier = parsed_local_frontier(local) if status == 200 else None
                    event("failed_transfer_local_observation", node=observer.node_id,
                          status=status, is_self=local.get("is_self") is True,
                          committed_index=frontier[0] if frontier else None,
                          applied_index=frontier[1] if frontier else None)
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    event("failed_transfer_local_observation", node=observer.node_id,
                          status="transport_or_deadline")
                record_health_failure(context, observer, event)
            raise
        epochs.append(next_leader.node_id)
        path, value = new_value("after-stepdown")
        write_once(context, next_leader, root_token, path, value)
        for node in nodes:
            read_exact(context, node, root_token, path, value)
        check("three_leadership_epochs_preserve_data", len(epochs) == 3
              and len(set(epochs)) >= 2, leader_epochs=epochs)

        stage = "quorum_loss"
        quorum_leader = wait_leader(context, nodes, root_token)
        stopped_nodes = [node for node in nodes if node != quorum_leader]
        for node in stopped_nodes:
            pid = remote_stop(node); started.discard(node)
            event("peer_stopped_for_quorum_loss", node=node.node_id, pid=pid)
        deadline = time.monotonic() + 35
        denied_health = None
        while time.monotonic() < deadline:
            try:
                denied_health = api(context, quorum_leader, "GET", "sys/health", timeout=3)
            except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                time.sleep(0.1); continue
            if (denied_health[0] == 503
                    and denied_health[1].get("ha_active") is False):
                break
            time.sleep(0.1)
        check("single_survivor_loses_authority", denied_health is not None
              and denied_health[0] == 503 and denied_health[1].get("ha_active") is False)
        rejected_path = f"mh-{nonce}/quorum-denied"
        status, denied = api(context, quorum_leader, "POST", f"secret/data/{rejected_path}",
                             {"data": {"value": "must-not-commit"}, "options": {"cas": 0}},
                             root_token, 12)
        check("quorum_loss_write_denied_without_data", status == 503
              and denied.get("data") in (None, {}))

        stage = "quorum_recovery"
        first_peer = stopped_nodes[0]
        remote_start(first_peer, ha=True); started.add(first_peer)
        wait_listener(context, first_peer)
        status, _ = api(context, first_peer, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
        check("quorum_peer_restarted", status == 200)
        recovered_leader = wait_leader(context, [quorum_leader, first_peer], root_token)
        wait_absent(context, recovered_leader, root_token, rejected_path)
        check("denied_quorum_write_has_no_effect", True)
        path, value = new_value("quorum-recovered")
        write_once(context, recovered_leader, root_token, path, value)

        last_peer = stopped_nodes[1]
        remote_start(last_peer, ha=True); started.add(last_peer)
        wait_listener(context, last_peer)
        status, _ = api(context, last_peer, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
        check("final_peer_restarted", status == 200)
        final_leader = wait_leader(context, nodes, root_token)
        for node in nodes:
            read_exact(context, node, root_token, path, value, 45)
            wait_absent(context, node, root_token, rejected_path)
        check("all_hosts_rejoined_after_quorum_recovery", True)
        if extension is not None:
            stage = "acl_quorum_recovery_authority"
            extension.after_quorum_recovery(nodes)
            extension.cleanup(final_leader)

        if full_restart:
            stage = "full_cluster_restart"
            restart_frontier = capture_committed_frontier(context, final_leader)
            for node in nodes:
                pid = remote_stop(node)
                started.discard(node)
                event("full_restart_voter_stopped", node=node.node_id, pid=pid)
            # Reopen all three existing durable roots, without reseeding,
            # cloning, reinitializing or deleting application/Raft state.
            for node in nodes[1:] + nodes[:1]:
                pid = remote_start(node, ha=True)
                started.add(node)
                event("full_restart_voter_started", node=node.node_id, pid=pid)
            for node in nodes:
                wait_listener(context, node)
                status, _ = api(context, node, "POST", "sys/unseal", {"key": unseal_key}, timeout=10)
                if status != 200:
                    raise FixtureError(f"full_restart_node_{node.node_id}_unseal_failed")
            final_leader = wait_leader(context, nodes, root_token, seconds=60)
            check("all_voters_restarted_from_persisted_state", True)
            for node in nodes:
                wait_local_frontier(context, node, restart_frontier, seconds=60, record=event)
                for key, value in acknowledged.items():
                    read_exact(context, node, root_token, key, value)
                wait_absent(context, node, root_token, rejected_path)
            check("full_restart_readindex_preserves_acknowledged_data", True,
                  required_index=restart_frontier, acknowledged_values=len(acknowledged))
            path, value = new_value("after-full-restart")
            write_once(context, final_leader, root_token, path, value)
            for node in nodes:
                read_exact(context, node, root_token, path, value)
            check("full_restart_new_write_replicated", True)

        stage = "application_cleanup"
        for key in acknowledged:
            status, _ = api(context, final_leader, "DELETE", f"secret/metadata/{key}",
                            token=root_token, timeout=12)
            check(f"cleanup_{key.rsplit('/', 1)[-1]}", status == 204)
        for node in nodes:
            for key in acknowledged:
                wait_absent(context, node, root_token, key)
        check("synthetic_application_data_cleaned", True)
        final = wait_leader(context, nodes, root_token)
        stage = "final_integrity"
        remote_digests = {
            str(node.node_id): remote_binary_digest(node)
            for node in nodes
        }
        unchanged = (
            sha256_file(local_binary) == args.expected_binary_sha256
            and sha256_file(runner_path) == initial_runner_sha256
            and sha256_file(shared_runner_path) == initial_shared_runner_sha256
            and remote_digests == expected_digests
            and all(sha256_file(path) == native_sources[alias][2]
                    for alias, path in native_copies.items())
        )
        if mesh is not None:
            unchanged = unchanged and sha256_file(Path(mesh.runner_path)) == report["mesh_runner_sha256"]
        check("source_and_binary_unchanged", unchanged)
        runtime_secrets = (root_token, unseal_key)
        if extension is not None:
            runtime_secrets += extension.runtime_secrets()
        check("report_excludes_runtime_secrets", report_is_secret_safe(report, runtime_secrets))
        observed = [row.get("case") for row in checks]
        check("multihost.complete",
              len(observed) == len(set(observed))
              and set(observed) == required_checks - {"multihost.complete"}
              and all(row.get("passed") is True for row in checks))
        final_names = [row.get("case") for row in checks]
        if (len(final_names) != len(set(final_names))
                or set(final_names) != required_checks):
            raise FixtureError("multihost_check_denominator_mismatch")
        report.update({
            "status": "passed",
            "cluster_id_sha256": hashlib.sha256(cluster_id.encode()).hexdigest(),
            "leader_epochs": epochs,
            "final_leader": final.node_id,
            "remote_hosts": remote_hosts,
            "remote_platforms": remote_platforms,
            "root_locations": {str(node.node_id): node.root for node in nodes},
            "binary_identical_on_all_hosts": len(set(expected_digests.values())) == 1,
            "native_binary_bound_on_all_hosts": True,
            "source_and_binary_unchanged": unchanged,
            "remote_binary_sha256": remote_digests,
            "mutating_requests_retried": False,
            "synthetic_cleanup": True,
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
        stop_owned_processes(nodes, started, report, event)
        if mesh is not None:
            try:
                mesh.stop(event)
                report["owned_mesh_cleanup"] = True
            except (OSError, subprocess.SubprocessError, FixtureError):
                report["owned_mesh_cleanup"] = False
                report["status"] = "failed"
                report.setdefault("failure_code", "owned_mesh_cleanup_failed")
        for node in nodes:
            local = work / f"remote-{node.node_id}"
            local.mkdir(exist_ok=True)
            try:
                names = remote_evidence_inventory(node)
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
        # Refuse to write a report containing a secret-bearing key or value.
        report = secret_safe_report(report, (root_token, unseal_key,
            *(extension.runtime_secrets() if extension is not None else ())))
        if extension is not None:
            extension.clear()
        root_token = ""
        unseal_key = ""
        summary = work / "summary.json"
        summary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        summary.chmod(0o600)
        # Console output is a literal classification, not a data-flow copy of
        # a secret-bearing runtime result. Exact redacted details stay in summary.
        public_status = "passed" if report["status"] == "passed" else "failed"
        print(json.dumps({"status": public_status, "checks": len(checks),
                          "failure_code": None if public_status == "passed" else "fixture_failed"},
                         sort_keys=True))
    return 0 if (report["status"] == "passed"
                 and not report.get("cleanup_failure")
                 and len(checks) == len(required_checks)
                 and {row.get("case") for row in checks} == required_checks
                 and all(row.get("passed") is True for row in checks)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
