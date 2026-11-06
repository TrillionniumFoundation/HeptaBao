"""Pure layout/configuration rendering for the reviewed future bootstrap.

No filesystem, key, service, credential or network operation is implemented.
Output is an uninstalled draft; it cannot substitute for runtime admission.
The exec guard referenced by the plist must be implemented and reviewed before
that plist may be installed. A dictionary of operator claims is not evidence.
"""
from __future__ import annotations

import ipaddress
import json
import plistlib
from pathlib import PurePosixPath
from typing import Any

SCHEMA = "heptabao.normal-kv2-bootstrap-layout.v1"
SERVICE_ROOT = (
    "/Volumes/T5/hepta-vnext-recovery-20261013/"
    "heptabao-production-20261104-r1/formal-kv2-current-20261106-r1"
)
LABEL = "org.heptabao.kv2"
UID = 501


class InvalidLayout(ValueError):
    """Only static classifications are suitable for a public failure receipt."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise InvalidLayout(code)


def absolute_path(value: Any) -> str:
    need(type(value) is str and 1 < len(value) <= 4096, "absolute_path_required")
    need(value.startswith("/") and not value.endswith("/"), "canonical_path_required")
    need(not any(ord(c) < 32 or ord(c) == 127 for c in value), "control_character_in_path")
    need(not any(part in ("", ".", "..") for part in value[1:].split("/")), "canonical_path_required")
    return value


def render(layout: dict[str, Any]) -> dict[str, Any]:
    """Render fixed non-secret config and manager data from reviewed locators.

    In particular, a key_root path does not prove its filesystem or permissions.
    The execution preflight must bind its actual private FD and internal volume.
    No root token, share, nonce, key bytes, digest of those values, or arbitrary
    ProgramArguments/EnvironmentVariables are accepted by this input shape.
    """
    need(type(layout) is dict, "layout_object_required")
    need(set(layout) == {
        "schema", "service_root", "key_root", "manager_domain", "manager_uid",
        "manager_label", "python_executable", "listen_address", "listen_port",
    }, "exact_layout_fields_required")
    need(layout["schema"] == SCHEMA, "layout_schema")
    root = absolute_path(layout["service_root"])
    need(root == SERVICE_ROOT, "frozen_service_root")
    keys = absolute_path(layout["key_root"])
    need(not (keys == "/Volumes" or keys.startswith("/Volumes/")), "internal_key_root_required")
    need(keys != root and not keys.startswith(root + "/") and not root.startswith(keys + "/"), "roots_disjoint")
    need(type(layout["manager_uid"]) is int and layout["manager_uid"] == UID, "frozen_manager_uid")
    need(layout["manager_domain"] in ("gui/501", "user/501"), "observed_user_domain_required")
    need(layout["manager_label"] == LABEL, "frozen_manager_label")
    python = absolute_path(layout["python_executable"])
    need(layout["listen_address"] == "127.0.0.1", "loopback_listener_required")
    need(ipaddress.ip_address(layout["listen_address"]).is_loopback, "loopback_listener_required")
    need(type(layout["listen_port"]) is int and layout["listen_port"] == 18240, "frozen_listener_port")
    base = PurePosixPath(root)
    custody = PurePosixPath(keys)
    files = {
        "server": str(base / "runtime/heptabao-server"),
        "seed": str(base / "runtime/heptabao-seed"),
        "server_config": str(base / "config/server.json"),
        "data": str(base / "data"),
        "audit": str(base / "audit/audit.jsonl"),
        "ca_certificate": str(base / "tls/ca.crt"),
        "server_certificate": str(base / "tls/server.crt"),
        "server_private_key": str(custody / "tls/server.key"),
        "ca_private_key": str(custody / "issuer/ca.key"),
        "root_token": str(custody / "root/root.token"),
        "recovery_nonce": str(custody / "bootstrap/recovery.nonce"),
        "local_share_1": str(custody / "share-1/unseal.share"),
        "pending_share_2": str(custody / "pending-share-2/unseal.share"),
        "pending_share_3": str(custody / "pending-share-3/unseal.share"),
        "exec_guard": str(base / "manager/launch_guard.py"),
        "launch_binding": str(base / "manager/launch-binding.private.json"),
        "plist": str(base / "manager" / (LABEL + ".plist")),
        "stdout_log": str(base / "logs/stdout.log"),
        "stderr_log": str(base / "logs/stderr.log"),
    }
    config = {
        "ui": False,
        "disable_unauthed_rekey_endpoints": True,
        "listen": "127.0.0.1:18240",
        "data_dir": files["data"],
        "storage": {"native_v6_file": {"path": files["data"]}},
        "audit_file": files["audit"],
        "tls_cert_file": files["server_certificate"],
        "tls_key_file": files["server_private_key"],
        "tls_min_version": "tls12",
        "tls_max_version": "tls13",
        "max_connections": 16,
        "timeout_seconds": 15,
        "outbound_endpoints": [],
    }
    # The domain is an external launchctl target, not a plist field. UserName is
    # deliberately absent in an observed same-UID user/gui domain.
    plist = {
        "Label": LABEL,
        "ProgramArguments": [python, "-I", "-B", files["exec_guard"], "--binding", files["launch_binding"]],
        "WorkingDirectory": root,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "ExitTimeOut": 20,
        "Umask": 0o077,
        "ProcessType": "Background",
        "StandardOutPath": files["stdout_log"],
        "StandardErrorPath": files["stderr_log"],
    }
    return {
        "schema": SCHEMA,
        "status": "uninstalled_draft",
        "runtime_admission_performed": False,
        "exec_guard_implemented_by_this_module": False,
        "manager_domain": layout["manager_domain"],
        "normal_server_argv": [files["server"], "--config", files["server_config"]],
        "server_config": config,
        "launchd_plist": plist,
        "private_locators": files,
        "service_started": False,
        "formal_kv2_qualified": False,
    }


def config_bytes(rendered: dict[str, Any]) -> bytes:
    return (json.dumps(rendered["server_config"], indent=2, sort_keys=True) + "\n").encode()


def plist_bytes(rendered: dict[str, Any]) -> bytes:
    return plistlib.dumps(rendered["launchd_plist"], fmt=plistlib.FMT_XML, sort_keys=True)
