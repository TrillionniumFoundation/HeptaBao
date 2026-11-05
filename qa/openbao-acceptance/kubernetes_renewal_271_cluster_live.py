#!/usr/bin/env python3
"""OpenBao 2.7.1 renewal against a new genuine KIND API/etcd/RBAC cluster.

The cluster is loopback-only and uses pinned KIND/node artifacts. Metadata-only
apiserver audit records prove each renewal reaches TokenReview. No existing
cluster, production namespace, Docker container or ambient kubeconfig is used.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import traceback

import kubernetes_cluster_live as kube
from bao_http import Client, private_read
from official_openbao_launcher import (
    start_oracle, stop_oracle, restart_oracle, verify_selected_oracle,
    pinned_artifact,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance

AUDIENCE = kube.AUDIENCE
MOUNT = "hb-real271"
RENEW_ROUTES = ("self", "admin", "accessor", "cidr")
SIDE_CASES = frozenset({
    "mount", "config", "policy", "role", "cidr_role", "login", "cidr_login",
    "positive_self", "positive_admin", "positive_accessor", "positive_cidr",
    "reviewer_restore_positive", "restart_revocation_persists",
    "recreated_uid_login", "old_uid_not_revived", "auth_unmount", "unmount_revokes_token",
} | {f"{phase}_{route}_denied" for phase in
     ("reviewer_rbac", "restart_reviewer_rbac", "service_account_deleted")
     for route in RENEW_ROUTES})
COMMON_CASES = frozenset({
    "kind_binary_pin", "candidate_source_freeze", "candidate_binary_pin",
    "official271_live_identity", "actual_apiserver_version", "actual_namespace_hb_review",
    "actual_namespace_hb_work", "actual_serviceaccount_uids_distinct",
    "actual_reviewer_rbac_admitted", "actual_issuer", "actual_tokenrequest_valid",
    "actual_tokenreview_metadata_audit_enabled",
    "actual_reviewer_rbac_revoked", "actual_reviewer_rbac_restored",
    "actual_serviceaccount_deleted", "actual_serviceaccount_uid_changed",
    "actual_metadata_audit_excludes_runtime_credentials", "denial_http_status_parity",
    "candidate_source_and_binary_unchanged", "owned_cluster_and_services_cleaned",
    "fixed_denominator_complete",
})
REQUIRED = COMMON_CASES | {f"{side}.{case}" for side in ("oracle271", "candidate") for case in SIDE_CASES}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_freeze(path, commit, tree):
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(path), *arguments], text=True).strip()
    return (git("rev-parse", "HEAD") == commit
            and git("rev-parse", "HEAD^{tree}") == tree
            and not git("status", "--porcelain", "--untracked-files=no"))


def validate_build_receipt(receipt, commit, tree, binary_digest):
    """Keep native-build admission identical to the mixed-native HA gate."""
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
        raise kube.FixtureFailure("native_build_receipt_binding_invalid")
    return receipt["native_abi"]


def read_build_receipt(path, expected_digest, commit, tree, binary_digest):
    """Admit the same bounded regular file bytes that supply the receipt hash."""
    if (not path.is_absolute() or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None):
        raise kube.FixtureFailure("native_build_receipt_input_invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise kube.FixtureFailure("native_build_receipt_not_regular")
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise kube.FixtureFailure("native_build_receipt_oversized")
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise kube.FixtureFailure("native_build_receipt_digest_mismatch")
    try:
        receipt = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise kube.FixtureFailure("native_build_receipt_invalid_json") from error
    return validate_build_receipt(receipt, commit, tree, binary_digest)


def owned_review_events(events, reviewer_uid, seen_audit_ids, expected_status):
    """A count increase alone cannot attribute a review to either service."""
    if len(events) != 1 or not isinstance(reviewer_uid, str) or not reviewer_uid:
        return False
    row = events[0]
    audit_id = row.get("auditID")
    user = row.get("user", {})
    resource = row.get("objectRef", {})
    valid = (isinstance(audit_id, str) and 1 <= len(audit_id) <= 128
             and audit_id not in seen_audit_ids
             and user.get("username") == "system:serviceaccount:hb-review:reviewer"
             and user.get("uid") == reviewer_uid
             and row.get("requestURI") == "/apis/authentication.k8s.io/v1/tokenreviews"
             and row.get("stage") == "ResponseComplete" and row.get("verb") == "create"
             and resource.get("apiGroup") == "authentication.k8s.io"
             and resource.get("apiVersion") == "v1" and resource.get("resource") == "tokenreviews"
             and row.get("responseStatus", {}).get("code") == expected_status)
    if valid:
        seen_audit_ids.add(audit_id)
    return valid


def renewed_token(result, token, route="self", accessor=None):
    auth = result.get("auth")
    if not isinstance(auth, dict) or auth.get("renewable") is not True:
        return False
    if route == "accessor":
        # Accessor renewal must not disclose the token's bearer credential.
        return (isinstance(accessor, str) and bool(accessor)
                and auth.get("accessor") == accessor and auth.get("client_token") in (None, ""))
    return auth.get("client_token") == token


def expiry_extended(before, after):
    try:
        first = datetime.fromisoformat(before.replace("Z", "+00:00"))
        second = datetime.fromisoformat(after.replace("Z", "+00:00"))
        return first.tzinfo is not None and second.tzinfo is not None and second > first
    except (TypeError, ValueError, AttributeError):
        return False


def capture_final_metadata(cluster, destination, secrets, report, expected_audit_ids):
    """The final required audit artifact is part of lifecycle success."""
    try:
        audit = cluster.audit()
        if not expected_audit_ids.issubset({row.get("auditID") for row in audit}):
            raise kube.FixtureFailure("final_metadata_missing_observed_audit_ids")
        encoded = json.dumps(audit, indent=2, sort_keys=True) + "\n"
        if any(value in encoded for value in secrets):
            raise kube.FixtureFailure("metadata_audit_contains_runtime_credential")
        destination.write_text(encoded)
        return True
    except Exception as error:
        report["metadata_capture_failure"] = type(error).__name__
        return False


def qualification_passed(report):
    """A complete denominator cannot override an evidence-capture failure."""
    checks = report.get("checks", [])
    return ("metadata_capture_failure" not in report and "failure_code" not in report
            and len(checks) == len(REQUIRED)
            and {row.get("case") for row in checks} == REQUIRED
            and all(row.get("passed") is True for row in checks))


class AuditCluster(kube.Cluster):
    """Use the existing strict generated-kubeconfig boundary and real API client."""
    def docker(self, *arguments, timeout=15):
        return subprocess.run(["docker", "--host", kube.DOCKER_SOCKET, *arguments],
                              env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout, check=False)

    def owned_node(self, container_id):
        result = self.docker("inspect", container_id)
        if result.returncode:
            raise kube.FixtureFailure("owned_node_inspection_failed")
        objects = json.loads(result.stdout)
        if len(objects) != 1:
            raise kube.FixtureFailure("owned_node_inspection_count")
        node = objects[0]
        if (node.get("Id") != container_id or len(container_id) != 64
                or node.get("Name") != "/" + self.name + "-control-plane"
                or node.get("Config", {}).get("Image") != kube.NODE_IMAGE
                or node.get("Config", {}).get("Labels", {}).get("io.x-k8s.kind.cluster") != self.name
                or not any(mount.get("Source") == str(self.root / "metadata-audit-policy.json")
                           and mount.get("Destination") == "/etc/kubernetes/hb-audit-policy.json"
                           and mount.get("RW") is False for mount in node.get("Mounts", []))):
            raise kube.FixtureFailure("owned_node_identity_rejected")
        return node

    def close(self):
        """Stop and remove only this exact disposable node, observing its exit.

        A forced KIND delete can deliver SIGKILL before Docker observes the
        systemd node's exit event. A timeout remains recorded, but removal only
        occurs after inspect establishes the same full ID is stopped/PID zero.
        No daemon restart, process wildcard, shared network or volume prune.
        """
        if not self.attempted:
            return
        receipt = {"cluster": self.name, "passed": False, "operations": []}
        try:
            listed = self.docker("ps", "-a", "--no-trunc", "--quiet", "--filter",
                                 "label=io.x-k8s.kind.cluster=" + self.name)
            if listed.returncode:
                raise kube.FixtureFailure("owned_node_inventory_failed")
            ids = listed.stdout.split()
            if len(ids) > 1:
                raise kube.FixtureFailure("unexpected_owned_node_count")
            if ids:
                cid = ids[0]
                node = self.owned_node(cid)
                started = node["State"]["StartedAt"]
                volumes = [mount["Name"] for mount in node["Mounts"] if mount["Type"] == "volume"]
                receipt.update(container_id=cid, before_state=node["State"], volumes=volumes,
                               exact_identity_verified=True)
                if node["State"]["Running"]:
                    try:
                        stopped = self.docker("stop", "--time", "30", cid, timeout=50)
                        receipt["operations"].append({"operation": "stop", "exit_code": stopped.returncode,
                                                       "stderr": stopped.stderr[:2048]})
                    except subprocess.TimeoutExpired:
                        receipt["operations"].append({"operation": "stop", "timeout": True})
                    until = time.monotonic() + 120
                    while True:
                        node = self.owned_node(cid)
                        if node["State"]["StartedAt"] != started:
                            raise kube.FixtureFailure("owned_node_restart_identity_changed")
                        if not node["State"]["Running"] and node["State"]["Pid"] == 0:
                            break
                        if time.monotonic() >= until:
                            raise kube.FixtureFailure("owned_node_exit_not_observed")
                        time.sleep(1)
                if node["State"]["Running"] or node["State"]["Pid"] != 0:
                    raise kube.FixtureFailure("owned_node_not_stopped")
                receipt["observed_stopped_state"] = node["State"]
                removed = self.docker("rm", "-v", cid, timeout=30)
                receipt["operations"].append({"operation": "remove_stopped_exact_id",
                                               "exit_code": removed.returncode, "stderr": removed.stderr[:2048]})
                if removed.returncode:
                    raise kube.FixtureFailure("owned_node_removal_failed")
                for volume in volumes:
                    result = self.docker("volume", "ls", "--quiet", "--filter", "name=" + volume)
                    if result.returncode or volume in result.stdout.split():
                        raise kube.FixtureFailure("owned_volume_remains")
            listed = self.docker("ps", "-a", "--no-trunc", "--quiet", "--filter",
                                 "label=io.x-k8s.kind.cluster=" + self.name)
            if listed.returncode or listed.stdout.strip():
                raise kube.FixtureFailure("owned_cluster_remains")
            receipt["passed"] = True
            self.attempted = False
        finally:
            kube.private(self.root / "owned-cleanup.json", (json.dumps(receipt, indent=2) + "\n").encode())

    def start(self):
        original = kube.private
        def write(path, data):
            if path.name == "kind.json":
                policy = self.root / "metadata-audit-policy.json"
                original(policy, json.dumps({
                    "apiVersion": "audit.k8s.io/v1", "kind": "Policy",
                    "rules": [{"level": "Metadata", "resources": [
                        {"group": "authentication.k8s.io", "resources": ["tokenreviews"]}]}],
                }).encode())
                configuration = json.loads(data)
                configuration["nodes"][0]["extraMounts"] = [{
                    "hostPath": str(policy), "containerPath": "/etc/kubernetes/hb-audit-policy.json",
                    "readOnly": True,
                }]
                # KIND v0.31.0 actually generates v1beta3 kubeadm documents for
                # this pinned node; v1beta4-only patches are silently unmatched.
                patch = {"apiVersion": "kubeadm.k8s.io/v1beta3", "kind": "ClusterConfiguration",
                         "apiServer": {"extraArgs": {
                             "audit-policy-file": "/etc/kubernetes/hb-audit-policy.json",
                             "audit-log-path": "/var/log/hb-audit/tokenreview.jsonl",
                             "audit-log-maxsize": "4", "audit-log-maxbackup": "1",
                         }, "extraVolumes": [
                             {"name": "hb-audit-policy", "hostPath": "/etc/kubernetes/hb-audit-policy.json",
                              "mountPath": "/etc/kubernetes/hb-audit-policy.json", "readOnly": True,
                              "pathType": "File"},
                             {"name": "hb-audit-log", "hostPath": "/var/log/hb-audit",
                              "mountPath": "/var/log/hb-audit", "readOnly": False,
                              "pathType": "DirectoryOrCreate"},
                         ]}}
                configuration["nodes"][0]["kubeadmConfigPatches"] = [json.dumps(patch)]
                data = json.dumps(configuration).encode()
            original(path, data)
        kube.private = write
        try:
            super().start()
        finally:
            kube.private = original

    def audit(self):
        result = subprocess.run(["docker", "--host", kube.DOCKER_SOCKET, "exec",
                                 self.name + "-control-plane", "cat",
                                 "/var/log/hb-audit/tokenreview.jsonl"], env=self.env,
                                capture_output=True, timeout=10, check=True)
        if len(result.stdout) > 8 * 1024 * 1024:
            raise kube.FixtureFailure("metadata_audit_bounds")
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
        if any("requestObject" in row or "responseObject" in row for row in records):
            raise kube.FixtureFailure("metadata_audit_contains_request_or_response_body")
        return [row for row in records if row.get("stage") == "ResponseComplete"
                and row.get("verb") == "create"
                and row.get("objectRef", {}).get("resource") == "tokenreviews"]

    def audit_after(self, before):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            records = self.audit()
            if len(records) > before:
                return records[before:]
            time.sleep(0.1)
        return []


class Side:
    def __init__(self, name, service=None, oracle=None):
        self.name, self.service, self.oracle = name, service, oracle
        self.tokens = {}
        self.accessors = {}

    def call(self, method, path, body=None, token=None):
        if self.service:
            return self.service.call(method, path, body, token=token)
        # The client requires a valid default credential; anonymous login is a
        # request override and must never replace that constructor credential.
        bearer = private_read(self.oracle["token_file"]).decode().strip()
        client = Client(self.oracle["address"], self.oracle["ca_file"], bearer, timeout=20)
        response = client.request(method, "/v1/" + path, body, token=token)
        return response.status, response.body

    def expiry(self, token):
        status, body = self.call("GET", "auth/token/lookup-self", token=token)
        value = body.get("data", {}).get("expire_time")
        if status != 200 or not isinstance(value, str) or not value:
            raise kube.FixtureFailure("issued_token_exact_expiry_unavailable_" + self.name)
        return value

    def login(self, jwt, role="worker"):
        return self.call("POST", "auth/" + MOUNT + "/login", {"role": role, "jwt": jwt}, token="")

    def renew(self, route):
        token = self.tokens["cidr" if route == "cidr" else "standard"]
        if route in ("self", "cidr"):
            return self.call("POST", "auth/token/renew-self", {"increment": 360}, token=token)
        if route == "admin":
            return self.call("POST", "auth/token/renew", {"token": token, "increment": 360})
        return self.call("POST", "auth/token/renew-accessor",
                         {"accessor": self.accessors["standard"], "increment": 360})

    def restart(self, unseal_key):
        if self.service:
            self.service.stop(); self.service.start()
            status, _ = self.call("POST", "sys/unseal", {"key": unseal_key})
            if status != 200:
                raise kube.FixtureFailure("candidate_restart_unseal_failed")
        else:
            stop_oracle(self.oracle)
            restart_oracle(self.oracle)

    def stop(self):
        if self.service:
            self.service.stop()
        elif self.oracle:
            stop_oracle(self.oracle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--candidate-source-root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--native-build-receipt", required=True, type=Path)
    parser.add_argument("--expected-native-build-receipt-sha256", required=True)
    parser.add_argument("--kind", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--allow-disposable-cluster", action="store_true")
    args = parser.parse_args()
    if not args.allow_disposable_cluster:
        parser.error("explicit disposable cluster authorization required")
    root = args.work_root
    if (not root.is_absolute() or root.exists()
            or root.parent.resolve(strict=True) != root.parent
            or root.parent.stat().st_uid != os.getuid() or root.parent.stat().st_mode & 0o022):
        parser.error("work-root must be new under its canonical owner-controlled parent")
    os.umask(0o077); root.mkdir(mode=0o700)
    report = {"schema": "heptabao.kubernetes271-genuine-renewal.v1", "status": "failed",
              "checks": [], "required_check_count": len(REQUIRED), "source_commit": args.source_commit,
              "source_tree": args.source_tree, "candidate_binary_sha256": args.expected_binary_sha256,
              "kind_version": kube.KIND_VERSION, "kind_binary_sha256": kube.KIND_SHA256,
              "runner_sha256": digest(__file__),
              "node_image": kube.NODE_IMAGE, "official_version": "2.7.1",
              "official_artifact_pins": pinned_artifact(version="2.7.1"),
              "native_build_receipt_sha256": args.expected_native_build_receipt_sha256,
              "native_build_receipt_verified": False,
              "production_authority": False, "full_openbao_compatibility": False,
              "scope": "new_disposable_genuine_kind_cluster_renewal_revocation_not_production"}
    phases = root / "phases"; phases.mkdir(mode=0o700)
    secrets = []
    cluster = None
    sides = []
    denial_statuses = {}
    reviewer_uid = None
    seen_audit_ids = set()
    positive_tokens = set()
    def save():
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if any(value and value in encoded for value in secrets):
            raise kube.FixtureFailure("report_contains_runtime_credential")
        temporary = root / "progress.copying"
        temporary.write_text(encoded); temporary.replace(root / "progress.json")
    def check(case, passed, **metadata):
        report["checks"].append({"case": case, "passed": passed is True, **metadata})
        save()
        (phases / f"{len(report['checks']):04d}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    def require(case, passed, **metadata):
        check(case, passed, **metadata)
        if not passed:
            raise kube.FixtureFailure(case)
    def mutation(side, case, method, path, body=None, expected=204):
        status, result = side.call(method, path, body)
        require(side.name + "." + case, status == expected, http_status=status)
        return result
    def review_metadata(events):
        return {"actual_tokenreview_count": len(events),
                "actual_tokenreview_status": [row.get("responseStatus", {}).get("code") for row in events],
                "actual_tokenreview_audit_ids": [row.get("auditID") for row in events],
                # UA is descriptive metadata; reviewer identity supplies admission.
                "actual_tokenreview_user_agents": [row.get("userAgent") for row in events]}
    def renewal(side, phase, route, deny, expected_api_status=None):
        key = "cidr" if route == "cidr" else "standard"
        token = side.tokens[key]
        expiry = side.expiry(token)
        before = len(cluster.audit())
        status, result = side.renew(route)
        events = cluster.audit_after(before)
        authority_absent = not result.get("auth") and not result.get("wrap_info")
        fresh = owned_review_events(events, reviewer_uid, seen_audit_ids, expected_api_status)
        name = phase + "_" + route + ("_denied" if deny else "")
        after = side.expiry(token)
        first_positive = not deny and (side.name, key) not in positive_tokens
        extended = expiry_extended(expiry, after) if first_positive else None
        identity_matches = renewed_token(result, token, route, side.accessors[key])
        valid = (400 <= status <= 599 and authority_absent and after == expiry
                 if deny else status == 200 and identity_matches
                 and (not first_positive or extended))
        if not deny:
            positive_tokens.add((side.name, key))
        check(side.name + "." + name, valid and fresh, http_status=status,
              **review_metadata(events),
              same_renewed_token=identity_matches if not deny and route != "accessor" else None,
              issued_accessor_matches=identity_matches if not deny and route == "accessor" else None,
              first_positive_expiry_extended=extended,
              no_authority=authority_absent if deny else None,
              exact_expiry_unchanged=after == expiry if deny else None)
        if deny:
            denial_statuses[(side.name, name)] = status
    try:
        require("kind_binary_pin", digest(args.kind) == kube.KIND_SHA256)
        kube.validate_binary(args.kind, kube.KIND_SHA256)
        native_abi = read_build_receipt(args.native_build_receipt, args.expected_native_build_receipt_sha256,
                                       args.source_commit, args.source_tree, args.expected_binary_sha256)
        report.update(native_build_receipt_verified=True, native_abi=native_abi)
        require("candidate_source_freeze", source_freeze(args.candidate_source_root, args.source_commit, args.source_tree),
                native_build_receipt_verified=True, native_abi=native_abi,
                native_build_receipt_sha256=args.expected_native_build_receipt_sha256)
        require("candidate_binary_pin", digest(args.binary) == args.expected_binary_sha256)
        cluster = AuditCluster(args.kind, root / "cluster"); cluster.start()
        status, version = cluster.call("GET", "/version")
        require("actual_apiserver_version", status == 200 and version.get("gitVersion") == "v1.35.0")
        report.update(actual_kube_apiserver=True, actual_etcd=True, actual_rbac=True,
                      cluster_name=cluster.name, apiserver_origin=cluster.origin)
        for namespace in ("hb-review", "hb-work"):
            value = cluster.post("/api/v1/namespaces", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
            require("actual_namespace_" + namespace.replace("-", "_"), bool(value["metadata"]["uid"]))
        reviewer = cluster.service_account("hb-review", "reviewer")
        worker = cluster.service_account("hb-work", "worker")
        reviewer_uid = reviewer["metadata"]["uid"]
        require("actual_serviceaccount_uids_distinct", isinstance(reviewer_uid, str) and bool(reviewer_uid)
                and reviewer_uid != worker["metadata"]["uid"])
        report["actual_reviewer_serviceaccount_uid"] = reviewer_uid
        cluster.post("/apis/rbac.authorization.k8s.io/v1/clusterroles", {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "hb-review-only"},
            "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}]})
        binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                   "metadata": {"name": "hb-review-only"},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "hb-review-only"},
                   "subjects": [{"kind": "ServiceAccount", "namespace": "hb-review", "name": "reviewer"}]}
        cluster.post("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", binding)
        cluster.await_review_permission(True); require("actual_reviewer_rbac_admitted", True)
        status, discovery = cluster.call("GET", "/.well-known/openid-configuration")
        issuer = discovery.get("issuer")
        require("actual_issuer", status == 200 and issuer == "https://kubernetes.default.svc.cluster.local")
        reviewer_jwt = cluster.token("hb-review", "reviewer", issuer)
        worker_jwt = cluster.token("hb-work", "worker", AUDIENCE)
        secrets.extend([reviewer_jwt, worker_jwt]); cluster.await_token_review(worker_jwt, True)
        require("actual_tokenrequest_valid", True)
        require("actual_tokenreview_metadata_audit_enabled", bool(cluster.audit()))
        seen_audit_ids.update(row.get("auditID") for row in cluster.audit())
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0)); oracle_port = connection.getsockname()[1]
        oracle = start_oracle(oracle_port, audit_file=True, version="2.7.1")
        sides.append(Side("oracle271", oracle=oracle))
        health = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip()).health()
        verify_selected_oracle(oracle, health, version="2.7.1")
        require("official271_live_identity", health["version"] == "2.7.1")
        service = Instance(args.binary, root / "candidate")
        sides.append(Side("candidate", service=service))
        cfg_path = service.root / "server.json"; cfg = json.loads(cfg_path.read_text())
        cfg["outbound_endpoints"] = [{"origin": cluster.origin, "address": cluster.origin.removeprefix("https://"),
                                     "server_name": "127.0.0.1", "ca_pem": cluster.ca.decode(), "path_prefix": "/"}]
        cfg_path.write_text(json.dumps(cfg)); service.start()
        status, initialized = service.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise kube.FixtureFailure("candidate_init_failed")
        service.token = initialized["root_token"]; unseal_key = initialized["keys_base64"][0]
        secrets.extend([service.token, unseal_key, private_read(oracle["token_file"]).decode().strip()])
        if service.call("POST", "sys/unseal", {"key": unseal_key})[0] != 200:
            raise kube.FixtureFailure("candidate_unseal_failed")
        role = {"bound_service_account_names": ["worker"], "bound_service_account_namespaces": ["hb-work"],
                "audience": AUDIENCE, "token_policies": ["hb-renew"], "token_ttl": 180, "token_max_ttl": 900}
        configuration = {"kubernetes_host": cluster.origin, "kubernetes_ca_cert": cluster.ca.decode(),
                         "token_reviewer_jwt": reviewer_jwt, "disable_local_ca_jwt": True,
                         "disable_iss_validation": True}
        for side in sides:
            mutation(side, "mount", "POST", "sys/auth/" + MOUNT, {"type": "kubernetes"})
            mutation(side, "config", "POST", "auth/" + MOUNT + "/config",
                     configuration if side.name == "oracle271" else {k:v for k,v in configuration.items() if k != "disable_iss_validation"})
            mutation(side, "policy", "PUT", "sys/policies/acl/hb-renew", {"policy":
                'path "auth/token/lookup-self" { capabilities = ["read"] }\npath "auth/token/renew-self" { capabilities = ["update"] }'})
            mutation(side, "role", "POST", "auth/" + MOUNT + "/role/worker", role)
            mutation(side, "cidr_role", "POST", "auth/" + MOUNT + "/role/worker-cidr", dict(role, token_bound_cidrs=["127.0.0.1/32"]))
            for key, selected in (("standard", "worker"), ("cidr", "worker-cidr")):
                before = len(cluster.audit()); status, logged = side.login(worker_jwt, selected)
                events = cluster.audit_after(before); auth = logged.get("auth", {})
                require(side.name + (".login" if key == "standard" else ".cidr_login"),
                        status == 200 and bool(auth.get("client_token")) and bool(auth.get("accessor"))
                        and auth.get("renewable") is True
                        and owned_review_events(events, reviewer_uid, seen_audit_ids, 201),
                        http_status=status, **review_metadata(events))
                side.tokens[key] = auth["client_token"]; side.accessors[key] = auth["accessor"]
                secrets.append(auth["client_token"])
            for route in RENEW_ROUTES:
                renewal(side, "positive", route, False, 201)
        require("actual_reviewer_rbac_revoked", cluster.call("DELETE", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/hb-review-only", {})[0] == 200)
        cluster.await_review_permission(False)
        for side in sides:
            for route in RENEW_ROUTES:
                renewal(side, "reviewer_rbac", route, True, 403)
        for side in sides:
            side.restart(unseal_key)
            check(side.name + ".restart_revocation_persists", True)
            for route in RENEW_ROUTES:
                renewal(side, "restart_reviewer_rbac", route, True, 403)
        cluster.post("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", binding)
        cluster.await_review_permission(True); require("actual_reviewer_rbac_restored", True)
        for side in sides:
            before = len(cluster.audit()); status, restored = side.renew("self"); events = cluster.audit_after(before)
            check(side.name + ".reviewer_restore_positive", status == 200
                  and renewed_token(restored, side.tokens["standard"])
                  and owned_review_events(events, reviewer_uid, seen_audit_ids, 201),
                  http_status=status, same_renewed_token=renewed_token(restored, side.tokens["standard"]),
                  **review_metadata(events))
        require("actual_serviceaccount_deleted", cluster.call("DELETE", "/api/v1/namespaces/hb-work/serviceaccounts/worker", {})[0] == 200)
        cluster.await_token_review(worker_jwt, False)
        for side in sides:
            for route in RENEW_ROUTES:
                renewal(side, "service_account_deleted", route, True, 201)
        recreated = cluster.service_account("hb-work", "worker")
        require("actual_serviceaccount_uid_changed", recreated["metadata"]["uid"] != worker["metadata"]["uid"])
        new_jwt = cluster.token("hb-work", "worker", AUDIENCE); secrets.append(new_jwt)
        for side in sides:
            before = len(cluster.audit()); status, result = side.login(new_jwt); events = cluster.audit_after(before)
            check(side.name + ".recreated_uid_login", status == 200 and bool(result.get("auth"))
                  and owned_review_events(events, reviewer_uid, seen_audit_ids, 201),
                  http_status=status, **review_metadata(events))
            if status == 200:
                secrets.append(result["auth"]["client_token"])
            before = len(cluster.audit()); status, result = side.login(worker_jwt); events = cluster.audit_after(before)
            check(side.name + ".old_uid_not_revived", status >= 400 and not result.get("auth")
                  and not result.get("wrap_info")
                  and owned_review_events(events, reviewer_uid, seen_audit_ids, 201),
                  http_status=status, **review_metadata(events))
            mutation(side, "auth_unmount", "DELETE", "sys/auth/" + MOUNT)
            check(side.name + ".unmount_revokes_token", side.call("GET", "auth/token/lookup-self", token=side.tokens["standard"])[0] == 403)
        audit = cluster.audit(); encoded_audit = json.dumps(audit)
        require("actual_metadata_audit_excludes_runtime_credentials", not any(value in encoded_audit for value in secrets))
        (root / "tokenreview-metadata.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
        check("denial_http_status_parity", all(denial_statuses.get(("oracle271", name)) == denial_statuses.get(("candidate", name))
                                             for name in {name for side, name in denial_statuses}), observed_denial_statuses={
                                                 side: {name: code for (owner, name), code in denial_statuses.items() if owner == side}
                                                 for side in ("oracle271", "candidate")})
        require("candidate_source_and_binary_unchanged", digest(args.binary) == args.expected_binary_sha256
                and source_freeze(args.candidate_source_root, args.source_commit, args.source_tree))
    except Exception as error:
        report["failure_code"] = str(error) if isinstance(error, kube.FixtureFailure) else type(error).__name__
        report["failure_stack"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                   for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        clean = True
        for side in reversed(sides):
            try:
                side.stop()
                report.setdefault("lifecycle_cleanup", {})[side.name] = {"passed": True}
            except Exception as error:
                clean = False
                report.setdefault("lifecycle_cleanup", {})[side.name] = {
                    "passed": False, "failure_type": type(error).__name__,
                    "stack": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                              for frame in traceback.extract_tb(error.__traceback__)]}
        if cluster is not None:
            if not capture_final_metadata(cluster, root / "tokenreview-metadata-final.json", secrets, report,
                                          seen_audit_ids):
                clean = False
            try:
                cluster.close()
                report.setdefault("lifecycle_cleanup", {})["cluster"] = {"passed": True}
            except Exception as error:
                clean = False
                report.setdefault("lifecycle_cleanup", {})["cluster"] = {"passed": False, "failure_type": type(error).__name__}
        check("owned_cluster_and_services_cleaned", clean)
        names = [row["case"] for row in report["checks"]]
        check("fixed_denominator_complete", set(names) == REQUIRED - {"fixed_denominator_complete"}
              and len(names) == len(set(names)) and all(row["passed"] for row in report["checks"]))
        if qualification_passed(report):
            report["status"] = "passed"
        save(); (root / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": report["status"], "checks": len(report["checks"]),
                          "required": len(REQUIRED), "failure_code": report.get("failure_code")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
