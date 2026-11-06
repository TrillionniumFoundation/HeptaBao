#!/usr/bin/env python3
"""One local-host stage of the synthetic two-physical-device sync qualification.

This is a manual qualification harness, not a sync daemon or a product pairing
protocol. An authenticated orchestrator transfers ONLY files in ``outbox`` to
the other role's ``inbox``. Never transfer ``private``, ``vault`` or plaintext
verification files. All secret generation and vault CLI stdin stay on clients.

Roles / phases (each uses a distinct private --root):
  B: prepare-peer -> adopt -> offline-b -> verify-local -> resolve-b -> recover
  A: seed -> offline-a -> verify-local
  S: store-seed -> store-a -> store-b-conflict -> store-b-resolved -> store-final

Transfer B/peer-public.pem to A; A/{seed-public.json,seed-request.json} to S.
After store-seed, transfer S/seed.hbv and A/{seed-public.json,enrollment.rsa} to
B for adoption. Transfer S/seed-receipt.json to A+B before the offline phases.
Transfer A/a-request.json and B/b-request.json to S.
After the successful A publication and rejected B publication, transfer
S/{a-receipt.json,b-conflict.json} to B and S/a-receipt.json to A. Transfer
B/b-resolved-request.json to S only AFTER verify-local has proved the rejected
branch still exists. This explicit publication preserves B as a second history;
it is not an automatic merge. Transfer S/{a-receipt.json,b-receipt.json,
fetch-a.hbv,fetch-b.hbv} and A/a-public.json to B for fresh-root recovery.

OpenSSL RSA-3072 OAEP-SHA256 is solely test enrollment: B retains the private
key, A encrypts random synthetic password/recovery material to B's public key.
The orchestrator must verify each transferred file's SHA256 and destination
version through its authenticated transport. Python does not promise memory
zeroization. Do not run this harness with real credentials.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time


MAX_FILE = 6 * 1024 * 1024
ITEM_ID = "synthetic-two-device-login"
ORIGIN = "https://sync-qualification.example.test"
PHASES = (
    "prepare-peer", "seed", "adopt", "offline-a", "offline-b", "verify-local",
    "resolve-b", "recover", "store-seed", "store-a", "store-b-conflict",
    "store-b-resolved", "store-final",
)


class QualificationError(Exception):
    """Fixed, non-secret error codes only; never include subprocess output."""


def require(condition, code):
    if not condition:
        raise QualificationError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def private_dir(path, create=False):
    require(path.is_absolute() and ".." not in path.parts, "invalid_path")
    for component in [*reversed(path.parents), path]:
        if component.exists() or component.is_symlink():
            require(not component.is_symlink(), "symlink_path")
    if create:
        path.mkdir(mode=0o700)
    meta = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
            and stat.S_IMODE(meta.st_mode) == 0o700, "private_directory_required")


def read_private(path):
    private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
                and meta.st_uid == os.getuid() and stat.S_IMODE(meta.st_mode) == 0o600
                and meta.st_size <= MAX_FILE, "private_file_required")
        data = stream.read(MAX_FILE + 1)
    require(len(data) <= MAX_FILE, "input_limit")
    return data


def write_private(path, data, replace=False):
    private_dir(path.parent)
    require(len(data) <= MAX_FILE, "output_limit")
    if replace:
        read_private(path)
    else:
        require(not path.exists() and not path.is_symlink(), "output_exists")
    temporary = path.parent / ("pending-" + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path):
    return json.loads(read_private(path))


def write_json(path, value, replace=False):
    write_private(path, encoded(value) + b"\n", replace)


def fingerprint(path):
    data = read_private(path)
    return {"sha256": digest(data), "bytes": len(data)}


def validate_vault_id(vault_id):
    require(isinstance(vault_id, str) and len(vault_id) == 22, "invalid_vault_id")
    raw = base64.b64decode(vault_id + "==", validate=True)
    require(len(raw) == 16 and base64.b64encode(raw).decode().rstrip("=") == vault_id,
            "invalid_vault_id")


def host_identity(root):
    def optional_text(path):
        try:
            return Path(path).read_text().strip()[:160]
        except OSError:
            return None
    machine = optional_text("/etc/machine-id")
    space = shutil.disk_usage(root)
    return {
        "hostname": platform.node(), "system": platform.system(),
        "architecture": platform.machine(),
        "machine_id_sha256": digest(machine.encode()) if machine else None,
        "dmi_vendor": optional_text("/sys/class/dmi/id/sys_vendor"),
        "dmi_product": optional_text("/sys/class/dmi/id/product_name"),
        "disk_total_bytes": space.total, "disk_free_bytes": space.free,
    }


class Run:
    def __init__(self, args):
        self.root = args.root.absolute()
        self.bin = args.bin_dir.absolute()
        self.phase = args.phase
        self.run_id = args.run_id
        require(re.fullmatch(r"[A-Za-z0-9_-]{16,48}", self.run_id), "invalid_run_id")
        os.umask(0o077)
        if self.phase in ("prepare-peer", "seed", "store-seed"):
            private_dir(self.root, create=True)
            for name in ("inbox", "outbox", "evidence", "private", "checks"):
                private_dir(self.root / name, create=True)
        else:
            private_dir(self.root)
        # Incoming files may be staged in a sibling private directory before
        # the root exists. Copy, never overwrite, only the explicitly named set.
        if args.incoming is not None:
            private_dir(args.incoming.absolute())
            allowed = {
                "seed": ("peer-public.pem",),
                "store-seed": ("seed-public.json", "seed-request.json"),
            }.get(self.phase)
            require(allowed is not None, "incoming_phase_invalid")
            for name in allowed:
                write_private(self.root / "inbox" / name, read_private(args.incoming / name))
        self.results = {}

    def call(self, name, arguments, request, error=None):
        result = subprocess.run(
            [str(self.bin / name), *map(str, arguments)], input=encoded(request),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
            check=False,
        )
        require(len(result.stdout) <= MAX_FILE and len(result.stderr) <= 4096,
                "cli_output_limit")
        # Do not relay process errors, request strings, or decrypted values.
        response = json.loads(result.stdout or result.stderr)
        if error is None:
            require(result.returncode == 0 and response.get("ok", True), "cli_failed")
        else:
            require(result.returncode != 0 and response.get("error") == error,
                    "expected_denial_missing")
        if name == "heptabao-vault":
            for field in ("password", "recovery_key"):
                value = request.get(field)
                require(not value or value.encode() not in result.stdout + result.stderr,
                        "secret_in_cli_output")
            item = request.get("item")
            require(not item or item["secret"].encode() not in result.stdout + result.stderr,
                    "secret_in_cli_output")
        return response

    def vault(self, command, request, root=None):
        return self.call("heptabao-vault", [root or self.root / "vault", command], request)

    def sync(self, request, error=None):
        public = read_json(self.root / "store-public.json")
        return self.call("heptabao-sync", [self.root / "data", public["vault_id"]],
                         request, error)

    def openssl(self, arguments, data=b""):
        result = subprocess.run(["/usr/bin/openssl", *map(str, arguments)], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 16384, "enrollment_failed")
        return result.stdout

    def credentials(self):
        return read_json(self.root / "private" / "credentials.json")

    def public(self):
        value = read_json(self.root / "client-public.json")
        require(value["run_id"] == self.run_id, "run_mismatch")
        return value

    def verify_item(self, vault_root, credentials, expected_digest, label, recovery=False):
        output = self.root / "checks" / (label + ".json")
        auth = {"recovery_key": credentials["recovery_key"]} if recovery else {
            "password": credentials["password"]}
        result = self.vault("get", {**auth, "id": ITEM_ID, "output": str(output)}, vault_root)
        item = read_json(output)
        require(digest(encoded(item)) == expected_digest, "restored_content_mismatch")
        require(item["origin"] == ORIGIN and item["id"] == ITEM_ID, "item_target_mismatch")
        output.unlink()
        return result["metadata"]

    def snapshot(self, label, credentials):
        path = self.root / "outbox" / (label + ".hbv")
        metadata = self.vault("backup", {"password": credentials["password"],
                              "output": str(path)})["metadata"]
        data = read_private(path)
        require(data == read_private(self.root / "vault" / "vault.hbv"), "backup_mismatch")
        for value in (credentials["password"], credentials["recovery_key"],
                      credentials["item"]["secret"]):
            require(value.encode() not in data, "plaintext_in_ciphertext")
        info = {"run_id": self.run_id, "vault_id": metadata["vault_id"],
                "revision": metadata["revision"], "label": label,
                "ciphertext_sha256": digest(data), "ciphertext_bytes": len(data),
                "item_sha256": digest(encoded(credentials["item"]))}
        write_json(self.root / "outbox" / (label + "-public.json"), info)
        return info

    def request(self, label, expected_head, suffix=None):
        data = read_private(self.root / "outbox" / (label + ".hbv"))
        name = suffix or label
        request = {"op": "publish", "operation_id": self.run_id + "-" + name,
                   "expected_head": expected_head, "ciphertext": base64.b64encode(data).decode()}
        write_json(self.root / "outbox" / (name + "-request.json"), request)

    def prepare_peer(self):
        key = self.root / "private" / "enrollment-private.pem"
        self.openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                      "-out", key])
        require(stat.S_IMODE(key.stat().st_mode) == 0o600, "private_key_permissions")
        public = self.openssl(["pkey", "-in", key, "-pubout"])
        write_private(self.root / "outbox" / "peer-public.pem", public)
        write_json(self.root / "peer-public.json", {"run_id": self.run_id,
                   "peer_public_sha256": digest(public)})
        self.results = {"peer_public_sha256": digest(public), "private_key_exported": False}

    def seed(self):
        private_dir(self.root / "vault", create=True)
        credentials = {"password": secrets.token_urlsafe(32), "item": {
            "id": ITEM_ID, "kind": "login", "title": "Synthetic two device login",
            "username": "synthetic-account@example.test", "origin": ORIGIN,
            "secret": secrets.token_urlsafe(32), "notes": "synthetic initial branch", "totp": None}}
        result = self.vault("init", {"password": credentials["password"],
                           "output": str(self.root / "private" / "recovery.json")})
        vault_id = result["metadata"]["vault_id"]
        validate_vault_id(vault_id)
        credentials["recovery_key"] = read_json(self.root / "private" / "recovery.json")["recovery_key"]
        write_json(self.root / "private" / "credentials.json", credentials)
        self.vault("put", {"password": credentials["password"], "expected_revision": 0,
                           "item": credentials["item"]})
        info = self.snapshot("seed", credentials)
        write_json(self.root / "client-public.json", {"run_id": self.run_id,
                   "vault_id": vault_id, "branch": "seed", "device": "a"})
        enrollment = encoded({"v": 1, "r": self.run_id, "i": vault_id,
                              "p": credentials["password"], "k": credentials["recovery_key"]})
        require(len(enrollment) <= 318, "enrollment_limit")
        capsule = self.openssl(["pkeyutl", "-encrypt", "-pubin", "-inkey",
                               self.root / "inbox" / "peer-public.pem", "-pkeyopt",
                               "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                               "-pkeyopt", "rsa_mgf1_md:sha256"], enrollment)
        write_private(self.root / "outbox" / "enrollment.rsa", capsule)
        self.request("seed", None)
        self.results = {**info, "enrollment_sha256": digest(capsule),
                        "peer_public": fingerprint(self.root / "inbox" / "peer-public.pem")}

    def adopt(self):
        peer = read_json(self.root / "peer-public.json")
        require(peer["run_id"] == self.run_id, "run_mismatch")
        capsule = read_private(self.root / "inbox" / "enrollment.rsa")
        raw = self.openssl(["pkeyutl", "-decrypt", "-inkey",
                            self.root / "private" / "enrollment-private.pem", "-pkeyopt",
                            "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                            "-pkeyopt", "rsa_mgf1_md:sha256"], capsule)
        material = json.loads(raw)
        require(material["v"] == 1 and material["r"] == self.run_id, "enrollment_binding")
        info = read_json(self.root / "inbox" / "seed-public.json")
        require(info["run_id"] == self.run_id and info["vault_id"] == material["i"], "seed_binding")
        data = read_private(self.root / "inbox" / "seed.hbv")
        require(digest(data) == info["ciphertext_sha256"], "seed_digest")
        private_dir(self.root / "vault", create=True)
        result = self.vault("restore", {"password": material["p"],
                           "input": str(self.root / "inbox" / "seed.hbv")})
        require(result["metadata"]["vault_id"] == material["i"], "restored_vault_id")
        output = self.root / "private" / "initial-item.json"
        self.vault("get", {"password": material["p"], "id": ITEM_ID, "output": str(output)})
        item = read_json(output)
        require(digest(encoded(item)) == info["item_sha256"], "restored_content_mismatch")
        output.unlink()
        credentials = {"password": material["p"], "recovery_key": material["k"], "item": item}
        write_json(self.root / "private" / "credentials.json", credentials)
        write_json(self.root / "private" / "recovery.json", {"format": "heptabao-personal-recovery-v1",
                   "vault_id": material["i"], "recovery_key": material["k"]})
        write_json(self.root / "client-public.json", {"run_id": self.run_id,
                   "vault_id": material["i"], "branch": "seed", "device": "b"})
        own_backup = self.snapshot("seed", credentials)
        require(own_backup == info, "initial_copies_differ")
        self.results = {**info, "initial_copy_verified": True, "enrollment_plaintext_exported": False}

    def offline(self, branch):
        public = self.public()
        require(public["device"] == branch and public["branch"] == "seed", "wrong_offline_stage")
        receipt = read_json(self.root / "inbox" / "seed-receipt.json")["receipt"]
        seed = read_json(self.root / "outbox" / "seed-public.json")
        require(receipt["ciphertext_sha256"] == seed["ciphertext_sha256"]
                and receipt["generation"] == 1, "seed_receipt_mismatch")
        credentials = self.credentials()
        credentials["item"]["secret"] = secrets.token_urlsafe(32)
        credentials["item"]["notes"] = "synthetic independent offline branch " + branch
        self.vault("put", {"password": credentials["password"], "expected_revision": 1,
                           "item": credentials["item"]})
        write_json(self.root / "private" / "credentials.json", credentials, replace=True)
        public["branch"] = branch
        write_json(self.root / "client-public.json", public, replace=True)
        info = self.snapshot(branch, credentials)
        require(info["revision"] == 2, "offline_revision")
        self.request(branch, receipt["head_id"])
        self.verify_item(self.root / "vault", credentials, info["item_sha256"], "offline-" + branch)
        self.results = {**info, "observed_head_id": receipt["head_id"],
                        "observed_generation": 1, "edit_mode": "local_without_sync_calls"}

    def verify_local(self):
        public = self.public()
        branch = public["branch"]
        require(branch in ("a", "b"), "missing_offline_branch")
        info = read_json(self.root / "outbox" / (branch + "-public.json"))
        data = read_private(self.root / "vault" / "vault.hbv")
        require(digest(data) == info["ciphertext_sha256"]
                and data == read_private(self.root / "outbox" / (branch + ".hbv")), "local_data_changed")
        self.verify_item(self.root / "vault", self.credentials(), info["item_sha256"], "preserved-" + branch)
        receipt = read_json(self.root / "inbox" / "a-receipt.json")["receipt"]
        require(receipt["generation"] == 2 and receipt["operation_id"] == self.run_id + "-a",
                "first_push_receipt")
        if branch == "a":
            require(receipt["ciphertext_sha256"] == info["ciphertext_sha256"], "first_push_digest")
        else:
            rejected = read_json(self.root / "inbox" / "b-conflict.json")
            attempted = read_json(self.root / "outbox" / "b-request.json")
            require(rejected["error"] == "Conflict" and rejected["head"] == receipt,
                    "conflict_not_observed")
            require(rejected["rejected_operation_id"] == attempted["operation_id"] == self.run_id + "-b"
                    and rejected["rejected_expected_head"] == attempted["expected_head"]
                    and attempted["expected_head"] != receipt["head_id"]
                    and rejected["rejected_ciphertext_sha256"] == info["ciphertext_sha256"]
                    and digest(base64.b64decode(attempted["ciphertext"], validate=True)) == info["ciphertext_sha256"],
                    "conflict_request_binding")
        self.results = {**info, "local_vault_and_backup_preserved": True,
                        "plaintext_verified_locally": True, "prior_publish": "accepted" if branch == "a" else "Conflict"}

    def resolve_b(self):
        public = self.public()
        require(public["branch"] == "b", "branch_b_required")
        verified = read_json(self.root / "evidence" / "verify-local.json")
        info = read_json(self.root / "outbox" / "b-public.json")
        require(verified["run_id"] == self.run_id and verified["phase"] == "verify-local"
                and verified["results"]["vault_id"] == public["vault_id"]
                and verified["results"]["label"] == "b"
                and verified["results"]["ciphertext_sha256"] == info["ciphertext_sha256"]
                == fingerprint(self.root / "vault" / "vault.hbv")["sha256"]
                and verified["results"]["prior_publish"] == "Conflict"
                and verified["results"]["local_vault_and_backup_preserved"], "preservation_not_verified")
        receipt = read_json(self.root / "inbox" / "a-receipt.json")["receipt"]
        self.request("b", receipt["head_id"], "b-resolved")
        self.results = {"explicit_branch_publication": True, "automatic_merge": False,
                        "expected_head_id": receipt["head_id"], "expected_generation": 2,
                        "local_ciphertext_sha256": fingerprint(self.root / "vault" / "vault.hbv")["sha256"]}

    def store_seed(self):
        public = read_json(self.root / "inbox" / "seed-public.json")
        require(public["run_id"] == self.run_id, "run_mismatch")
        validate_vault_id(public["vault_id"])
        write_json(self.root / "store-public.json", {"run_id": self.run_id, "vault_id": public["vault_id"]})
        private_dir(self.root / "data", create=True)
        self.store_publish("seed", 1)
        receipt = self.results["receipt"]
        require(receipt["ciphertext_sha256"] == public["ciphertext_sha256"], "initial_store_digest")
        fetched = self.sync({"op": "fetch", "ciphertext_sha256": receipt["ciphertext_sha256"]})
        data = base64.b64decode(fetched["ciphertext"], validate=True)
        require(digest(data) == public["ciphertext_sha256"], "initial_fetch_digest")
        write_private(self.root / "outbox" / "seed.hbv", data)
        self.results["initial_ciphertext_fetch_verified"] = True

    def store_publish(self, label, generation, conflict=False):
        request = read_json(self.root / "inbox" / (label + "-request.json"))
        require(set(request) == {"op", "operation_id", "expected_head", "ciphertext"}
                and request["operation_id"] == self.run_id + "-" + label, "request_binding")
        before = self.sync({"op": "head"})["head"]
        if conflict:
            response = self.sync(request, error="Conflict")
            require(self.sync({"op": "head"})["head"] == before, "conflict_changed_head")
            self.sync({"op": "receipt", "operation_id": request["operation_id"]}, error="NotFound")
            denied = {"error": response["error"], "head": before,
                      "rejected_operation_id": request["operation_id"],
                      "rejected_expected_head": request["expected_head"],
                      "rejected_ciphertext_sha256": digest(base64.b64decode(request["ciphertext"], validate=True))}
            write_json(self.root / "outbox" / "b-conflict.json", denied)
            self.results = {**denied, "head_unchanged": True, "receipt_absent": True,
                            "cli_exit_nonzero": True}
            return
        receipt = self.sync(request)["receipt"]
        require(receipt["generation"] == generation, "publication_generation")
        require(self.sync(request)["receipt"] == receipt, "publication_replay_changed")
        require(self.sync({"op": "receipt", "operation_id": request["operation_id"]})["receipt"] == receipt,
                "receipt_recovery_failed")
        require(self.sync({"op": "head"})["head"] == receipt, "head_receipt_mismatch")
        saved_label = "b" if label == "b-resolved" else label
        write_json(self.root / "outbox" / (saved_label + "-receipt.json"), {"receipt": receipt})
        self.results = {"receipt": receipt, "exact_request_replay_stable": True,
                        "independent_process_receipt_recovery": True}

    def store_final(self):
        receipts = {}
        for label in ("seed", "a", "b"):
            receipt = read_json(self.root / "outbox" / (label + "-receipt.json"))["receipt"]
            fetched = self.sync({"op": "fetch", "ciphertext_sha256": receipt["ciphertext_sha256"]})
            data = base64.b64decode(fetched["ciphertext"], validate=True)
            require(digest(data) == receipt["ciphertext_sha256"], "fetched_ciphertext_digest")
            envelope = json.loads(data)
            require("password_wrap" in envelope and "recovery_wrap" in envelope
                    and "body" in envelope and "password" not in envelope
                    and "recovery_key" not in envelope and "items" not in envelope,
                    "opaque_ciphertext_required")
            if label != "seed":
                write_private(self.root / "outbox" / ("fetch-" + label + ".hbv"), data)
            receipts[label] = receipt
        require(receipts["a"]["ciphertext_sha256"] != receipts["b"]["ciphertext_sha256"], "branches_not_distinct")
        inventory = {}
        for path in sorted((self.root / "data").iterdir()):
            require(path.name == "state.json" or re.fullmatch(r"ciphertext-[0-9a-f]{64}\.bin", path.name),
                    "unexpected_store_file")
            inventory[path.name] = fingerprint(path)
        require(len(inventory) == 4, "history_inventory_count")
        self.results = {"receipts": receipts, "inventory": inventory,
                        "retained_initial_and_both_branches": True,
                        "server_received_unlock_material": False}

    def recover(self):
        credentials = self.credentials()
        public = self.public()
        restored = {}
        before = fingerprint(self.root / "vault" / "vault.hbv")
        for label in ("a", "b"):
            receipt = read_json(self.root / "inbox" / (label + "-receipt.json"))["receipt"]
            info = read_json(self.root / ("inbox" if label == "a" else "outbox") / (label + "-public.json"))
            require(info["run_id"] == self.run_id and info["vault_id"] == public["vault_id"], "history_vault_binding")
            incoming = self.root / "inbox" / ("fetch-" + label + ".hbv")
            require(fingerprint(incoming)["sha256"] == receipt["ciphertext_sha256"] == info["ciphertext_sha256"],
                    "history_ciphertext_mismatch")
            target = self.root / ("recovered-" + label)
            private_dir(target, create=True)
            auth = {"password": credentials["password"]} if label == "a" else {
                "recovery_key": credentials["recovery_key"]}
            result = self.vault("restore", {**auth, "input": str(incoming)}, target)
            require(result["metadata"]["vault_id"] == public["vault_id"]
                    and result["metadata"]["revision"] == 2, "history_metadata_mismatch")
            self.verify_item(target, credentials, info["item_sha256"], "restored-" + label, recovery=label == "b")
            restored[label] = {"ciphertext_sha256": info["ciphertext_sha256"],
                               "item_sha256": info["item_sha256"], "metadata": result["metadata"],
                               "unlock_method": "password" if label == "a" else "recovery_key",
                               "fresh_root_and_process": True}
        require(restored["a"]["item_sha256"] != restored["b"]["item_sha256"], "branch_contents_not_distinct")
        require(fingerprint(self.root / "vault" / "vault.hbv") == before, "recovery_changed_original")
        self.results = {"restored": restored, "both_histories_verified": True,
                        "different_plaintext_branches_verified": True,
                        "original_device_vault_preserved": True, "third_physical_host_claimed": False}

    def finish(self):
        manifest = {"schema": "heptabao-two-device-qualification-v1", "synthetic_only": True,
                    "run_id": self.run_id, "phase": self.phase, "ok": True,
                    "unix_seconds": int(time.time()), "host": host_identity(self.root),
                    "harness_sha256": digest(Path(__file__).read_bytes()),
                    "binary_sha256": {name: digest((self.bin / name).read_bytes()) for name in
                                      ("heptabao-vault", "heptabao-sync")},
                    "results": self.results}
        path = self.root / "evidence" / (self.phase + ".json")
        write_json(path, manifest)
        print(json.dumps({"ok": True, "phase": self.phase, "manifest": str(path),
                          "manifest_sha256": digest(read_private(path)), "results": self.results}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--incoming", type=Path, help="Private pre-staged public/ciphertext inputs for new seed/store roots only")
    args = parser.parse_args()
    run = Run(args)
    phases = {
        "prepare-peer": run.prepare_peer, "seed": run.seed, "adopt": run.adopt,
        "offline-a": lambda: run.offline("a"), "offline-b": lambda: run.offline("b"),
        "verify-local": run.verify_local, "resolve-b": run.resolve_b,
        "recover": run.recover, "store-seed": run.store_seed,
        "store-a": lambda: run.store_publish("a", 2),
        "store-b-conflict": lambda: run.store_publish("b", 0, conflict=True),
        "store-b-resolved": lambda: run.store_publish("b-resolved", 3),
        "store-final": run.store_final,
    }
    phases[args.phase]()
    run.finish()


if __name__ == "__main__":
    try:
        main()
    except QualificationError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "stage_failed_inspect_private_state"}), file=sys.stderr)
        sys.exit(1)
