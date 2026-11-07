#!/usr/bin/env python3
"""Actual independent-process vault/native-message/sync qualification, synthetic only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target/debug"
PASSWORD = "synthetic-master-OnlyForQualification-2026"
SECRET = "synthetic-login-Secret-Unique-Edge-2026"
USER = "synthetic-account@example.test"
ORIGIN = "https://login.example.test"


def invoke(binary, args, request, ok=True):
    result = subprocess.run([str(BIN / binary), *map(str, args)], input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if ok and result.returncode != 0:
        raise AssertionError(f"{binary} rejected with code {result.returncode}: {(result.stderr or result.stdout).decode()}")
    if not ok and result.returncode == 0:
        raise AssertionError(f"{binary} unexpectedly accepted")
    return json.loads(result.stdout or result.stderr)


class EdgeLive(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="heptabao-edge-")
        self.base = Path(self.temp.name).resolve()
        self.vault = self.base / "vault"
        self.vault.mkdir(mode=0o700)
        initialized = invoke("heptabao-vault", [self.vault, "init"], {"password": PASSWORD, "output": str(self.base / "recovery.json")})
        self.vault_id = initialized["metadata"]["vault_id"]
        self.item = {"id": "synthetic-login", "kind": "login", "title": "Synthetic login", "username": USER, "origin": ORIGIN, "secret": SECRET, "notes": "", "totp": None}
        invoke("heptabao-vault", [self.vault, "put"], {"password": PASSWORD, "expected_revision": 0, "item": self.item})
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.stdin.close()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed: stream.close()
        self.temp.cleanup()

    def native(self, ttl=60):
        config = self.base / f"native-{len(self.processes)}.json"
        config.write_text(json.dumps({"vault_root": str(self.vault), "extension_id": "a" * 32, "unlock_seconds": ttl}))
        config.chmod(0o600)
        process = subprocess.Popen([str(BIN / "heptabao-browser"), "--config", str(config), "chrome-extension://" + "a" * 32 + "/"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        return process

    @staticmethod
    def frame(process, request, number=1):
        raw = json.dumps({"id": number, "request": request}).encode()
        process.stdin.write(struct.pack("=I", len(raw)) + raw)
        process.stdin.flush()
        header = process.stdout.read(4)
        if len(header) != 4:
            raise AssertionError("native host exited before complete response")
        length = struct.unpack("=I", header)[0]
        if length > 131072:
            raise AssertionError("native response exceeded bound")
        return json.loads(process.stdout.read(length))

    def test_native_exact_origin_lock_expiry_and_reopen(self):
        process = self.native(ttl=2)
        self.assertFalse(self.frame(process, {"op": "fill", "origin": ORIGIN, "item_id": self.item["id"], "top_frame": True})["ok"])
        self.assertTrue(self.frame(process, {"op": "unlock", "password": PASSWORD})["ok"])
        found = self.frame(process, {"op": "list", "origin": ORIGIN})
        self.assertEqual(len(found["result"]), 1)
        self.assertNotIn(SECRET, json.dumps(found))
        for origin, top in [(ORIGIN + ".evil.test", True), ("http://login.example.test", True), (ORIGIN, False)]:
            self.assertFalse(self.frame(process, {"op": "fill", "origin": origin, "item_id": self.item["id"], "top_frame": top})["ok"])
        allowed = self.frame(process, {"op": "fill", "origin": ORIGIN, "item_id": self.item["id"], "top_frame": True})
        self.assertEqual(allowed["result"]["password"], SECRET)
        time.sleep(2.2)
        self.assertFalse(self.frame(process, {"op": "fill", "origin": ORIGIN, "item_id": self.item["id"], "top_frame": True})["ok"])
        process.stdin.close(); process.wait(timeout=3)
        self.assertEqual(process.stderr.read(), b"")
        # New process can decrypt persisted ciphertext; old session is gone.
        reopened = self.native()
        self.assertTrue(self.frame(reopened, {"op": "status"})["result"]["locked"])
        self.assertFalse(self.frame(reopened, {"op": "unlock", "password": "wrong-key-should-never-unlock"})["ok"])
        self.assertTrue(self.frame(reopened, {"op": "unlock", "password": PASSWORD})["ok"])
        self.assertTrue(self.frame(reopened, {"op": "lock"})["result"]["locked"])

    def test_ciphertext_sync_conflict_receipt_and_aba(self):
        store = self.base / "sync"; store.mkdir(mode=0o700)
        ciphertext = (self.vault / "vault.hbv").read_bytes()
        self.assertNotIn(SECRET.encode(), ciphertext)
        def call(request, ok=True): return invoke("heptabao-sync", [store, self.vault_id], request, ok)
        request_a = {"op": "publish", "operation_id": "device-a-operation-0001", "expected_head": None, "ciphertext": base64.b64encode(ciphertext).decode()}
        first = call(request_a)["receipt"]
        self.assertEqual(call(request_a)["receipt"], first)  # lost-ACK replay, new process
        self.assertEqual(call({"op": "receipt", "operation_id": request_a["operation_id"]})["receipt"], first)
        # A second physical ciphertext version exists before any store mutation.
        changed_item = {**self.item, "secret": "synthetic-new-secret-device-B"}
        invoke("heptabao-vault", [self.vault, "put"], {"password": PASSWORD, "expected_revision": 1, "item": changed_item})
        changed = (self.vault / "vault.hbv").read_bytes()
        request_b = {"op": "publish", "operation_id": "device-b-operation-0002", "expected_head": first["head_id"], "ciphertext": base64.b64encode(changed).decode()}
        second = call(request_b)["receipt"]
        stale = {**request_a, "operation_id": "offline-a-operation-0003", "expected_head": first["head_id"]}
        self.assertEqual(call(stale, False)["error"], "Conflict")
        self.assertEqual(call({**request_b, "ciphertext": request_a["ciphertext"]}, False)["error"], "OperationConflict")
        third = call({**request_a, "operation_id": "restore-a-operation-0004", "expected_head": second["head_id"]})["receipt"]
        self.assertEqual(first["ciphertext_sha256"], third["ciphertext_sha256"])
        self.assertNotEqual(first["head_id"], third["head_id"])
        self.assertEqual(call(stale, False)["error"], "Conflict")
        # Both complete versions remain recoverable. No silent overwrite or merge.
        for receipt, expected in [(first, ciphertext), (second, changed)]:
            fetched = call({"op": "fetch", "ciphertext_sha256": receipt["ciphertext_sha256"]})
            self.assertEqual(base64.b64decode(fetched["ciphertext"]), expected)
        self.assertEqual(call(request_a)["receipt"], first)
        self.assertEqual(call({"op": "head"})["head"], third)
        recovered = self.base / "device-c"; recovered.mkdir(mode=0o700)
        backup = self.base / "encrypted-backup.hbv"; backup.write_bytes(changed); backup.chmod(0o600)
        invoke("heptabao-vault", [recovered, "restore"], {"password": PASSWORD, "input": str(backup)})
        out = self.base / "restored-item.json"
        invoke("heptabao-vault", [recovered, "get"], {"password": PASSWORD, "id": self.item["id"], "output": str(out)})
        self.assertEqual(json.loads(out.read_text())["secret"], changed_item["secret"])
        for path in store.iterdir():
            if path.is_file(): self.assertNotIn(SECRET.encode(), path.read_bytes())

    def test_store_rejects_tamper_cross_vault_and_nonprivate_root(self):
        store = self.base / "sync"; store.mkdir(mode=0o700)
        ciphertext = (self.vault / "vault.hbv").read_bytes()
        request = {"op": "publish", "operation_id": "synthetic-operation-001", "expected_head": None, "ciphertext": base64.b64encode(ciphertext).decode()}
        receipt = invoke("heptabao-sync", [store, self.vault_id], request)["receipt"]
        self.assertEqual(invoke("heptabao-sync", [store, "AAAAAAAAAAAAAAAAAAAAAA"], {"op": "head"}, False)["error"], "CorruptState")
        blob = store / ("ciphertext-" + receipt["ciphertext_sha256"] + ".bin")
        blob.write_bytes(b"corrupt")
        self.assertEqual(invoke("heptabao-sync", [store, self.vault_id], {"op": "head"}, False)["error"], "CorruptState")
        store.chmod(0o755)
        self.assertEqual(invoke("heptabao-sync", [store, self.vault_id], {"op": "head"}, False)["error"], "PrivateRootRequired")

    def test_orphan_budget_and_partial_publication_recovery(self):
        store = self.base / "sync"; store.mkdir(mode=0o700)
        ciphertext = (self.vault / "vault.hbv").read_bytes()
        request = {"op": "publish", "operation_id": "recover-partial-operation-001", "expected_head": None, "ciphertext": base64.b64encode(ciphertext).decode()}
        # A killed writer can leave an unreferenced partial content-addressed
        # object and an unpublished state temp. These are staged filesystem
        # fault fixtures, not a claimed physical power-cut experiment.
        blob = store / ("ciphertext-" + hashlib.sha256(ciphertext).hexdigest() + ".bin")
        blob.write_bytes(ciphertext[:17]); blob.chmod(0o600)
        pending = store / "pending.json"; pending.write_bytes(b'{"partial":'); pending.chmod(0o600)
        receipt = invoke("heptabao-sync", [store, self.vault_id], request)["receipt"]
        self.assertEqual(blob.read_bytes(), ciphertext)
        self.assertEqual(invoke("heptabao-sync", [store, self.vault_id], {"op": "receipt", "operation_id": request["operation_id"]})["receipt"], receipt)
        bounded = self.base / "bounded-sync"; bounded.mkdir(mode=0o700)
        # Sparse files count by their logical retained length, just as admitted
        # ciphertext does. The metadata-only quota check includes every orphan.
        for index in range(16):
            path = bounded / ("ciphertext-" + f"{index:064x}" + ".bin")
            with path.open("xb") as stream: stream.truncate(4 * 1024 * 1024)
            path.chmod(0o600)
        self.assertEqual(invoke("heptabao-sync", [bounded, self.vault_id], request, False)["error"], "Capacity")
        self.assertEqual(len(list(bounded.iterdir())), 16)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--bin-dir", type=Path)
    args, remaining = parser.parse_known_args()
    if args.bin_dir: BIN = args.bin_dir.resolve()
    unittest.main(argv=[__file__, *remaining])
