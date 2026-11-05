#!/usr/bin/env python3
"""Synthetic-only native extension and exact old-reader boundary.

This extension intentionally differs from OpenBao. Default compatibility is
checked separately by the unchanged complete transit_derived_live profile.
No live endpoints or credentials are accepted. Reports contain only fixed case
IDs, status codes, predicates, file names and identity hashes.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time

from bao_http import SafeArgumentParser

ROOT = Path(__file__).resolve().parents[2]
KINDS = ("aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305")


def expected_case_names():
    names = ["legacy.initialize", "legacy.unseal", "legacy.mount"]
    for kind in KINDS:
        names.extend(kind+suffix for suffix in (".legacy.create", ".legacy.no_extension_descriptor", ".legacy.encrypt"))
    names.append("ordinary.old65_accepts_new_ordinary65_state")
    for kind in KINDS:
        names.extend(kind+suffix for suffix in (".ordinary.old65_decrypt", ".ordinary.old65_plaintext", ".ordinary.old65_encrypt", ".ordinary.old65_cipher_matches", ".ordinary.old65_descriptor", ".ordinary.old65_no_extension_descriptor"))
    names.append("new.accepts_legacy65_state")
    for kind in KINDS:
        names.extend(kind+suffix for suffix in (
            ".before_upgrade.legacy_decrypt", ".before_upgrade.legacy_plaintext", ".explicit_upgrade", ".upgrade.descriptor",
            ".safe.encrypt_one", ".safe.repeat", ".safe.encrypt_changed_aad", ".safe.deterministic", ".safe.aad_changes_nonce", ".safe.aad_changes_body",
            ".safe.decrypt_one", ".safe.plaintext_one", ".safe.decrypt_two", ".safe.plaintext_two", ".safe.decrypt_legacy", ".safe.plaintext_legacy",
            ".safe.wrong_aad", ".floor.encrypt", ".floor.rewrap", ".floor.datakey_plaintext", ".floor.datakey_wrapped", ".floor.config_0", ".floor.config_1",
            ".no_exportability", ".no_plaintext_backup"))
        names.extend(kind+".no_rotate_downgrade_"+str(index) for index in range(7))
        names.extend(kind+suffix for suffix in (".no_bare_export_encryption-key", ".no_bare_export_hmac-key", ".batch.floor", ".batch.floor_and_safe_version", ".datakey.safe", ".datakey.decrypt", ".datakey.plaintext", ".rewrap.migrate_old", ".rewrap.actual_new_mode"))
    names.extend(("old65.rejects_safe66_unseal", "old65.refusal_is_authenticated_record_validation", "old65.authoritative_files_present", "old65.authoritative_owner_journal_unchanged", "old65.only_nonce_rebuild_ledger_may_change", "new.reopen_after_old65_refusal"))
    for kind in KINDS:
        names.extend(kind+suffix for suffix in (".restart.decrypt_old", ".restart.plaintext_old", ".restart.decrypt_safe", ".restart.plaintext_safe", ".restart.rotate_inherits", ".restart.mode_and_floor"))
    names.extend(("sticky.unmount_last_safe", "sticky.ordinary_mount", "sticky.ordinary_write", "sticky.old65_rejects_retired_safe66", "sticky.refusal_is_unsupported_schema", "sticky.authoritative_files_present", "sticky.authoritative_owner_journal_unchanged", "sticky.only_nonce_rebuild_ledger_may_change", "sticky.new_reopens", "sticky.ordinary_read", "sticky.ordinary_plaintext"))
    return names


def complete_trace(rows):
    expected = expected_case_names()
    return len(expected) == 246 and len(set(expected)) == 246 and [row["case"] for row in rows] == expected and all(row["passed"] is True for row in rows)


class Failure(Exception):
    pass


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024*1024), b""):
            digest.update(data)
    return digest.hexdigest()


def b64(value):
    return base64.b64encode(value).decode()


def payload(value):
    return base64.b64decode(value.split(":", 2)[2], validate=True)


class Trace:
    def __init__(self, instance, rows):
        self.instance, self.rows = instance, rows

    def check(self, name, predicate):
        self.rows.append({"case": name, "passed": bool(predicate)})
        if not predicate:
            raise Failure(name)

    def call(self, name, method, path, expected, body=None):
        status, data = self.instance.call(method, path, body)
        self.rows.append({"case": name, "status": status, "passed": status == expected})
        if status != expected:
            raise Failure(name)
        return data


def snapshots(instance):
    root = instance.root / "data"
    return {str(path.relative_to(root)): file_hash(path) for path in sorted(root.rglob("*")) if path.is_file()}


def run(instance, legacy, candidate, rows, file_audits):
    t = Trace(instance, rows)
    context, message = b64(b"synthetic context"), b64(b"synthetic message")
    aad_one, aad_two = b64(b"first AAD"), b64(b"second AAD")
    # A fresh ordinary-only store written by this new binary must remain an
    # actual old-reader positive. Then that old writer supplies the legacy
    # ciphertext used by the safe-upgrade/read compatibility checks below.
    instance.binary = candidate
    instance.start()
    initialized = t.call("legacy.initialize", "POST", "sys/init", 200, {"secret_shares": 1, "secret_threshold": 1})
    unseal_key, instance.token = initialized["keys_base64"][0], initialized["root_token"]
    t.call("legacy.unseal", "POST", "sys/unseal", 200, {"key": unseal_key})
    t.call("legacy.mount", "POST", "sys/mounts/aadfixture", 204, {"type": "transit"})
    saved = {}
    for kind in KINDS:
        base = "aadfixture/"
        options = {"plaintext": message, "context": context, "associated_data": aad_one}
        descriptor = t.call(kind+".legacy.create", "POST", base+"keys/"+kind, 200, {"type": kind, "derived": True, "convergent_encryption": True})["data"]
        t.check(kind+".legacy.no_extension_descriptor", not any(key.startswith("heptabao_") for key in descriptor))
        cipher = t.call(kind+".legacy.encrypt", "POST", base+"encrypt/"+kind, 200, options)["data"]["ciphertext"]
        saved[kind] = {"old": cipher}
    instance.stop()
    instance.binary = legacy
    instance.start()
    t.call("ordinary.old65_accepts_new_ordinary65_state", "POST", "sys/unseal", 200, {"key": unseal_key})
    for kind in KINDS:
        old = t.call(kind+".ordinary.old65_decrypt", "POST", "aadfixture/decrypt/"+kind, 200, {"ciphertext": saved[kind]["old"], "context": context, "associated_data": aad_one})["data"]
        t.check(kind+".ordinary.old65_plaintext", old["plaintext"] == message)
        cipher = t.call(kind+".ordinary.old65_encrypt", "POST", "aadfixture/encrypt/"+kind, 200, {"plaintext": message, "context": context, "associated_data": aad_one})["data"]["ciphertext"]
        t.check(kind+".ordinary.old65_cipher_matches", cipher == saved[kind]["old"])
        saved[kind]["old"] = cipher
        descriptor = t.call(kind+".ordinary.old65_descriptor", "GET", "aadfixture/keys/"+kind, 200)["data"]
        t.check(kind+".ordinary.old65_no_extension_descriptor", not any(key.startswith("heptabao_") for key in descriptor))
    instance.stop()
    instance.binary = candidate
    instance.start()
    t.call("new.accepts_legacy65_state", "POST", "sys/unseal", 200, {"key": unseal_key})
    for kind in KINDS:
        kp, ep, dp, rp = ("aadfixture/"+operation+"/"+kind for operation in ("keys", "encrypt", "decrypt", "rewrap"))
        old_body = {"ciphertext": saved[kind]["old"], "context": context, "associated_data": aad_one}
        before = t.call(kind+".before_upgrade.legacy_decrypt", "POST", dp, 200, old_body)["data"]
        t.check(kind+".before_upgrade.legacy_plaintext", before["plaintext"] == message)
        rotated = t.call(kind+".explicit_upgrade", "POST", kp+"/rotate", 200, {"heptabao_convergent_version": 1})["data"]
        t.check(kind+".upgrade.descriptor", rotated["latest_version"] == 2 and rotated["min_encryption_version"] == 2 and rotated["heptabao_convergent_min_encryption_version"] == 2 and rotated["heptabao_convergent_versions"] == {"1": 0, "2": 1})
        options = {"plaintext": message, "context": context, "associated_data": aad_one}
        first = t.call(kind+".safe.encrypt_one", "POST", ep, 200, options)["data"]["ciphertext"]
        repeated = t.call(kind+".safe.repeat", "POST", ep, 200, options)["data"]["ciphertext"]
        second = t.call(kind+".safe.encrypt_changed_aad", "POST", ep, 200, {**options, "associated_data": aad_two})["data"]["ciphertext"]
        first_raw, second_raw = payload(first), payload(second)
        n = 24 if kind.startswith("xchacha") else 12
        t.check(kind+".safe.deterministic", first == repeated)
        t.check(kind+".safe.aad_changes_nonce", first_raw[:n] != second_raw[:n])
        t.check(kind+".safe.aad_changes_body", first_raw[n:-16] != second_raw[n:-16])
        for label, cipher, aad in (("one", first, aad_one), ("two", second, aad_two), ("legacy", saved[kind]["old"], aad_one)):
            result = t.call(kind+".safe.decrypt_"+label, "POST", dp, 200, {"ciphertext": cipher, "context": context, "associated_data": aad})["data"]
            t.check(kind+".safe.plaintext_"+label, result["plaintext"] == message)
        t.call(kind+".safe.wrong_aad", "POST", dp, 400, {"ciphertext": first, "context": context, "associated_data": aad_two})
        t.call(kind+".floor.encrypt", "POST", ep, 400, {**options, "key_version": 1})
        t.call(kind+".floor.rewrap", "POST", rp, 400, {**old_body, "key_version": 1})
        for mode in ("plaintext", "wrapped"):
            t.call(kind+".floor.datakey_"+mode, "POST", "aadfixture/datakey/"+mode+"/"+kind, 400, {"context": context, "associated_data": aad_one, "key_version": 1})
        for floor in (0, 1):
            t.call(kind+".floor.config_"+str(floor), "POST", kp+"/config", 400, {"min_encryption_version": floor})
        t.call(kind+".no_exportability", "POST", kp+"/config", 400, {"exportable": True})
        t.call(kind+".no_plaintext_backup", "POST", kp+"/config", 501, {"allow_plaintext_backup": True})
        for index, value in enumerate((None, 0, 2, True, "1", [], {})):
            t.call(kind+".no_rotate_downgrade_"+str(index), "POST", kp+"/rotate", 400, {"heptabao_convergent_version": value})
        for exported in ("encryption-key", "hmac-key"):
            t.call(kind+".no_bare_export_"+exported, "GET", "aadfixture/export/"+exported+"/"+kind, 403)
        batch = t.call(kind+".batch.floor", "POST", ep, 207, {"partial_failure_response_code": 207, "batch_input": [{**options, "key_version": 1}, {**options, "associated_data": aad_two}]})["data"]["batch_results"]
        t.check(kind+".batch.floor_and_safe_version", "error" in batch[0] and batch[1]["key_version"] == 2 and batch[1]["ciphertext"] == second)
        generated = t.call(kind+".datakey.safe", "POST", "aadfixture/datakey/plaintext/"+kind, 200, {"bits": 128, "context": context, "associated_data": aad_one})["data"]
        decoded = t.call(kind+".datakey.decrypt", "POST", dp, 200, {"ciphertext": generated["ciphertext"], "context": context, "associated_data": aad_one})["data"]
        t.check(kind+".datakey.plaintext", decoded["plaintext"] == generated["plaintext"] and len(base64.b64decode(decoded["plaintext"])) == 16)
        rewrapped = t.call(kind+".rewrap.migrate_old", "POST", rp, 200, old_body)["data"]["ciphertext"]
        t.check(kind+".rewrap.actual_new_mode", rewrapped == first)
        saved[kind]["safe"] = first
    instance.stop()
    before = snapshots(instance)
    instance.binary = legacy
    instance.start()
    refused = t.call("old65.rejects_safe66_unseal", "POST", "sys/unseal", 503, {"key": unseal_key})
    t.check("old65.refusal_is_authenticated_record_validation", refused.get("errors") == ["record state failed authenticated validation"])
    instance.stop()
    after = snapshots(instance)
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    authoritative = [name for name in set(before) | set(after) if Path(name).name in ("state.hbs", "journal.hbj")]
    t.check("old65.authoritative_files_present", len(authoritative) >= 2)
    t.check("old65.authoritative_owner_journal_unchanged", all(before.get(name) == after.get(name) for name in authoritative))
    t.check("old65.only_nonce_rebuild_ledger_may_change", all(Path(name).name == "ledger.hbl" for name in changed))
    file_audits.append({"case": "old65.safe66_refusal", "before": before, "after": after, "changed_paths": changed})
    instance.binary = candidate
    instance.start()
    t.call("new.reopen_after_old65_refusal", "POST", "sys/unseal", 200, {"key": unseal_key})
    for kind in KINDS:
        for label in ("old", "safe"):
            data = t.call(kind+".restart.decrypt_"+label, "POST", "aadfixture/decrypt/"+kind, 200, {"ciphertext": saved[kind][label], "context": context, "associated_data": aad_one})["data"]
            t.check(kind+".restart.plaintext_"+label, data["plaintext"] == message)
        rotated = t.call(kind+".restart.rotate_inherits", "POST", "aadfixture/keys/"+kind+"/rotate", 200, {})["data"]
        t.check(kind+".restart.mode_and_floor", rotated["latest_version"] == 3 and rotated["heptabao_convergent_min_encryption_version"] == 2 and rotated["heptabao_convergent_versions"] == {"1": 0, "2": 1, "3": 1})
    t.call("sticky.unmount_last_safe", "DELETE", "sys/mounts/aadfixture", 204)
    t.call("sticky.ordinary_mount", "POST", "sys/mounts/ordinary", 204, {"type": "kv"})
    t.call("sticky.ordinary_write", "POST", "ordinary/value", 204, {"synthetic": "value"})
    instance.stop()
    before = snapshots(instance)
    instance.binary = legacy
    instance.start()
    refused = t.call("sticky.old65_rejects_retired_safe66", "POST", "sys/unseal", 503, {"key": unseal_key})
    file_audits.append({"case": "old65.retired_safe66_refusal_reason_observation",
                        "unsupported_schema": refused.get("errors") == ["unsupported or downgraded identity state schema"],
                        "authenticated_record_validation": refused.get("errors") == ["record state failed authenticated validation"]})
    t.check("sticky.refusal_is_unsupported_schema", refused.get("errors") == ["unsupported or downgraded identity state schema"])
    instance.stop()
    after = snapshots(instance)
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    authoritative = [name for name in set(before) | set(after) if Path(name).name in ("state.hbs", "journal.hbj")]
    t.check("sticky.authoritative_files_present", len(authoritative) >= 2)
    t.check("sticky.authoritative_owner_journal_unchanged", all(before.get(name) == after.get(name) for name in authoritative))
    t.check("sticky.only_nonce_rebuild_ledger_may_change", all(Path(name).name == "ledger.hbl" for name in changed))
    file_audits.append({"case": "old65.retired_safe66_refusal", "before": before, "after": after, "changed_paths": changed})
    instance.binary = candidate
    instance.start()
    t.call("sticky.new_reopens", "POST", "sys/unseal", 200, {"key": unseal_key})
    result = t.call("sticky.ordinary_read", "GET", "ordinary/value", 200)["data"]
    t.check("sticky.ordinary_plaintext", result == {"synthetic": "value"})
    instance.stop()


def main():
    parser = SafeArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    candidate, legacy, output = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True), Path(args.output).resolve()
    if output.exists() or output.parent.stat().st_mode & 0o077 or output.parent.stat().st_uid != os.geteuid():
        parser.error("output must be new and its parent private and caller-owned")
    before = {"candidate": file_hash(candidate), "legacy": file_hash(legacy), "runner": file_hash(__file__)}
    fixture_parent = Path(tempfile.mkdtemp(prefix="heptabao-aad-bound-", dir=output.parent))
    os.chmod(fixture_parent, 0o700)
    # smoke.Instance creates its root; the private parent exists and the node
    # itself must be absent so construction does not fail before any service.
    fixture = fixture_parent / "node"
    spec = importlib.util.spec_from_file_location("aad_smoke", ROOT/"qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
    owned_pids = []

    class OwnedInstance(smoke.Instance):
        def start(self):
            super().start()
            if self.process is not None:
                owned_pids.append(self.process.pid)

    instance = OwnedInstance(legacy, fixture)
    os.chmod(instance.root, 0o700)
    rows, file_audits, code, failure = [], [], 0, None
    started = time.monotonic()
    try:
        run(instance, legacy, candidate, rows, file_audits)
        if not complete_trace(rows):
            raise Failure("incomplete_or_reordered_fixed_trace")
    except Failure as error:
        code, failure = 1, str(error)
    except Exception as error:
        code, failure = 1, "unexpected_"+type(error).__name__
    finally:
        instance.stop()
        alive = []
        for pid in owned_pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except ProcessLookupError:
                pass
        if alive:
            code, failure = 1, "owned_processes_remain"
        after = {"candidate": file_hash(candidate), "legacy": file_hash(legacy), "runner": file_hash(__file__)}
        if before != after:
            code, failure = 1, "artifact_identity_changed"
        result = {"schema": "heptabao.convergent-aad-extension.v1", "exit_code": code, "case_count": len(rows), "expected_case_count": 246, "complete_fixed_trace": complete_trace(rows), "rows": rows, "file_audits": file_audits, "failure": failure, "before": before, "after": after, "identity_unchanged": before == after, "owned_process_stopped": instance.process is None, "owned_server_pids": owned_pids, "owned_server_pids_remaining": alive, "elapsed_seconds": round(time.monotonic()-started, 3), "intentional_extension": True, "fresh_oracle_comparison": False, "independent_security_qualified": False, "full_replacement": False}
        output.write_text(json.dumps(result, indent=2)+"\n")
        os.chmod(output, 0o600)
        print(json.dumps({key: result[key] for key in ("exit_code", "case_count", "failure", "identity_unchanged", "owned_process_stopped", "elapsed_seconds")}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
