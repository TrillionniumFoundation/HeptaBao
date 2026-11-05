#!/usr/bin/env python3
"""Exercise the bounded initialization-recovery/bootstrap lifecycle.

This fixture binds the declarative bootstrap profile to the real HeptaBao TLS
process.  The service does not provide an implicit development startup: the
operator supplies a client-generated recovery nonce, unseals with the returned
shares, applies a small declared policy/token step, and explicitly revokes the
bootstrap root.  A SIGKILL before acknowledgement proves that the same nonce
recovers the original response after restart without publishing a second
cluster.  This is scoped evidence for the existing ``sys/init`` recovery and
token lifecycle; it is not a claim of a complete OpenBao self-init feature.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import subprocess
import secrets
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_smoke():
    path = ROOT / "qa/single-node/smoke.py"
    spec = importlib.util.spec_from_file_location("self_init_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load single-node smoke helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def credential_absent(root: Path, values: list[str]) -> bool:
    needles = [value.encode() for value in values if value]
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if any(needle in data for needle in needles):
            return False
    return True


def run_fixture(binary: Path, root: Path) -> dict:
    smoke = load_smoke()
    instance = smoke.Instance(binary, root)
    checks: list[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise RuntimeError(f"failed scenario: {name}")
        checks.append(name)

    nonce = secrets.token_bytes(32)
    nonce_text = base64.b64encode(nonce).decode("ascii")
    init_body = {"secret_shares": 3, "secret_threshold": 2, "recovery_nonce": nonce_text}
    init_response = None
    bootstrap_token = ""
    child_token = ""
    unseal_shares: list[str] = []
    try:
        instance.start()
        check("self_init_starts_uninitialized", instance.call("GET", "sys/health")[0] == 501)

        # Distinct client nonces racing on a fresh directory must publish one
        # initialization only.  Exactly one request may create the cluster;
        # all other contenders must fail closed rather than minting another
        # root or replacing the recovery binding.
        contenders = []
        for _ in range(4):
            contender_nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            contenders.append({"secret_shares": 3, "secret_threshold": 2, "recovery_nonce": contender_nonce})
        with ThreadPoolExecutor(max_workers=len(contenders)) as pool:
            raced = list(pool.map(lambda body: instance.call("POST", "sys/init", body), contenders))
        successful = [index for index, (status, _) in enumerate(raced) if status == 200]
        check(
            "self_init_race_exclusion",
            len(successful) == 1
            and all(status in (400, 403, 409, 503) for index, (status, _) in enumerate(raced) if index != successful[0]),
        )
        init_body = contenders[successful[0]]
        nonce_text = init_body["recovery_nonce"]
        status, init_response = raced[successful[0]]
        check(
            "self_init_one_time_bootstrap",
            status == 200
            and init_response.get("init_ack_required") is True
            and isinstance(init_response.get("root_token"), str)
            and len(init_response["root_token"]) >= 16
            and isinstance(init_response.get("keys_base64"), list)
            and len(init_response["keys_base64"]) == 3,
        )
        bootstrap_token = init_response["root_token"]
        unseal_shares = init_response["keys_base64"]
        instance.token = ""
        check(
            "self_init_custody_material_not_persisted_plaintext",
            credential_absent(root, [nonce_text, bootstrap_token, *unseal_shares]),
        )

        # Deliberately lose the response and process before unseal/ack.  The
        # recovery object is the only durable copy and is bound to the nonce
        # and seal metadata.
        instance.stop()
        instance.start()
        status, recovered = instance.call("POST", "sys/init", init_body)
        check(
            "self_init_lost_ack_recovers_same_response",
            status == 200 and recovered == init_response,
        )
        wrong = dict(init_body)
        wrong["recovery_nonce"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        check("self_init_wrong_nonce_denied", instance.call("POST", "sys/init", wrong)[0] == 403)
        mismatch = dict(init_body)
        mismatch["secret_threshold"] = 3
        check("self_init_parameter_replay_denied", instance.call("POST", "sys/init", mismatch)[0] == 400)
        check(
            "self_init_without_nonce_cannot_reinitialize",
            instance.call("POST", "sys/init", {"secret_shares": 3, "secret_threshold": 2})[0] == 400,
        )

        instance.token = bootstrap_token
        check("self_init_threshold_unseal", all(
            instance.call("POST", "sys/unseal", {"key": share})[0] == 200
            for share in unseal_shares[:2]
        ))
        check(
            "self_init_declared_policy",
            instance.call(
                "POST",
                "sys/policies/acl/self-init-reader",
                {"policy": 'path "secret/data/self-init" { capabilities = ["read"] }'},
            )[0]
            == 204,
        )
        status, created = instance.call(
            "POST",
            "auth/token/create",
            {"policies": ["self-init-reader"], "no_default_policy": True, "ttl": "1h"},
        )
        child_token = created.get("auth", {}).get("client_token", "") if isinstance(created, dict) else ""
        check("self_init_declared_transient_token", status == 200 and bool(child_token))
        check(
            "self_init_declared_effect_readback",
            instance.call("POST", "secret/data/self-init", {"data": {"value": "bootstrap"}})[0] == 200
            and instance.call("GET", "secret/data/self-init", token=child_token)[1]
            .get("data", {}).get("data", {}).get("value")
            == "bootstrap",
        )

        # Acknowledgement is an authenticated, root-namespace operation.  It
        # removes the encrypted response only after a directory sync and is
        # intentionally safe to repeat after a lost acknowledgement.
        check("self_init_root_ack", instance.call("POST", "sys/init/ack", {}, token=bootstrap_token)[0] == 204)
        check("self_init_ack_idempotent", instance.call("POST", "sys/init/ack", {}, token=bootstrap_token)[0] == 204)
        check("self_init_recovery_artifact_removed", not (root / "data" / "init-recovery.hbe").exists())

        # The bootstrap credential is transient.  Revocation must invalidate
        # both it and any child token before the process is allowed to restart.
        check("self_init_transient_root_revoked", instance.call("POST", "auth/token/revoke-self", {}, token=bootstrap_token)[0] == 204)
        check("self_init_root_unusable_after_revoke", instance.call("GET", "secret/data/self-init", token=bootstrap_token)[0] == 403)
        check("self_init_child_unusable_after_root_revoke", instance.call("GET", "secret/data/self-init", token=child_token)[0] == 403)

        instance.stop()
        instance.start()
        check("self_init_restart_stays_sealed", instance.call("GET", "sys/health")[0] == 503)
        check(
            "self_init_restart_unseal",
            all(instance.call("POST", "sys/unseal", {"key": share})[0] == 200 for share in unseal_shares[:2]),
        )
        check("self_init_revocation_survives_restart", instance.call("GET", "secret/data/self-init", token=child_token)[0] == 403)
        check("self_init_reinit_after_ack_rejected", instance.call("POST", "sys/init", init_body)[0] == 409)
        check("self_init_persisted_credentials_absent", credential_absent(root, [nonce_text, bootstrap_token, *unseal_shares]))
        return {
            "schema": "heptabao.self-init-live.v1",
            "status": "passed",
            "checks": checks,
            "count": len(checks),
            "candidate_binary_sha256": file_hash(binary),
            "runner_sha256": file_hash(Path(__file__)),
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
            "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
            "compatibility_claim": False,
            "production_authority": False,
            "scope": "bounded sys/init recovery, declared policy/token step and transient-root revocation",
        }
    finally:
        instance.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute() or args.work_dir.exists():
        parser.error("--binary and a new absolute --work-dir are required")
    try:
        report = run_fixture(args.binary.resolve(strict=True), args.work_dir)
    except Exception as error:
        print(f"self-init live fixture failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
