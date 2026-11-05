#!/usr/bin/env python3
"""Real TLS TokenReview comparison; synthetic server, never a kube-apiserver claim."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT
from official_openbao_launcher import BINARY_SHA256, certificates, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance, signing_key
from kubernetes_renewal_live import Reviewer, assertion, configuration, role
from oidc_renewal_live import free_port
from jwt_api_tls_live import Failure, Trace, wrong_name_leaf

ADAPTATION = {
    "transport": "API-owned explicit replacement CA; candidate startup outbound_endpoints empty",
    "reviewer": "absent/null/empty reviewer uses presented JWT; configured reviewer never falls back",
    "request": "candidate includes TokenReview TypeMeta, official omits it; both exact spec and bearer checked",
    "local_validation": "official receives issuer and PEM validation key; candidate retains bounded local claim profile",
    "malformed_ca": "official persists malformed/trailing PEM; candidate rejects at config",
    "provider_failure": "native completed TokenReview failures are 403; legacy enrollment and caller deadline exhaustion retain 503",
    "ambient": "disable_local_ca_jwt=true on both; no pod files, system root fallback or real cluster",
}


def config_variant(config, value):
    result = dict(config)
    if value == "omitted":
        result.pop("token_reviewer_jwt")
    else:
        result["token_reviewer_jwt"] = value
    return result


REQUIRED_CASES = {"config.ca_exact", "configured.exact_single_post", "omitted.exact_single_post",
                  "empty.exact_single_post", "null.exact_single_post", "wrong_reviewer.no_fallback",
                  "wrong_ca.zero_http", "wrong_san.zero_http", "restart.ca_preserved",
                  "restart.existing_tokens_no_provider", "restart.new_token", "complete"}


def safe_rows(rows):
    return (isinstance(rows, list) and bool(rows)
            and len({row.get("case") for row in rows}) == len(rows)
            and all(isinstance(row, dict) and row.get("passed") is True
                    and re.fullmatch(r"api_tls\.[a-z0-9_.]{1,160}", row.get("case", ""))
                    and all(type(v) in (bool, int) for k, v in row.items() if k not in ("case", "passed"))
                    for row in rows)
            and {"api_tls.kubernetes." + name for name in REQUIRED_CASES}.issubset({row["case"] for row in rows})
            and rows[-1].get("case") == "api_tls.kubernetes.complete")


def run_side(client, side, reviewer, mismatch, private, jwk, ca, wrong_ca, restart, rows):
    t = Trace(client, rows, "kubernetes")
    mount = "api-kubernetes"
    base = "auth/" + mount
    t.call("mount", "sys/auth/" + mount, {"type": "kubernetes"}, expected=204)
    t.call("role", base + "/role/app", role(token_policies=["default"]), expected=204)
    reviewer.presented = assertion(private, jwk)
    original_reviewer = reviewer.reviewer
    config = configuration(side, reviewer, private, ca)
    for name, value in [("missing", "omitted"), ("empty", ""), ("null", None)]:
        params = dict(config)
        if value == "omitted":
            params.pop("kubernetes_ca_cert")
        else:
            params["kubernetes_ca_cert"] = value
        before = len(reviewer.calls)
        t.call("fresh_ca." + name, base + "/config", params, expected=400)
        t.check("fresh_ca." + name + ".no_preflight", len(reviewer.calls) == before)
    before = len(reviewer.calls)
    t.call("config.correct", base + "/config", config, expected=204)
    t.check("config.no_preflight", len(reviewer.calls) == before)
    current = t.call("config.read", base + "/config", method="GET").get("data", {})
    t.check("config.ca_exact", current.get("kubernetes_ca_cert") == ca)
    t.check("config.secret_hidden", "token_reviewer_jwt" not in current)
    for name, value in [("malformed", "synthetic-malformed-ca"), ("trailing", ca + "trailing-junk\n")]:
        before = len(reviewer.calls)
        t.call("strict_profile." + name, base + "/config", dict(config, kubernetes_ca_cert=value),
               expected=204 if side == "oracle" else 400)
        t.check("strict_profile." + name + ".no_preflight", len(reviewer.calls) == before)
        observed = t.call("strict_profile." + name + ".read", base + "/config", method="GET").get("data", {})
        t.check("strict_profile." + name + ".observed_contract",
                observed.get("kubernetes_ca_cert") == (value if side == "oracle" else ca))
        t.call("strict_profile." + name + ".restore", base + "/config", config, expected=204)
    tokens = []
    for label, value in [("configured", original_reviewer), ("omitted", "omitted"), ("empty", ""), ("null", None)]:
        reviewer.reviewer = original_reviewer if label == "configured" else reviewer.presented
        reviewer.request_valid = True
        params = config_variant(config, value)
        before = len(reviewer.calls)
        t.call(label + ".config", base + "/config", params, expected=204)
        t.check(label + ".no_preflight", len(reviewer.calls) == before)
        data = t.call(label + ".read", base + "/config", method="GET").get("data", {})
        t.check(label + ".reviewer_redacted", "token_reviewer_jwt" not in data)
        t.check(label + ".reviewer_presence", data.get("token_reviewer_jwt_set") == (label == "configured"))
        before = len(reviewer.calls)
        auth = t.call(label + ".login", base + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="").get("auth", {})
        t.check(label + ".exact_single_post", len(reviewer.calls) == before + 1 and reviewer.request_valid)
        bearer = auth.get("client_token")
        t.check(label + ".issued", isinstance(bearer, str) and bool(bearer))
        tokens.append(bearer)
    reviewer.reviewer = original_reviewer
    t.call("wrong_reviewer.config", base + "/config", dict(config, token_reviewer_jwt="synthetic-invalid-reviewer"), expected=204)
    before = len(reviewer.calls)
    denied = t.call("wrong_reviewer.denied", base + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="",
                    expected=403)
    t.check("wrong_reviewer.no_fallback", len(reviewer.calls) == before + 1)
    t.check("wrong_reviewer.no_token", not denied.get("auth") and not denied.get("wrap_info"))
    for label, provider, trust in [("wrong_ca", reviewer, wrong_ca), ("wrong_san", mismatch, ca)]:
        bad_mount = mount + "-" + label
        t.call(label + ".mount", "sys/auth/" + bad_mount, {"type": "kubernetes"}, expected=204)
        t.call(label + ".role", "auth/" + bad_mount + "/role/app", role(token_policies=["default"]), expected=204)
        bad = dict(config, kubernetes_host=provider.origin, kubernetes_ca_cert=trust)
        before = len(provider.calls)
        t.call(label + ".config_without_preflight", "auth/" + bad_mount + "/config", bad, expected=204)
        t.check(label + ".config_zero_http", len(provider.calls) == before)
        denied = t.call(label + ".login_denied", "auth/" + bad_mount + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="",
                        expected=403)
        t.check(label + ".zero_http", len(provider.calls) == before)
        t.check(label + ".no_token", not denied.get("auth") and not denied.get("wrap_info"))
    reviewer.mode = "unavailable"
    before = len(reviewer.calls)
    t.call("unavailable.config_without_preflight", base + "/config", config, expected=204)
    t.check("unavailable.config_zero_http", len(reviewer.calls) == before)
    restart()
    t.check("restart", True)
    data = t.call("restart.config_read", base + "/config", method="GET").get("data", {})
    t.check("restart.ca_preserved", data.get("kubernetes_ca_cert") == ca)
    before = len(reviewer.calls)
    for index, bearer in enumerate(tokens):
        t.call("restart.lookup_" + str(index), "auth/token/lookup-self", method="GET", bearer=bearer)
        t.call("restart.renew_" + str(index), "auth/token/renew-self", {}, bearer=bearer)
    t.check("restart.existing_tokens_no_provider", len(reviewer.calls) == before)
    reviewer.mode, reviewer.request_valid = "normal", True
    auth = t.call("restart.fresh_login", base + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="").get("auth", {})
    t.check("restart.exact_single_post", len(reviewer.calls) == before + 1 and reviewer.request_valid)
    t.check("restart.new_token", bool(auth.get("client_token")) and auth["client_token"] not in tokens)
    t.check("complete", True)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build-source-commit")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit or "") is None):
        parser.error("candidate binary and full build source commit required")
    output = args.output.absolute()
    admitted = admit_output(output)
    binary = args.binary.resolve(strict=True) if args.binary else None
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-kubernetes-api-tls-"))
    root.chmod(0o700)
    instance, oracle, providers = None, None, []
    cases, failures = {}, {}
    unenrolled = False
    try:
        oracle = start_oracle(free_port())
        ca_root = Path(oracle["root"])
        ca = (ca_root / "ca.crt").read_text()
        wrong_root = root / "wrong-ca"
        wrong_root.mkdir(mode=0o700)
        certificates(wrong_root)
        wrong = (wrong_root / "ca.crt").read_text()
        mismatch_pair = wrong_name_leaf(root / "wrong-name", ca_root)
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip())
        def restart_reference():
            stop_oracle(oracle)
            restart_oracle(oracle)
        targets = [("oracle", reference, restart_reference)]
        if not args.oracle_only:
            instance = Instance(binary, root / "candidate")
            cfg_path = instance.root / "server.json"
            cfg = json.loads(cfg_path.read_text())
            cfg.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            cfg_path.write_text(json.dumps(cfg)); cfg_path.chmod(0o600)
            unenrolled = json.loads(cfg_path.read_text())["outbound_endpoints"] == []
            instance.start()
            status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if status != 200:
                raise Failure("candidate_init_failed")
            instance.token, key = init["root_token"], init["keys_base64"][0]
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise Failure("candidate_unseal_failed")
            def restart_candidate():
                instance.stop()
                if json.loads(cfg_path.read_text())["outbound_endpoints"] != []:
                    raise Failure("candidate_enrollment_changed")
                instance.start()
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise Failure("candidate_restart_failed")
            targets.append(("candidate", Client(instance.address, str(instance.root / "ca.crt"), instance.token), restart_candidate))
        for side, client, restart in targets:
            reviewer = Reviewer(ca_root / "tls.crt", ca_root / "tls.key", side)
            mismatch = Reviewer(*mismatch_pair, side)
            providers.extend((reviewer, mismatch))
            private, jwk = signing_key("ES256", "synthetic-api-reviewer")
            cases[side] = []
            try:
                run_side(client, side, reviewer, mismatch, private, jwk, ca, wrong, restart, cases[side])
            except Exception as error:
                failures[side] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    except Exception as error:
        failures["setup"] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        for provider in providers:
            provider.close()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before else None
    runner_unchanged = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    expected = {"oracle"} if args.oracle_only else {"oracle", "candidate"}
    passed = (not failures and set(cases) == expected and all(safe_rows(rows) for rows in cases.values())
              and runner_unchanged and (args.oracle_only or (unchanged and unenrolled)))
    report = {"schema": "heptabao.kubernetes-api-tls-comparison.v1", "status": "passed" if passed else "failed",
              "candidate_source": before, "build_source_commit": args.build_source_commit,
              "source_and_binary_unchanged": unchanged, "runner_sha256": runner_hash, "runner_unchanged": runner_unchanged,
              "oracle_binary_sha256": BINARY_SHA256, "oracle_only": args.oracle_only, "target_version": "2.6.2",
              "candidate_startup_enrollment_empty": unenrolled, "cases": cases, "failures": failures,
              "configuration_adaptation": ADAPTATION, "synthetic_tokenreview": True, "actual_kube_apiserver": False,
              "full_openbao_compatibility": False, "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "cases": {side: len(rows) for side, rows in cases.items()}, "failures": failures}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
