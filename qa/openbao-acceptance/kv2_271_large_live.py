#!/usr/bin/env python3
"""Exact-version OpenBao 2.7.1 KV2 2560-KiB HTTPS differential.

Run only against two new, isolated, loopback TLS instances with synthetic
payloads.  This is the executable check for the recorded OpenBao=200 versus
HeptaBao=413 ingress mismatch; passing it is not V6 HA or replacement admission.

Example (private outputs, never commit credentials or server logs):
  python qa/openbao-acceptance/kv2_271_large_live.py \
      --binary /path/to/heptabao-server \
      --private-work-root /private/new-work-root \
      --output /private/new-evidence.json

HB_ORACLE_BINARY/HB_ORACLE_ARCHIVE must refer to the already verified official
2.7.1 pair.  No endpoint or credential is accepted on the command line.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
sys.path.insert(0, str(ROOT / "clients/python/src"))

from bao_http import private_read, private_write
from official_openbao_launcher import (
    pinned_artifact, restart_oracle, start_oracle, stop_oracle, verify_inputs,
)
from online_evidence import source_identity
from smoke import Instance, free_loopback_port

VERSION = "2.7.1"
PAYLOAD_BYTES = 2560 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
EXPECTED = (
    "mount", "write_v1", "read_v1", "write_v2", "read_v2",
    "unauthorized_write_denied", "version_unchanged", "restart",
    "cold_read_v1", "cold_read_v2",
)


def request(address: str, ca_file: Path, token: str, method: str,
            path: str, body: dict | None = None) -> tuple[int, dict]:
    parsed = urlsplit(address)
    if (parsed.scheme != "https" or parsed.hostname not in ("127.0.0.1", "localhost")
            or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment or not parsed.port):
        raise ValueError("non_loopback_fixture_rejected")
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    headers = {"Accept": "application/json", "Connection": "close"}
    if token:
        headers["X-Vault-Token"] = token
    wire = None
    if body is not None:
        wire = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPSConnection(
        parsed.hostname, parsed.port, context=context, timeout=20,
    )
    try:
        conn.request(method, "/v1/" + path, body=wire, headers=headers)
        result = conn.getresponse()
        raw = result.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("bounded_response_exceeded")
        value = json.loads(raw) if raw else {}
        if not isinstance(value, dict):
            raise ValueError("invalid_response_envelope")
        return result.status, value
    finally:
        conn.close()


def scenario(address: str, ca_file: Path, root_token: str, restart,
             rows: list[dict]) -> list[dict]:

    def check(case: str, status: int | None, good: bool) -> None:
        rows.append({"case": case, "status": status, "passed": good is True})
        if good is not True:
            raise RuntimeError(case)

    def checked_call(case, method, path, body=None, *, token=None, expected=200):
        status, value = request(
            address, ca_file, root_token if token is None else token,
            method, path, body,
        )
        check(case, status, status == expected)
        return value

    checked_call("mount", "POST", "sys/mounts/secret",
                 {"type": "kv", "options": {"version": "2"}}, expected=204)
    payloads = {
        1: "A" * PAYLOAD_BYTES,
        2: "B" * PAYLOAD_BYTES,
    }

    def read(case: str, version: int, *, selected: bool = True):
        suffix = "?version=" + str(version) if selected else ""
        status, body = request(
            address, ca_file, root_token, "GET", "secret/data/large" + suffix,
        )
        observed = body.get("data", {})
        if not isinstance(observed, dict):
            observed = {}
        metadata = observed.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        secret = observed.get("data", {})
        if not isinstance(secret, dict):
            secret = {}
        text = secret.get("payload")
        # Digest is of a fixed public synthetic payload; never log a bearer or
        # source value.  Require both exact data and the independent KV version.
        valid = (
            status == 200
            and metadata.get("version") == version
            and isinstance(text, str)
            and len(text) == PAYLOAD_BYTES
            and hashlib.sha256(text.encode()).digest()
                == hashlib.sha256(payloads[version].encode()).digest()
            and text == payloads[version]
        )
        check(case, status, valid)

    for version in (1, 2):
        checked_call("write_v" + str(version), "POST", "secret/data/large",
                     {"data": {"payload": payloads[version]}})
        read("read_v" + str(version), version)
    status, result = request(
        address, ca_file, "", "POST", "secret/data/large",
        {"data": {"payload": "unauthorized-must-not-commit"}},
    )
    check("unauthorized_write_denied", status, status == 403
          and "data" not in result and "auth" not in result)
    read("version_unchanged", 2, selected=False)

    restart()
    check("restart", None, True)
    read("cold_read_v1", 1)
    read("cold_read_v2", 2)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--private-work-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.output.exists():
        raise RuntimeError("report_already_exists")
    if args.private_work_root.exists():
        raise RuntimeError("fixture_root_already_exists")
    # Verify custody BEFORE creating fixtures; unsupported host/architecture
    # must fail closed, rather than silently comparing a different Oracle.
    verify_inputs(version=VERSION)
    before = source_identity(ROOT, args.binary)
    args.private_work_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.environ["HB_ORACLE_WORK_ROOT"] = str(args.private_work_root)
    report = {
        "schema": "heptabao.openbao271-kv2-2560k-https-differential.v1",
        **before,
        "official_version": VERSION,
        "official_artifact": pinned_artifact(version=VERSION),
        "synthetic_only": True,
        "tls_verified": True,
        "v6_ha_qualified": False,
        "full_compatibility_claim": False,
        "replacement_authority": False,
        "observations": {},
        "failures": {},
    }
    for label in ("official", "candidate"):
        oracle = None
        candidate = None
        try:
            if label == "official":
                oracle = start_oracle(free_loopback_port(), version=VERSION)
                address = oracle["address"]
                ca_file = Path(oracle["ca_file"])
                token = private_read(Path(oracle["token_file"])).decode().strip()

                def restart():
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                candidate = Instance(args.binary, args.private_work_root / "candidate")
                candidate.start()
                status, initialized = candidate.call(
                    "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1},
                )
                if status != 200:
                    raise RuntimeError("candidate_initialize")
                token = initialized["root_token"]
                key = initialized["keys_base64"][0]
                candidate.token = token
                if candidate.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise RuntimeError("candidate_unseal")
                address = candidate.address
                ca_file = candidate.root / "ca.crt"

                def restart():
                    candidate.stop()
                    candidate.start()
                    if candidate.call("POST", "sys/unseal", {"key": key})[0] != 200:
                        raise RuntimeError("candidate_reunseal")
            report["observations"][label] = []
            # Retain each partial observation on failure, not only on success.
            rows = report["observations"][label]
            scenario(address, ca_file, token, restart, rows)
        except BaseException as error:
            # No transport exceptions or opaque provider text in shared JSON.
            report["failures"][label] = (
                str(error) if isinstance(error, RuntimeError)
                and str(error) in EXPECTED + (
                    "candidate_initialize", "candidate_unseal", "candidate_reunseal",
                ) else type(error).__name__
            )
        finally:
            if candidate is not None:
                candidate.stop()
            if oracle is not None:
                stop_oracle(oracle)

    after = source_identity(ROOT, args.binary)
    report["source_and_binary_unchanged"] = before == after
    official = {row["case"]: row for row in report["observations"].get("official", [])}
    candidate = {row["case"]: row for row in report["observations"].get("candidate", [])}
    report["mismatches"] = [
        {"case": case, "official_status": official[case]["status"],
         "candidate_status": candidate[case]["status"]}
        for case in EXPECTED if case in official and case in candidate
        and (official[case]["status"] != candidate[case]["status"]
             or official[case]["passed"] != candidate[case]["passed"])
    ]
    report["status"] = "passed" if (
        not report["failures"] and not report["mismatches"] and before == after
        and all(
            [row["case"] for row in report["observations"].get(label, [])]
            == list(EXPECTED)
            and all(row["passed"] for row in report["observations"][label])
            for label in ("official", "candidate")
        )
    ) else "failed"
    private_write(args.output, report, replace=False)
    print(json.dumps({
        "status": report["status"],
        "failures": report["failures"], "mismatches": report["mismatches"],
        "source_commit": before["source_commit"],
        "binary_sha256": before["binary_sha256"],
        "replacement_authority": False,
    }))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
