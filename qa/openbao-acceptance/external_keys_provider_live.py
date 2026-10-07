#!/usr/bin/env python3
"""Candidate-only External Keys verification through an admitted KMS provider.

This profile proves the Service external-effect boundary and durable publication.
It does not claim OpenBao provider interoperability or Transit/PKI key consumption.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure(instance: smoke.Instance, root: Path):
    trace = root / "external-key-provider-trace.jsonl"
    wrapper = root / "external-key-sandbox-wrapper.py"
    plugin = root / "external-key-provider.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
args=sys.argv[1:]
def value(flag): return args[args.index(flag)+1]
if value('--heptabao-profile')!='external_keys_profile' or value('--heptabao-protocol')!='1' or value('--heptabao-operation')!='read':
    raise SystemExit(64)
os.execv(value('--heptabao-plugin'),[value('--heptabao-plugin')])
""",
    )
    plugin_sha = make_exec(
        plugin,
        f"""#!{sys.executable}
import json,struct,sys,time
TRACE={str(trace)!r}
frame=sys.stdin.buffer.read(1048588)
if len(frame)<11 or frame[:4]!=b'HBP1' or frame[4:6]!=b'\\x00\\x01' or frame[6]!=1:
    raise SystemExit(65)
length=struct.unpack('>I',frame[7:11])[0]
if length==0 or len(frame)!=11+length:
    raise SystemExit(65)
request=json.loads(frame[11:].decode('utf-8'))
action=request.get('action')
if action not in ('verify_config','verify_key'):
    raise SystemExit(66)
if request.get('plugin') not in ('transit','pkcs11'):
    raise SystemExit(66)
values=[]
for name in ('values','config_values','key_values'):
    value=request.get(name,{{}})
    if not isinstance(value,dict):
        raise SystemExit(66)
    values.append(value)
with open(TRACE,'a',encoding='utf-8') as output:
    output.write(json.dumps({{'action':action,'config':request.get('config'),'key':request.get('key')}},sort_keys=True,separators=(',',':'))+'\\n')
if any(value.get('provider_timeout') is True for value in values):
    time.sleep(2)
verified=not any(value.get('provider_reject') is True for value in values)
response={{'verified':verified,'namespace':request.get('namespace'),'action':action,
          'plugin':request.get('plugin'),'config':request.get('config')}}
if action=='verify_key':
    response['key']=request.get('key')
encoded=json.dumps(response,sort_keys=True,separators=(',',':')).encode('utf-8')
sys.stdout.buffer.write(b'HBR1'+struct.pack('>I',len(encoded))+encoded)
""",
    )
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    base = {
        "command": str(plugin),
        "command_sha256": plugin_sha,
        "sandbox_provider_id": "external_keys_sandbox",
        "sandbox_command": str(wrapper),
        "sandbox_command_sha256": wrapper_sha,
        "sandbox_profile_id": "external_keys_profile",
        "key_version": 1,
        "capabilities": ["wrap"],
        "maximum_request_bytes": 262144,
        "maximum_response_bytes": 262144,
        "timeout_ms": 300,
    }
    config["plugin_kms"] = [
        dict(base, id="transit", key_id="external_keys_transit_provider"),
        dict(base, id="pkcs11", key_id="external_keys_pkcs11_provider", enabled=False),
    ]
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)
    return plugin, trace, plugin.read_bytes(), plugin_sha


def trace_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run(binary: Path, root: Path) -> None:
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    instance = smoke.Instance(binary, root / "server")
    plugin, trace, original_plugin, plugin_sha = configure(instance, root)
    passed: list[str] = []

    def check(name: str, condition: bool) -> None:
        if condition is not True:
            raise RuntimeError(name)
        passed.append(name)

    config = "sys/external-keys/configs/verified"
    key_path = config + "/keys/signing"
    secret_canary = "synthetic-provider-credential-never-report"
    try:
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        unseal = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)

        status, catalog = instance.call("LIST", "sys/plugins/catalog/kms")
        check(
            "catalog_lists_verification_providers",
            status == 200
            and catalog.get("data", {}).get("keys") == ["pkcs11", "transit"],
        )
        status, detail = instance.call("GET", "sys/plugins/catalog/kms/transit")
        check(
            "catalog_binds_provider_checksum",
            status == 200
            and detail.get("data", {}).get("sha256") == plugin_sha
            and detail.get("data", {}).get("state") == "active",
        )

        status, _ = instance.call(
            "POST",
            config,
            {
                "plugin": "transit",
                "address": "https://provider.invalid",
                "token": secret_canary,
            },
        )
        check("default_verify_config_contacts_provider", status == 204)
        check(
            "config_provider_request_is_exact",
            trace_rows(trace)
            == [{"action": "verify_config", "config": "verified", "key": None}],
        )
        status, readback = instance.call("GET", config)
        check(
            "verified_config_published_with_secret_redaction",
            status == 200
            and readback.get("data", {}).get("plugin") == "transit"
            and readback.get("data", {}).get("token") == "(redacted)",
        )

        status, _ = instance.call(
            "POST", key_path, {"name": "remote-signing-key", "version": 7}
        )
        check("default_verify_key_contacts_provider", status == 204)
        check(
            "key_provider_request_is_exact",
            trace_rows(trace)[-1]
            == {"action": "verify_key", "config": "verified", "key": "signing"},
        )
        status, key_read = instance.call("GET", key_path)
        check(
            "verified_key_published",
            status == 200
            and key_read.get("data") == {"name": "remote-signing-key", "version": 7},
        )

        entered = len(trace_rows(trace))
        check(
            "grant_mutation_never_contacts_provider",
            instance.call("POST", key_path + "/grants/pki", {})[0] == 204
            and len(trace_rows(trace)) == entered,
        )
        check(
            "disabled_provider_fails_before_entry",
            instance.call(
                "POST",
                "sys/external-keys/configs/disabled",
                {"plugin": "pkcs11", "slot": 1},
            )[0]
            == 403
            and len(trace_rows(trace)) == entered,
        )

        status, _ = instance.call(
            "POST",
            "sys/external-keys/configs/rejected",
            {"plugin": "transit", "provider_reject": True, "token": "must-not-persist"},
        )
        check("provider_rejection_fails_closed", status == 503)
        check(
            "provider_rejection_never_publishes_candidate",
            instance.call("GET", "sys/external-keys/configs/rejected")[0] != 200,
        )

        entered = len(trace_rows(trace))
        check(
            "verify_false_never_contacts_provider",
            instance.call(
                "POST",
                "sys/external-keys/configs/unverified",
                {"plugin": "transit", "verify": False, "provider_timeout": True},
            )[0]
            == 204
            and len(trace_rows(trace)) == entered,
        )

        instance.stop()
        instance.start()
        check(
            "restart_unseal",
            instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200,
        )
        check("restart_does_not_replay_provider_effect", len(trace_rows(trace)) == entered)
        check("restart_preserves_verified_config", instance.call("GET", config)[0] == 200)
        check("restart_preserves_verified_key", instance.call("GET", key_path)[0] == 200)

        with plugin.open("ab") as stream:
            stream.write(b"\n# changed after admission\n")
        check(
            "changed_provider_binary_fails_before_entry",
            instance.call(
                "POST",
                "sys/external-keys/configs/changed",
                {"plugin": "transit", "address": "https://changed.invalid"},
            )[0]
            == 503
            and len(trace_rows(trace)) == entered,
        )
        check(
            "changed_provider_candidate_not_published",
            instance.call("GET", "sys/external-keys/configs/changed")[0] != 200,
        )
        plugin.write_bytes(original_plugin)
        plugin.chmod(0o700)

        status, _ = instance.call(
            "POST",
            "sys/external-keys/configs/timeout",
            {
                "plugin": "transit",
                "provider_timeout": True,
                "token": "timeout-candidate-must-not-persist",
            },
        )
        check("post_entry_timeout_fails_closed", status == 503)
        entered_after_timeout = len(trace_rows(trace))
        check("post_entry_timeout_reached_provider_once", entered_after_timeout == entered + 1)
        check(
            "timeout_candidate_not_published",
            instance.call("GET", "sys/external-keys/configs/timeout")[0] != 200,
        )
        status, detail = instance.call("GET", "sys/plugins/catalog/kms/transit")
        check(
            "timeout_fences_provider_host",
            status == 200
            and detail.get("data", {}).get("state") == "reconciliation_required",
        )
        check(
            "fenced_provider_rejects_blind_retry",
            instance.call(
                "POST",
                "sys/external-keys/configs/blind-retry",
                {"plugin": "transit", "address": "https://retry.invalid"},
            )[0]
            == 503
            and len(trace_rows(trace)) == entered_after_timeout,
        )

        instance.stop()
        instance.start()
        check(
            "restart_after_unknown_unseal",
            instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200,
        )
        check(
            "restart_does_not_replay_unknown_effect",
            len(trace_rows(trace)) == entered_after_timeout
            and instance.call("GET", "sys/external-keys/configs/timeout")[0] != 200,
        )
        check(
            "restart_readmits_fresh_provider",
            instance.call(
                "POST",
                "sys/external-keys/configs/after-restart",
                {"plugin": "transit", "address": "https://fresh.invalid"},
            )[0]
            == 204
            and len(trace_rows(trace)) == entered_after_timeout + 1,
        )

        trace_bytes = trace.read_bytes()
        service_files = [
            path.read_bytes()
            for path in (instance.root / "data").rglob("*")
            if path.is_file()
        ]
        check(
            "provider_trace_and_service_disk_do_not_expose_credentials",
            secret_canary.encode() not in trace_bytes
            and secret_canary.encode() not in b"".join(service_files),
        )
        print(
            json.dumps(
                {
                    "status": "passed",
                    "checks": passed,
                    "count": len(passed),
                    "scope": "candidate_external_keys_verify_true_provider_publication_boundary",
                    "openbao_provider_interoperability": False,
                    "transit_or_pki_external_key_consumption": False,
                    "full_openbao_compatibility": False,
                    "independent_qualification": False,
                    "production_authority": False,
                },
                sort_keys=True,
            )
        )
    finally:
        instance.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute():
        parser.error("paths must be absolute")
    try:
        run(args.binary.resolve(), args.work_dir.resolve())
    except Exception as error:
        print(
            "external keys provider live failed: " + type(error).__name__,
            file=sys.stderr,
        )
        raise SystemExit(1) from None
