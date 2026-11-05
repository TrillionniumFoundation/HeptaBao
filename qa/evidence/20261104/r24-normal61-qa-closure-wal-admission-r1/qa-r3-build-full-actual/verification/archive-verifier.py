#!/usr/bin/env python3
"""Verify complete original QA command streams, Cargo events and retained dependency locks."""
import hashlib
import json
import sys
import tomllib
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
core = json.loads(data["core_raw"])
files = data["command_files"]
checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append({"name":name,"passed":True})
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()
check("original-core-qualified-success", core["status"] == "passed"
      and core["schema"] == "heptabao.native-h2-qa.build.v3"
      and core["all_owned_stopped"] and core["all_input_fds_closed"]
      and not core["command_outcome_unknown"])
labels = [r["label"] for r in core["commands"]]
check("all-thirty-six-original-command-files", len(labels) == 12 and len(set(labels)) == 12
      and set(files) == {name + suffix for name in labels for suffix in (".public.json",".stdout",".stderr")})
for record in core["commands"]:
    name = record["label"]
    check("standalone-record-" + name, json.loads(files[name+".public.json"]) == record)
    for suffix in ("stdout","stderr"):
        check("whole-stream-" + name + "." + suffix,
              sha(files[name+"."+suffix]) == record[suffix+"_sha256"])
root = "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3"
cargo_counts = {}
for name, role, test in (("build","executable",False),("components-build","component_binary",True)):
    info = json.loads(data["cargo_stream_info_raws"][name])
    raw = files[name+".stdout"]
    check("cargo-original-info-" + name, info["path"] == root + "/" + name + ".stdout"
          and len(raw.encode()) == info["size"] and sha(raw) == info["sha256"]
          == core[role]["cargo_stdout_sha256"])
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    check("cargo-json-dictionaries-" + name, all(type(event) is dict for event in events))
    finished = [event for event in events if event.get("reason") == "build-finished"]
    check("one-actual-success-" + name, len(finished) == 1 and finished[0].get("success") is True
          and events[-1] == finished[0])
    candidates = [event for event in events if event.get("reason") == "compiler-artifact"
                  and event.get("target",{}).get("name") == "heptabao-native-h2-qa"
                  and event.get("executable")]
    check("single-owned-artifact-" + name, len(candidates) == 1)
    event = candidates[0]
    check("actual-cargo-artifact-profile-" + name, event["features"] == core[role]["features"] == []
          and event["profile"] == core[role]["profile"]
          == {"opt_level":"3","debuginfo":0,"debug_assertions":True,"overflow_checks":True,"test":test})
    check("actual-cargo-owned-project-" + name,
          event["manifest_path"] == root + "/project/Cargo.toml"
          and event["target"]["src_path"] == root + "/project/native_h2_client.rs"
          and event["executable"] == core[role]["compiler_executable"])
    check("no-cargo-error-message-" + name, not any(event.get("reason") == "compiler-message"
          and event.get("message",{}).get("level") == "error" for event in events))
    command = next(r for r in core["commands"] if r["label"] == name)
    expected = ["build","--release","--locked","--offline","--bin","heptabao-native-h2-qa",
                "--message-format=json-render-diagnostics"] if not test else [
                "test","--release","--locked","--offline","--bin","heptabao-native-h2-qa",
                "--no-run","--message-format=json-render-diagnostics"]
    check("original-exact-cargo-flags-" + name, command["argv"][1:] == expected
          and command["argv"][0] == "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo"
          and command["outer_cap_seconds"] == 180)
    cargo_counts[name] = len(events)
for phase in ("before","after"):
    check("raw-canonical-commit-" + phase, files["source-"+phase+"-commit.stdout"]
          == core["candidate_commit"] + "\n")
    check("raw-canonical-tree-" + phase, files["source-"+phase+"-tree.stdout"]
          == core["candidate_tree"] + "\n")
    check("raw-canonical-clean-" + phase, files["source-"+phase+"-status.stdout"] == "")
check("actual-rustc-version", files["rustc-version.stdout"] == core["rustc_vv"]
      and "release: 1.98.0\n" in core["rustc_vv"] and "host: x86_64-unknown-linux-gnu\n" in core["rustc_vv"])
actual_raw, canonical_raw = data["qa_lock_raw"], data["canonical_lock_original_raw"]
actual = tomllib.loads(actual_raw)
canonical = tomllib.loads(canonical_raw)
manifest = tomllib.loads(data["cargo_manifest_raw"])
qi = json.loads(data["qa_lock_info_raw"])
ci = json.loads(data["canonical_copy_info_raw"])
check("qa-retained-lock-whole", sha(actual_raw) == qi["sha256"] == core["lock_subset"]["qa_lock_sha256"]
      and len(actual_raw.encode()) == qi["size"])
check("canonical-retained-copy-whole-observation", sha(canonical_raw) == ci["sha256"]
      == core["lock_subset"]["canonical_sha256"]
      == "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
      and len(canonical_raw.encode()) == ci["size"] == 101193)
for role, info in (("qa",qi),("canonical",ci)):
    check("retained-lock-custody-" + role, info["mode"] == info["metadata"]["mode"] == 0o600
          and info["metadata"]["uid"] == info["metadata"]["gid"] == 1000
          and info["metadata"]["link_count"] == 1)
allowed = {}
for package in canonical["package"]:
    key = (package["name"], package["version"], package.get("source"))
    if key in allowed:
        raise AssertionError("duplicate canonical package")
    allowed[key] = package.get("checksum")
members, seen, owned = [], set(), []
for package in actual["package"]:
    key = (package["name"],package["version"],package.get("source"))
    if key in seen:
        raise AssertionError("duplicate actual package")
    seen.add(key)
    check("actual-package-fields-" + package["name"] + "@" + package["version"],
          set(package) <= {"name","version","source","checksum","dependencies"}
          and all(type(value) is str for value in package.get("dependencies",[])))
    if package["name"] == "heptabao-native-h2-qa":
        owned.append(package)
        continue
    check("exact-canonical-member-" + package["name"] + "@" + package["version"],
          package.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
          and key in allowed and package.get("checksum") == allowed[key])
    members.append({key:package[key] for key in ("name","version","source","checksum")})
members.sort(key=lambda item:(item["name"],item["version"],item["source"]))
check("one-owned-qa-root", len(owned) == 1 and owned[0]["version"] == manifest["package"]["version"] == "0.1.0"
      and owned[0]["name"] == manifest["package"]["name"]
      and "source" not in owned[0] and "checksum" not in owned[0])
expected = {"schema":"heptabao.native-h2-qa.lock-subset.v1",
            "canonical_sha256":sha(canonical_raw),"qa_lock_sha256":sha(actual_raw),
            "registry_package_count":len(members),"owned_qa_package_count":len(owned),
            "packages":members,"exact_version_source_checksum_subset":True}
check("full-actual-subset-equals-core", expected == core["lock_subset"]
      and len(members) == 76)
print(json.dumps({
 "schema":"heptabao.qa-r3.actual-archive-check.v1","status":"passed",
 "check_count":len(checks),"checks":checks,"command_records":12,"command_streams":24,
 "all_command_files":36,"cargo_event_counts":cargo_counts,"registry_members":len(members),
 "canonical_copy_body_provenance":"Previous independently read and root-accepted exact input bytes; this run's retained-copy independent file_info whole SHA matches. No new retained canonical payload read is claimed.",
 "actual_qa_lock_payload_read":True,"unsafe_ns_not_reserialized":True,
 "parent_core_verification_blob":data["verified_core_check_blob"],
 "qa_components_denominator":6,"product_or_http_requests":0,
 "host_or_child_calls_by_this_verifier":0
},indent=2,sort_keys=True))
