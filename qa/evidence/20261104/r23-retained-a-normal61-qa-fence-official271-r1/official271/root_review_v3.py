"""Pure-data official 2.7.1 inventory refinement and current native gap binding.

No product code, host operation, provider request, or runtime coverage is executed.
All outputs are evidence artifacts for the existing HeptaBao Git repository.
"""
import base64
import collections
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
payload = json.loads(sys.argv[1])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def write(name, raw):
    path = BASE / name
    path.write_bytes(raw)
    return {"name": name, "bytes": len(raw), "sha256": digest(raw), "git_blob": git_blob(raw)}


inventory_raw = (BASE / "official271-source-contract-declarations-v2.public.json").read_bytes()
assert digest(inventory_raw) == "239492f70e7e66aaa193c4c322d88edc1dc2e9b8c0c4379f9c9b20971ccaadac"
before = json.loads(inventory_raw)
corpus_raw = (BASE / "source-corpus-r3.json").read_bytes()
assert digest(corpus_raw) == "bc478d26bf1a58720bb5195e9894f648cd2aa9968aecd79a529950146f1d5f6d"
corpus = json.loads(corpus_raw)
tree = json.loads((BASE / "official-tree.original.json").read_bytes())
entries = sorted([[e["path"], e["mode"], e["type"], e["sha"], e.get("size")] for e in tree["tree"]])
entry_raw = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode()
assert digest(entry_raw) == payload["official_entry_sha256"]
tree_paths = {e["path"]: e for e in tree["tree"]}
official_metas = {m["path"]: m for m in corpus["metas"]}
assert len(corpus["sources"]) == len(official_metas) == 242
for path, text in corpus["sources"].items():
    raw = text.encode()
    meta = official_metas[path]
    assert (len(raw), digest(raw), git_blob(raw)) == (meta["bytes"], meta["sha256"], meta["blob"])
    assert tree_paths[path]["sha"] == meta["blob"] and tree_paths[path]["type"] == "blob"
assert sum(m["bytes"] for m in official_metas.values()) == 3894129

product_raw = (BASE / "product-corpus.json").read_bytes()
assert digest(product_raw) == "d1f17d4a194aef6e443a87f3d2c207043a04bd2755b70bbb18dcea093ebf9ea6"
product = json.loads(product_raw)
product_metas = {m["path"]: m for m in product["metas"]}
bindings = {m["path"]: m for m in payload["current_product_bindings"]}
assert set(bindings) == set(product_metas) == set(product["sources"])
for path, text in product["sources"].items():
    raw = text.encode()
    meta, binding = product_metas[path], bindings[path]
    assert (len(raw), digest(raw), git_blob(raw)) == (meta["bytes"], meta["sha256"], meta["blob"])
    assert binding["same"] and binding["current_blob"] == meta["blob"]
    assert binding["bytes"] == len(raw) and binding["sha256"] == digest(raw)

after = copy.deepcopy(before)
changes = []
collections_to_check = ("route_declarations", "route_operation_declarations", "field_schema_declarations", "registration_and_lifecycle_sites")
for collection in collections_to_check:
    for number, row in enumerate(after[collection]):
        assert row["source_blob"] == official_metas[row["source"]]["blob"]
        if "family" not in row:
            continue
        old_family = row["family"]
        new_family = old_family
        if row["source"].startswith("internal/vault/identity/") or old_family == "identity-and-mfa":
            new_family = "identity"
        elif row["source"] == "internal/vault/logical_raw.go":
            new_family = "sys/raw"
        if new_family != old_family:
            row["family"] = new_family
            changes.append({"collection": collection, "index": number, "source": row["source"], "previous_family": old_family, "family": new_family})

# A source-family correction changes neither declaration identities nor semantics.
inverse = copy.deepcopy(after)
for change in changes:
    inverse[change["collection"]][change["index"]]["family"] = change["previous_family"]
assert inverse == before
assert [len(after[k]) for k in collections_to_check] == [423, 720, 1064, 128]
assert len({r["declaration_id"] for r in after["route_declarations"]}) == 423
declarations = {r["declaration_id"]: r for r in after["route_declarations"]}
assert all(r["declaration_id"] in declarations for r in after["route_operation_declarations"])
assert all(r["declaration_id"] in declarations for r in after["field_schema_declarations"])
after["schema"] = "official271-source-contract-declarations-v3"
after["family_operation_counts"] = dict(sorted(collections.Counter(r["family"] for r in after["route_operation_declarations"]).items()))
after["source_family_refinement"] = {
    "purpose": "Correct identity source files and the conditional raw backend previously grouped under shared-core-or-registry.",
    "rules": ["internal/vault/identity/* and previous identity-and-mfa -> identity", "internal/vault/logical_raw.go -> sys/raw"],
    "changes": changes,
    "all_other_inventory_bytes_semantically_unchanged": True,
    "does_not_establish_registration_or_HTTP_reachability": True,
}
after["complete_runtime_route_denominator"] = False
after["whole_openbao271_replacement"] = False

gap = payload["prior_gap_map"]
gates = []
for row in gap["action_rows"]:
    new = copy.deepcopy(row)
    new["status"] = "OPEN"
    new["evidence_kind"] = "CURRENT_NATIVE_SOURCE_GUARD_OR_SEPARATELY_IDENTIFIED_RUNTIME_GATE"
    new["current_candidate_runtime_qualified"] = False
    new["current_source_anchor_bindings"] = []
    for anchor_index, anchor in enumerate(row["source_anchors"]):
        path = anchor[0]
        if path in bindings:
            assert type(anchor[1]) is int and type(anchor[2]) is int
            lines = product["sources"][path].splitlines()
            end_line = anchor[2]
            if path == "crates/heptabao-server/src/engines/pki_native.rs" and anchor == [path, 1, 32]:
                assert len(lines) == 29 and bindings[path]["current_blob"] == "39d2a76d45894fb377a391e400cee7fe894ad9c1"
                end_line = 29
                new["source_anchors"][anchor_index] = [path, 1, end_line]
                new.setdefault("historical_anchor_corrections", []).append({
                    "path": path, "previous_line_range": [1, 32], "current_exact_line_range": [1, 29],
                    "reason": "The previous partial source map cited past EOF. The entire verified file has29 lines; its original blob is preserved.",
                })
            assert 1 <= anchor[1] <= end_line <= len(lines)
            new["current_source_anchor_bindings"].append({
                "path": path, "line_start": anchor[1], "line_end": end_line,
                "blob": bindings[path]["current_blob"], "whole_sha256": bindings[path]["sha256"],
                "excerpt_sha256": digest(("\n".join(lines[anchor[1]-1:end_line])+"\n").encode()),
            })
    if row["id"] == "native_snapshot_cli_and_standby":
        new["historical_boundary_retained"] = new.pop("current_boundary")
        new["current_boundary"] = (
            "Current 1c665 Mac run passed the original60 and failed the additional same-root test before entering the repair checks. "
            "Successor4e808 changes only that test fixture and is source-only at this audit. "
            "Last physical df026 LAN run stopped at91/98 with post-cold0/12 unentered. "
            "Separate snapshot/CLI and trusted AuthBus gates remain open; historical unknown operations are not replayed."
        )
        new["required_work"] = (
            "Pass actual successor normal61 on Mac and Linux, then the original physical98 plus independent post-cold12. "
            "Use newly qualified artifacts for the bounded current-WAL diagnosis, actual valid A/B archives with two-version API readback and cold restart, "
            "and the separate reviewed standby transfer custody. Do not infer archive success from redirects or CLI exit alone."
        )
    gates.append(new)

report = {
    "schema": "heptabao.root.current-native-openbao271-gates.v1",
    "as_of_utc": payload["as_of_utc"],
    "status": "FULL_REPLACEMENT_FALSE_OPEN_IMPLEMENTATION_AND_RUNTIME_GATES",
    "official": {"repository": "openbao/openbao", "tag": "v2.7.1", "commit": before["official_commit"], "tree": before["official_tree"], "canonical_entries_sha256": payload["official_entry_sha256"], "root_merkle_trees_verified": 939, "entries": 6328, "source_files_in_corpus": 242, "source_bytes_in_corpus": 3894129},
    "native_product_binding": {"commit": "1c66541993662f92cf717154e33717abedb2ea74", "tree": "94ced21a63ff9aaca4538c0d4796efea2150e632", "verified_current_files": payload["current_product_bindings"], "files": 14, "bytes": sum(x["bytes"] for x in bindings.values()), "normal_features": ["default", "native-v6-ha", "native-v6-storage"]},
    "successor": {"commit": "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec", "tree": "eba5e650bd080b8ad41ea52a2bc68867f541d255", "parent": "1c66541993662f92cf717154e33717abedb2ea74", "changed_path": "crates/heptabao-server/src/service_native_v6_ha_same_root_republication_tests.rs", "all14_native_guard_files_unchanged": True, "runtime_qualification_transferred": False},
    "source_inventory": {"declarations": 423, "declared_operations": 720, "declared_fields": 1064, "registration_and_lifecycle_sites": 128, "family_operation_counts": after["family_operation_counts"], "runtime_denominator": False, "behavior_coverage": False},
    "official_default_registry": gap["official_registry"],
    "open_work": gates,
    "conditional_or_nondefault_contracts_not_invented": gap["do_not_invent_gates"],
    "implementation_principle": "Implement typed native owner, migration/cold codec, authorization, mandatory audit, revocation/renewal and unknown external-effect reconciliation before widening admission guards.",
    "qualifications": {"whole_openbao271_replacement": False, "all_official_runtime_routes_resolved": False, "current_lan_complete": False, "current_authbus_complete": False, "all_consumers_and_backups_migrated": False, "production_cutover": False, "old_versions_deletion": False},
    "limits": [
        "Counts are lexical source declarations. Dynamic factories, conditional registration, framework-generated routes, HTTP method/existence-check mapping, help, configuration and lifecycle remain unresolved.",
        "A complete API inventory would still require real behavior, state, errors, authority and recovery tests; source registration is not a test result.",
        "Current native guards show concrete admission gaps. Existing legacy implementations and scoped tests do not qualify a full migration of those states into native storage.",
        "Installed-client cutover is a separate finite migration claim; it cannot establish universal OpenBao2.7.1 compatibility.",
        "No host operations, credentials, provider effects, product tests, cutover or deletion were performed by this data analysis.",
    ],
}

artifacts = []
artifacts.append(write("root-review-v3-input.public.json", encoded(payload)))
artifacts.append(write("official271-source-contract-declarations-v3.public.json", encoded(after)))
artifacts.append(write("current-native-openbao271-gates.public.json", encoded(report)))
proof = {
    "schema": "heptabao.root.official271-source-refinement-proof.v1", "status": "PASS_SOURCE_ONLY",
    "official_files_all_whole_git_sha1_sha256_and_membership_verified": 242,
    "product_current_files_all_whole_git_sha1_sha256_and_binding_verified": 14,
    "same_declarations_operations_fields_lifecycle_counts": [423,720,1064,128],
    "family_rows_changed": len(changes), "family_inverse_exact": True,
    "all423_declaration_ids_unique": True, "all_operation_and_field_declaration_ids_resolved": True,
    "full_runtime_denominator": False, "full_replacement": False,
    "artifacts": artifacts,
}
artifacts.append(write("root-source-refinement-proof.public.json", encoded(proof)))
v3_raw = (BASE / "official271-source-contract-declarations-v3.public.json").read_bytes()
compressed = gzip.compress(v3_raw, mtime=0)
text = base64.b64encode(compressed)
compressed_meta = write("official271-source-contract-v3.gzip.base64", text)
artifacts.append(compressed_meta)
artifact_index = {"schema":"heptabao.root.official271-review-artifact-index.v1", "files": artifacts,
    "compressed_inventory": {"encoding":"base64 then gzip", "decoded_gzip_bytes":len(compressed), "decoded_gzip_sha256":digest(compressed), "uncompressed_bytes":len(v3_raw), "uncompressed_sha256":digest(v3_raw)},
    "source_corpus_manifest":"corpus-checkpoint-index.public.json", "git_repository_persistence_pending": True}
index_meta = write("root-review-v3-artifact-index.public.json", encoded(artifact_index))
print(json.dumps({"status":"PASS_SOURCE_ONLY", "artifacts":artifacts, "index":index_meta,
                  "families":after["family_operation_counts"], "changed_family_rows":len(changes),
                  "host_calls":0, "full_replacement":False},sort_keys=True))
