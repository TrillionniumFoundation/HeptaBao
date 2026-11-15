#!/usr/bin/env python3
"""Strict static ELF/provider compatibility for the X230 admission boundary.

Parse completed, pinned readelf -W -h -l -d --version-info observations.
The caller supplies normal107 artifact pins and freshly checks the receiver
files through its existing owned command runner. This module executes no binary
and never declares a runtime workload passed.
"""
from __future__ import annotations
import hashlib
import re
import struct

class AbiRefused(RuntimeError):
    pass

def need(value, reason):
    if not value:
        raise AbiRefused(reason)

def unique(items, reason):
    values = list(items)
    need(len(values) == len(set(values)), reason)
    return values

def parse_elf_observation(header_hex, raw):
    """Return a closed ELF summary; refuse malformed or truncated tool output."""
    need(isinstance(raw, str) and 0 < len(raw.encode()) <= 1024 * 1024
         and "\x00" not in raw, "bounded_readelf_output_required")
    try:
        header = bytes.fromhex(header_hex)
    except (TypeError, ValueError):
        raise AbiRefused("invalid_actual_elf_header") from None
    need(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
         and header[7] in (0, 3)
         and struct.unpack_from("<H", header, 18)[0] == 62
         and struct.unpack_from("<I", header, 20)[0] == 1
         and struct.unpack_from("<H", header, 52)[0] == 64,
         "actual_elf64_little_endian_x86_64_required")
    elf_type = struct.unpack_from("<H", header, 16)[0]
    need(elf_type in (2, 3), "executable_or_shared_elf_required")
    phnum = struct.unpack_from("<H", header, 56)[0]
    need(0 < phnum < 65535 and struct.unpack_from("<H", header, 54)[0] == 56,
         "ordinary_program_header_table_required")
    need(raw.count("ELF Header:") == 1 and not re.search(r"(?im)readelf:\s*(?:Error|Warning)", raw),
         "single_complete_readelf_object_required")
    def field(label):
        matches = re.findall(r"(?m)^\s*" + re.escape(label) + r":\s*(.*?)\s*$", raw)
        need(len(matches) == 1, "one_elf_header_field_" + label.replace(" ", "_"))
        return matches[0]
    need(field("Class") == "ELF64" and field("Data") == "2's complement, little endian"
         and field("Machine") == "Advanced Micro Devices X86-64"
         and field("Type").split()[0] == {2: "EXEC", 3: "DYN"}[elf_type]
         and field("Number of program headers") == str(phnum),
         "readelf_header_matches_actual_bytes")
    program = re.search(r"(?ms)^Program Headers:\s*\n(.*?)(?=^\s*Section to Segment mapping:)", raw)
    need(program is not None, "complete_program_headers_required")
    rows = re.findall(r"(?m)^\s*(\S+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+", program[1])
    need(len(rows) == phnum and rows.count("LOAD") >= 1, "program_header_count_matches_actual_bytes")
    interpreter = re.findall(r"\[Requesting program interpreter: ([^\]\r\n]+)\]", program[1])
    need(len(interpreter) == rows.count("INTERP") and len(interpreter) <= 1,
         "one_unambiguous_interpreter")
    if interpreter:
        need(re.fullmatch(r"/[A-Za-z0-9_./+-]+", interpreter[0])
             and "//" not in interpreter[0] and "/../" not in interpreter[0],
             "absolute_literal_interpreter_required")
    dynamic_heads = re.findall(r"(?m)^Dynamic section at offset \S+ contains (\d+) entries:", raw)
    need(len(dynamic_heads) == 1 and rows.count("DYNAMIC") == 1, "one_dynamic_section_required")
    entries = re.findall(r"(?m)^\s*0x[0-9a-f]+\s+\(([^)]+)\)\s+(.*?)\s*$", raw)
    need(len(entries) == int(dynamic_heads[0]) and entries[-1][0] == "NULL",
         "complete_dynamic_entry_count")
    forbidden = {"RPATH", "RUNPATH", "FILTER", "AUXILIARY", "AUDIT", "DEPAUDIT"}
    need(not any(tag in forbidden for tag, _ in entries), "unmodeled_loader_search_or_audit_path_refused")
    def dynamic_names(tag, description):
        result = []
        for key, value in entries:
            if key != tag:
                continue
            match = re.fullmatch(re.escape(description) + r": \[([A-Za-z0-9_.+-]+)\]", value)
            need(match is not None, "literal_dynamic_library_name_required")
            result.append(match[1])
        return unique(result, "duplicate_dynamic_library_name")
    needed = dynamic_names("NEEDED", "Shared library")
    sonames = dynamic_names("SONAME", "Library soname")
    need(len(sonames) <= 1, "one_soname_required")
    definitions, needs, needs_index = {}, {}, {}
    sections = list(re.finditer(
        r"(?m)^Version (symbols|definition|needs) section '[^']+' contains (\d+) entr(?:y|ies):\s*$", raw))
    unique((section[1] for section in sections), "duplicate_version_section")
    section_counts = {section[1]: int(section[2]) for section in sections}
    for name, count_tag, address_tag in (("needs", "VERNEEDNUM", "VERNEED"),
                                          ("definition", "VERDEFNUM", "VERDEF")):
        counts = [value for tag, value in entries if tag == count_tag]
        addresses = [value for tag, value in entries if tag == address_tag]
        need((not counts and not addresses and name not in section_counts)
             or (len(counts) == len(addresses) == 1 and counts[0].isdecimal()
                 and int(counts[0]) == section_counts.get(name) and int(counts[0]) > 0),
             "dynamic_version_contract_missing_or_truncated_" + name)
    need(sum(tag == "VERSYM" for tag, _ in entries) == int("symbols" in section_counts),
         "dynamic_version_symbol_table_missing_or_duplicated")
    for pos, section in enumerate(sections):
        body = raw[section.end():sections[pos + 1].start() if pos + 1 < len(sections) else len(raw)]
        count = int(section[2])
        need(0 < count <= 65535, "bounded_nonzero_version_section")
        if section[1] == "symbols":
            continue
        if section[1] == "definition":
            records = list(re.finditer(
                r"(?m)^\s*(?:0x)?[0-9a-f]+:\s+Rev: 1\s+Flags: (\S+)\s+Index: (\d+)\s+Cnt: (\d+)\s+Name: ([A-Za-z0-9_.+-]+)\s*$", body))
            need(len(records) == count, "complete_version_definition_count")
            for index, record in enumerate(records):
                name, number, aux = record[4], int(record[2]), int(record[3])
                need(name not in definitions and number not in {v["index"] for v in definitions.values()}
                     and number > 0 and aux > 0 and record[1] in ("none", "BASE", "WEAK"),
                     "unique_valid_version_definition")
                tail = body[record.end():records[index + 1].start() if index + 1 < len(records) else len(body)]
                parents = re.findall(r"(?m)^\s*(?:0x)?[0-9a-f]+:\s+Parent \d+: ([A-Za-z0-9_.+-]+)\s*$", tail)
                need(len(parents) == aux - 1 and len(parents) == len(set(parents)),
                     "complete_version_definition_parents")
                definitions[name] = {"index": number, "parents": parents}
        else:
            records = list(re.finditer(
                r"(?m)^\s*(?:0x)?[0-9a-f]+:\s+Version: 1\s+File: ([A-Za-z0-9_.+-]+)\s+Cnt: (\d+)\s*$", body))
            need(len(records) == count, "complete_version_need_file_count")
            for index, record in enumerate(records):
                name = record[1]
                need(name in needed and name not in needs and int(record[2]) > 0,
                     "version_need_must_name_one_direct_dependency")
                tail = body[record.end():records[index + 1].start() if index + 1 < len(records) else len(body)]
                versions = re.findall(
                    r"(?m)^\s*(?:0x)?[0-9a-f]+:\s+Name: ([A-Za-z0-9_.+-]+)\s+Flags: (none|WEAK)\s+Version: (\d+)\s*$", tail)
                need(len(versions) == int(record[2]), "complete_version_need_name_count")
                needs[name] = unique((x[0] for x in versions), "duplicate_version_requirement")
                for version, _flags, number in versions:
                    number = int(number)
                    need(number >= 2 and number not in needs_index, "unique_version_requirement_index")
                    needs_index[number] = (name, version)
    for value in definitions.values():
        need(set(value["parents"]) <= set(definitions), "defined_version_parent_missing")
    need(not set(needs_index).intersection(v["index"] for v in definitions.values()),
         "version_requirement_definition_index_overlap")
    need(bool(sections) or "No version information found in this file." in raw,
         "version_information_output_missing")
    return {
        "abi": "x86_64-unknown-linux-gnu", "type": {2: "EXEC", 3: "DYN"}[elf_type],
        "interpreter": interpreter[0] if interpreter else None,
        "soname": sonames[0] if sonames else None, "needed": needed,
        "version_needs": {name: sorted(values) for name, values in needs.items()},
        "version_definitions": sorted(definitions),
        "readelf_stdout_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "actual_header_sha256": hashlib.sha256(header).hexdigest(),
    }

def verify_compatibility(artifacts, providers, *, expected_artifact_pins,
                         interpreter_path, interpreter_resolved_path):
    """Compare exact producer observations with actual pinned X230 providers.

    Rows contain pin and parsed elf members. The normal107 admission supplies
    expected_artifact_pins; the receiver supplies one unambiguous freshly pinned
    path per SONAME and the actual interpreter symlink resolution. Library
    dependencies are recursively closed; no largest-version shortcut is used.
    """
    def checked(row):
        need(isinstance(row, dict) and row.get("pin") == row.get("pin_before")
             == row.get("pin_after") and isinstance(row.get("pin"), dict),
             "readelf_input_pin_changed_or_not_observed")
        parsed = parse_elf_observation(row.get("header_hex"), row.get("raw_readelf"))
        need("elf" not in row or row["elf"] == parsed, "parsed_elf_does_not_match_original_readelf")
        command = row.get("command", {})
        need(command.get("exit_code") == 0 and type(command.get("exit_code")) is int
             and command.get("timed_out") is False and command.get("stderr_bytes") == 0
             and command.get("stdout_bytes") == len(row["raw_readelf"].encode())
             and command.get("stdout_sha256") == parsed["readelf_stdout_sha256"],
             "actual_completed_readelf_output_required")
        return {"pin": row["pin"], "elf": parsed}
    artifacts = {name: checked(row) for name, row in artifacts.items()}
    providers = {name: checked(row) for name, row in providers.items()}
    names = {"heptabao-server", "heptabao-seed"}
    need(set(artifacts) == set(expected_artifact_pins) == names, "both_exact_normal_artifacts_required")
    need(isinstance(interpreter_path, str) and interpreter_path.startswith("/")
         and isinstance(interpreter_resolved_path, str) and interpreter_resolved_path.startswith("/"),
         "actual_receiver_interpreter_paths_required")
    for name, row in artifacts.items():
        expected = expected_artifact_pins[name]
        need(row["pin"].get("sha256") == expected.get("sha256")
             and row["pin"].get("bytes") == expected.get("bytes")
             and re.fullmatch(r"[0-9a-f]{64}", row["pin"].get("sha256", ""))
             and type(row["pin"].get("bytes")) is int and row["pin"]["bytes"] > 0,
             "exact_normal_artifact_hash_and_size")
        elf = row["elf"]
        need(elf.get("abi") == "x86_64-unknown-linux-gnu" and elf.get("type") in ("EXEC", "DYN")
             and elf.get("interpreter") == interpreter_path,
             "normal_artifact_receiver_interpreter_mismatch")
    loader = [name for name, row in providers.items()
              if row["pin"].get("path") == interpreter_resolved_path]
    need(len(loader) == 1, "one_actual_pinned_receiver_loader")
    for soname, row in providers.items():
        pin, elf = row["pin"], row["elf"]
        need(elf.get("soname") == soname and elf.get("abi") == "x86_64-unknown-linux-gnu"
             and elf.get("type") == "DYN" and elf.get("interpreter") in (None, interpreter_path),
             "provider_soname_or_abi_or_interpreter_mismatch")
        need(isinstance(pin.get("path"), str) and pin["path"].startswith("/")
             and re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", ""))
             and type(pin.get("bytes")) is int and pin["bytes"] > 0, "actual_provider_file_pin_required")
    needed = {loader[0]}
    for row in artifacts.values():
        needed.update(row["elf"]["needed"])
    visited = set()
    while needed - visited:
        name = sorted(needed - visited)[0]
        need(name in providers, "required_provider_missing_" + name)
        visited.add(name)
        needed.update(providers[name]["elf"]["needed"])
    need(set(providers) == needed, "exact_receiver_provider_closure_required")
    requirements = []
    for origin, row in [*artifacts.items(), *providers.items()]:
        elf = row["elf"]
        need(set(elf["version_needs"]) <= set(elf["needed"]), "version_requirements_bound_to_direct_dependencies")
        for soname, versions in elf["version_needs"].items():
            need(soname in providers and set(versions) <= set(providers[soname]["elf"]["version_definitions"]),
                 "provider_version_set_incomplete_" + soname)
            requirements.append({"origin": origin, "provider": soname, "required_versions": sorted(versions)})
    return {
        "schema": "heptabao.x230-static-elf-provider-compatibility.v1",
        "static_elf_and_version_requirements_match": True,
        "artifacts": {name: row["pin"] for name, row in artifacts.items()},
        "providers": {name: row["pin"] for name, row in providers.items()},
        "interpreter_path": interpreter_path, "interpreter_resolved_path": interpreter_resolved_path,
        "requirements": requirements, "target_binary_executions": 0,
        "actual_x230_runtime_qualified": False, "normal107_qualification_granted_by_this_check": False,
        "production_changed": False, "full_replacement_qualified": False,
        "fresh_receiver_pin_recheck_required_before_runtime": True,
        "scope": "ELF ABI, interpreter and dependency version sets; real workload execution remains mandatory.",
    }
