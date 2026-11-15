#!/usr/bin/env python3
"""Synthetic rejection fixtures only; these are not product/runtime evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'x230_native_abi_admission.py'
if not HELPER.is_file():
    HELPER = HERE.parent / 'x230_native_abi_admission.py'
SPEC = importlib.util.spec_from_file_location('x230_native_abi_admission', HELPER)
abi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(abi)

LOADER = "/lib64/ld-linux-x86-64.so.2"
RESOLVED = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"

def fixture(*, soname=None, needed=(), requires=None, defines=(), interpreter=None, label="fixture"):
    requires = requires or {}
    ph = ["LOAD"] + (["INTERP"] if interpreter else []) + ["DYNAMIC"]
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 3, 62, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, len(ph))
    entries = [("NEEDED", "Shared library: [" + name + "]") for name in needed]
    if soname:
        entries += [("SONAME", "Library soname: [" + soname + "]")]
    if defines:
        entries += [("VERDEF", "0x200"), ("VERDEFNUM", str(len(defines)))]
    if requires:
        entries += [("VERNEED", "0x300"), ("VERNEEDNUM", str(len(requires)))]
    entries += [("NULL", "0x0")]
    lines = ["ELF Header:", "  Class: ELF64", "  Data: 2's complement, little endian",
             "  Type: DYN (Shared object file)", "  Machine: Advanced Micro Devices X86-64",
             "  Number of program headers: " + str(len(ph)), "Program Headers:",
             "  Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align"]
    for kind in ph:
        lines.append("  " + kind + " 0x0000 0x0000 0x0000 0x0000 0x0000 R 0x1000")
        if kind == "INTERP":
            lines.append("      [Requesting program interpreter: " + interpreter + "]")
    lines += [" Section to Segment mapping:", "  Segment Sections...",
              "Dynamic section at offset 0x80 contains " + str(len(entries)) + " entries:"]
    for tag, value in entries:
        lines.append(" 0x0000000000000001 (" + tag + ") " + value)
    if defines:
        lines += ["Version definition section '.gnu.version_d' contains " + str(len(defines))
                  + (" entry:" if len(defines) == 1 else " entries:")]
        for number, name in enumerate(defines, 2):
            lines.append(f"  0x0010: Rev: 1 Flags: none Index: {number} Cnt: 1 Name: {name}")
    if requires:
        lines += ["Version needs section '.gnu.version_r' contains " + str(len(requires))
                  + (" entry:" if len(requires) == 1 else " entries:")]
        number = 100
        for name, versions in requires.items():
            lines.append(f"  000000: Version: 1 File: {name} Cnt: {len(versions)}")
            for version in versions:
                lines.append(f"  0x0010: Name: {version} Flags: none Version: {number}")
                number += 1
    if not requires and not defines:
        lines.append("No version information found in this file.")
    raw = "\n".join(lines) + "\n"
    pin = {"path": RESOLVED if soname == "ld-linux-x86-64.so.2" else "/owned/" + label,
           "sha256": hashlib.sha256(label.encode()).hexdigest(), "bytes": 1234}
    return {"pin": pin, "pin_before": copy.deepcopy(pin), "pin_after": copy.deepcopy(pin),
            "header_hex": bytes(header).hex(), "raw_readelf": raw,
            "command": {"exit_code": 0, "timed_out": False, "stderr_bytes": 0,
                        "stdout_bytes": len(raw.encode()), "stdout_sha256": hashlib.sha256(raw.encode()).hexdigest()}}

def refresh(row):
    raw = row["raw_readelf"]
    row["command"].update(stdout_bytes=len(raw.encode()), stdout_sha256=hashlib.sha256(raw.encode()).hexdigest())

def bundle():
    artifacts = {name: fixture(needed=["libc.so.6"], requires={"libc.so.6": ["GLIBC_2.34"]},
                               interpreter=LOADER, label=name)
                 for name in ("heptabao-server", "heptabao-seed")}
    providers = {
        "libc.so.6": fixture(soname="libc.so.6", needed=["ld-linux-x86-64.so.2"],
                            requires={"ld-linux-x86-64.so.2": ["GLIBC_PRIVATE"]},
                            defines=["GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_2.39"], label="libc.so.6"),
        "ld-linux-x86-64.so.2": fixture(soname="ld-linux-x86-64.so.2",
                                      defines=["GLIBC_PRIVATE"], label="ld-linux-x86-64.so.2"),
    }
    expected = {name: copy.deepcopy(row["pin"]) for name, row in artifacts.items()}
    return artifacts, providers, expected

class AbiGuards(unittest.TestCase):
    def setUp(self):
        self.a, self.p, self.expected = bundle()

    def verify(self):
        return abi.verify_compatibility(self.a, self.p, expected_artifact_pins=self.expected,
                                        interpreter_path=LOADER, interpreter_resolved_path=RESOLVED)

    def refuse(self, pattern):
        return self.assertRaisesRegex(abi.AbiRefused, pattern)

    def test_match_does_not_claim_runtime_or_normal107(self):
        result = self.verify()
        self.assertTrue(result["static_elf_and_version_requirements_match"])
        self.assertFalse(result["actual_x230_runtime_qualified"])
        self.assertFalse(result["normal107_qualification_granted_by_this_check"])
        self.assertEqual(result["target_binary_executions"], 0)

    def test_actual_x230_original_provider_readelf_bytes(self):
        roots = [HERE / 'actual-x230', HERE.parent / 'evidence' / 'x230-static-abi-20261106-r1']
        roots = [root for root in roots if (root / 'inventory.original.public.json').is_file()]
        self.assertEqual(len(roots), 1)
        root = roots[0]
        raw = (root / 'inventory.original.public.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '58b1f3838d3ab032f7b07f0c01874e9374791f305bc026e29e118beaa0fc149a')
        original = json.loads(raw)
        self.assertEqual(set(original['providers']),
                         {'ld-linux-x86-64.so.2', 'libc.so.6', 'libgcc_s.so.1', 'libm.so.6'})
        for name, row in original['providers'].items():
            with self.subTest(actual_provider=name):
                raw = (root / row['raw_readelf_file']).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row['raw_readelf_sha256'])
                parsed = abi.parse_elf_observation(row['header_hex'], raw.decode())
                self.assertEqual(parsed['soname'], name)
                self.assertEqual(parsed['abi'], 'x86_64-unknown-linux-gnu')
        self.assertFalse(original['candidate_abi_qualified'])
        self.assertEqual(original['product_binary_executions'], 0)

    def test_required_newer_glibc_is_refused(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].replace("GLIBC_2.34", "GLIBC_2.40")
        refresh(row)
        with self.refuse("provider_version_set_incomplete"): self.verify()

    def test_larger_maximum_version_does_not_replace_missing_member(self):
        row = self.p["libc.so.6"]
        row["raw_readelf"] = row["raw_readelf"].replace("GLIBC_2.34", "GLIBC_2.42")
        refresh(row)
        with self.refuse("provider_version_set_incomplete"): self.verify()

    def test_missing_recursive_loader_version_is_refused(self):
        row = self.p["ld-linux-x86-64.so.2"]
        row["raw_readelf"] = row["raw_readelf"].replace("GLIBC_PRIVATE", "GLIBC_2.39")
        refresh(row)
        with self.refuse("provider_version_set_incomplete"): self.verify()

    def test_seed_is_mandatory(self):
        del self.a["heptabao-seed"]
        with self.refuse("both_exact"): self.verify()

    def test_artifact_hash_must_match_original_normal107(self):
        self.expected["heptabao-seed"]["sha256"] = "a" * 64
        with self.refuse("exact_normal_artifact"): self.verify()

    def test_wrong_receiver_interpreter_is_refused(self):
        row = self.a["heptabao-seed"]
        row["raw_readelf"] = row["raw_readelf"].replace(LOADER, "/other/ld-linux-x86-64.so.2")
        refresh(row)
        with self.refuse("interpreter_mismatch"): self.verify()

    def test_wrong_actual_machine_is_refused(self):
        row = self.a["heptabao-server"]; header = bytearray.fromhex(row["header_hex"])
        struct.pack_into("<H", header, 18, 183); row["header_hex"] = header.hex()
        with self.refuse("actual_elf64"): self.verify()

    def test_readelf_header_cannot_override_actual_elf_class(self):
        row = self.a["heptabao-server"]; header = bytearray.fromhex(row["header_hex"])
        header[4] = 1; row["header_hex"] = header.hex()
        with self.refuse("actual_elf64"): self.verify()

    def test_missing_version_need_section_is_refused(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].split("Version needs section")[0]
        refresh(row)
        with self.refuse("dynamic_version_contract_missing_or_truncated"): self.verify()

    def test_missing_version_definition_section_is_refused(self):
        row = self.p["ld-linux-x86-64.so.2"]
        row["raw_readelf"] = row["raw_readelf"].split("Version definition section")[0]
        refresh(row)
        with self.refuse("dynamic_version_contract_missing_or_truncated"): self.verify()

    def test_truncated_requirement_names_are_refused(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].replace("Cnt: 1", "Cnt: 2")
        refresh(row)
        with self.refuse("complete_version_need_name_count"): self.verify()

    def test_extra_unqualified_provider_is_refused(self):
        self.p["libextra.so.1"] = fixture(soname="libextra.so.1", label="extra")
        with self.refuse("exact_receiver_provider_closure"): self.verify()

    def test_missing_direct_dependency_is_refused(self):
        del self.p["libc.so.6"]
        with self.refuse("required_provider_missing"): self.verify()

    def test_same_basename_wrong_soname_is_refused(self):
        row = self.p["libc.so.6"]
        row["raw_readelf"] = row["raw_readelf"].replace("Library soname: [libc.so.6]", "Library soname: [libfake.so.6]")
        refresh(row)
        with self.refuse("provider_soname"): self.verify()

    def test_missing_non_glibc_family_is_refused(self):
        row = fixture(needed=["libgcc_s.so.1"], requires={"libgcc_s.so.1": ["GCC_14.0.0"]},
                      interpreter=LOADER, label="heptabao-server")
        self.a["heptabao-server"] = row
        self.p["libgcc_s.so.1"] = fixture(soname="libgcc_s.so.1", defines=["GCC_3.0"], label="libgcc")
        with self.refuse("provider_version_set_incomplete"): self.verify()

    def test_version_needs_cannot_refer_to_undeclared_library(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].replace("File: libc.so.6", "File: libgcc_s.so.1")
        refresh(row)
        with self.refuse("version_need_must_name"): self.verify()

    def test_runpath_is_not_silently_ignored(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].replace("(VERNEED) 0x300", "(RUNPATH) Library runpath: [$ORIGIN]")
        refresh(row)
        with self.refuse("unmodeled_loader_search"): self.verify()

    def test_duplicate_elf_object_is_refused(self):
        row = self.a["heptabao-server"]; row["raw_readelf"] += row["raw_readelf"]; refresh(row)
        with self.refuse("single_complete"): self.verify()

    def test_truncated_dynamic_table_is_refused(self):
        row = self.a["heptabao-server"]
        row["raw_readelf"] = row["raw_readelf"].replace(" 0x0000000000000001 (NULL) 0x0\n", "")
        refresh(row)
        with self.refuse("complete_dynamic_entry_count"): self.verify()

    def test_changed_input_inode_is_refused(self):
        self.p["libc.so.6"]["pin_after"]["identity"] = [1, 2, 3]
        with self.refuse("input_pin_changed"): self.verify()

    def test_failed_or_timed_out_readelf_is_refused(self):
        for patch in ({"exit_code": 1}, {"exit_code": True}, {"timed_out": True}, {"stderr_bytes": 1}):
            with self.subTest(patch=patch):
                a, p, expected = bundle()
                a["heptabao-server"]["command"].update(patch)
                with self.refuse("actual_completed"):
                    abi.verify_compatibility(a, p, expected_artifact_pins=expected,
                                             interpreter_path=LOADER, interpreter_resolved_path=RESOLVED)

    def test_output_hash_mismatch_is_refused(self):
        self.a["heptabao-server"]["command"]["stdout_sha256"] = "0" * 64
        with self.refuse("actual_completed"): self.verify()

    def test_edited_parsed_summary_cannot_hide_original_requirements(self):
        row = self.a["heptabao-server"]
        row["elf"] = abi.parse_elf_observation(row["header_hex"], row["raw_readelf"])
        row["elf"]["version_needs"] = {}
        with self.refuse("parsed_elf_does_not_match"): self.verify()

if __name__ == "__main__":
    unittest.main(verbosity=2)
