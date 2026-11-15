#!/usr/bin/env python3
"""Supplemental synthetic input for the fixed r7 phone acceptance run.

The frozen e0f driver remains unchanged. Its original empty-text guard refused
Android's visible hint before reading the master. This helper uses ordinary
keyboard select-all/delete, re-observes the unique focused password EditText,
and only then reads the private synthetic master. The hint comparison is a
standard TextView/source inference, not an observed isShowingHintText flag.
It does not import, approve a credential operation, or pass an acceptance case.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import types

DRIVER_SHA256 = "e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
PROFILE_PUBLIC_SHA256 = "8a2c3e83c878ea5a6c6d646f94559d0de5154fd9b8210604bcdc879349a7165d"
BUILD_SHA256 = "e12bd68de3c606e03ce22a7a688ebb90c7b6ec4a951d15e5be233339e698042b"
PROVIDER_SHA256 = "b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
HINT = "Vault password"


class Failed(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failed(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_driver(path):
    require(path.is_absolute() and str(path) == str(path.resolve(strict=True)), "unsafe_driver_path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) & 0o022 == 0
                and 0 < before.st_size <= 1024 * 1024, "unsafe_driver_file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(raw) == before.st_size and sha(raw) == DRIVER_SHA256, "driver_source_changed")
    finally:
        os.close(fd)
    live = types.ModuleType("frozen_passkey_core_driver")
    live.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), live.__dict__)
    return live


def input_master(live, device, master_path, wrong=False):
    provider = live.PROVIDER
    allowed = {(provider, provider + ".HomeActivity"), (provider, provider + ".OperationActivity")}
    require(device.package_hash(provider) == PROVIDER_SHA256, "input_provider_artifact_changed")

    def observe(expected=None, focused=False, blank=True):
        foreground, nodes = device.ui()
        require(foreground in allowed and (expected is None or foreground == expected), "password_activity_changed")
        fields = [n for n in nodes if n.get("package") == provider
                  and n.get("password") == "true" and n.get("class") == "android.widget.EditText"]
        require(len(fields) == 1, "password_field_not_unique")
        node = fields[0]
        require("text" in node.attrib and node.get("enabled") == "true" and node.get("hint") == HINT,
                "password_field_metadata_changed")
        require(not focused or node.get("focused") == "true", "password_focus_changed")
        if blank:
            # This only admits the clearing operation. A fixed hint alone is
            # never treated as proof that a prior clearing operation occurred.
            require(node.get("text", "") in ("", HINT), "password_field_not_empty")
        return foreground, node

    foreground, field = observe()
    device.tap_node(field, foreground)
    observe(foreground, focused=True)
    require(device.foreground() == foreground, "password_target_changed_before_clear")
    require(device.shell("input", "keyboard", "-d", "0", "keycombination",
                         "KEYCODE_CTRL_LEFT", "KEYCODE_A") == "", "password_select_all_unconfirmed")
    observe(foreground, focused=True)
    require(device.foreground() == foreground, "password_target_changed_before_clear")
    require(device.shell("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_DEL") == "", "password_delete_unconfirmed")
    observe(foreground, focused=True)
    require(device.package_hash(provider) == PROVIDER_SHA256, "input_provider_artifact_changed")
    require(device.foreground() == foreground, "password_target_changed_before_input")

    # No master read occurs until all clearing and fresh target checks passed.
    master_bytes = live.private_file(master_path, 64)
    try:
        original = master_bytes.decode("ascii", "strict")
        require(re.fullmatch(r"[A-Za-z0-9_-]{32}", original) is not None, "unexpected_synthetic_master")
        master = secrets.token_urlsafe(24) if wrong else original
    finally:
        del master_bytes
    del original
    try:
        require(device.foreground() == foreground, "password_target_changed_before_input")
        # The explicitly authorized synthetic-only adb/input argv exception
        # remains. This value never enters a public receipt or Runtime argv.
        require(device.shell("input", "-d", "0", "text", master) == "", "password_input_unconfirmed")
        _, final_field = observe(foreground, focused=True, blank=False)
        require(len(final_field.get("text", "")) == 32 and final_field.get("text") != HINT,
                "password_input_length_unconfirmed")
    finally:
        del master
    return {"ok": True, "phase": "input-master", "synthetic_wrong_password": wrong,
            "clearing_method": "ordinary_keyboard_ctrl_a_then_delete",
            "empty_check": "post_clear_empty_or_exact_standard_password_hint",
            "showing_hint_flag_observed": False, "credential_entry": "synthetic_only_adb_input_text_argv",
            "input_character_count_verified": 32, "case_passed_by_phase": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--expected-build-sha256")
    parser.add_argument("--master-file", type=Path)
    parser.add_argument("--phase", choices=("input-master",), default="input-master")
    parser.add_argument("--wrong", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(); os.umask(0o077)
    live = load_driver(args.driver.absolute())
    if args.self_test:
        self_test(live); return
    require(all(value is not None for value in (args.adb, args.root, args.artifacts, args.master_file)), "missing_input_argument")
    root, artifacts = args.root.absolute(), args.artifacts.absolute()
    for directory in (root.parent, root, artifacts, root.parent / "private"):
        live.private_directory(directory)
    require(root.parent == artifacts.parent and args.expected_build_sha256 == BUILD_SHA256, "input_run_binding_changed")
    master_path = args.master_file.absolute()
    require(master_path.parent == root.parent / "private" and master_path.name == "master.private"
            and str(master_path) == str(master_path.resolve(strict=True)), "master_outside_private_root")
    build_raw = live.private_file(artifacts / "build.receipt.json", 1024 * 1024)
    require(sha(build_raw) == BUILD_SHA256
            and sha(live.private_file(root / "profile.public.json", 1024 * 1024)) == PROFILE_PUBLIC_SHA256,
            "input_run_binding_changed")
    build = json.loads(build_raw)
    require(build["artifacts"]["provider"]["sha256"] == PROVIDER_SHA256
            and build["artifacts"]["provider"]["package"] == live.PROVIDER, "input_provider_artifact_changed")
    fd = os.open(root / "driver.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe_driver_lock")
        live.fcntl.flock(fd, live.fcntl.LOCK_EX | live.fcntl.LOCK_NB)
        journal = json.loads(live.private_file(root / "journal.private.json", 8 * 1024 * 1024))
        live.validate_journal(journal, build, BUILD_SHA256)
        require(PROVIDER_SHA256 in journal["owned_packages"].get(live.PROVIDER, []), "unowned_provider")
        device = live.Device(args.adb)
        require({key: device.setting(key) for key in live.SETTING_KEYS} == journal["owned_settings"], "input_settings_changed")
        result = input_master(live, device, master_path, args.wrong)
        result.update({"core_driver_sha256": DRIVER_SHA256, "input_helper_sha256": sha(Path(__file__).read_bytes()),
                       "profile_public_sha256": PROFILE_PUBLIC_SHA256, "build_receipt_sha256": BUILD_SHA256})
        # Supplementary evidence is separate. Do not rewrite old driver phases.
        receipt = root / ("input-supplement-" + str(time.time_ns()) + ".public.json")
        require(not receipt.exists(), "input_receipt_exists")
        live.atomic(receipt, result)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(fd)


def self_test(live):
    """Exercise the actual input method against explicit UI/device doubles."""
    from unittest import mock
    from xml.etree.ElementTree import Element
    checks = []
    home = (live.PROVIDER, live.PROVIDER + ".HomeActivity")
    operation = (live.PROVIDER, live.PROVIDER + ".OperationActivity")

    class Device:
        def __init__(self, **changes):
            self.state = {"foreground": home, "text": HINT, "hint": HINT, "password": "true",
                          "class": "android.widget.EditText", "enabled": "true", "focused": "false",
                          "package": live.PROVIDER, "copies": 1, "hash": PROVIDER_SHA256}
            self.state.update(changes); self.events = []; self.ui_count = 0; self.hook = None
        def package_hash(self, _):
            self.events.append("apk"); return self.state["hash"]
        def foreground(self):
            return self.state["foreground"]
        def ui(self):
            self.ui_count += 1
            if self.hook: self.hook(self)
            fields = [Element("node", {k: self.state[k] for k in
                      ("text", "hint", "password", "class", "enabled", "focused", "package")})
                      for _ in range(self.state["copies"])]
            return self.foreground(), fields
        def tap_node(self, _, foreground):
            assert foreground == self.foreground(); self.events.append("tap"); self.state["focused"] = "true"
        def shell(self, *args):
            if "keycombination" in args:
                self.events.append("select_all")
                assert args == ("input", "keyboard", "-d", "0", "keycombination", "KEYCODE_CTRL_LEFT", "KEYCODE_A")
            elif "keyevent" in args:
                self.events.append("delete")
                assert args == ("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_DEL")
                self.state["text"] = HINT
            else:
                self.events.append("input")
                assert args[:4] == ("input", "-d", "0", "text") and len(args[4]) == 32
                self.state["text"] = "\u2022" * 32
            return ""

    def check(name, device, expected_error=None, wrong=False, expected_reads=0):
        reads = []
        def private_file(path, maximum):
            reads.append(True); device.events.append("master_read")
            assert device.events.index("delete") < len(device.events) - 1
            return b"A" * 32
        with mock.patch.object(live, "private_file", side_effect=private_file):
            try:
                result = input_master(live, device, Path("/synthetic/master.private"), wrong)
            except Failed as error:
                assert str(error) == expected_error, (name, str(error))
            else:
                assert expected_error is None and result["ok"] and result["case_passed_by_phase"] is False, name
                assert device.events.index("select_all") < device.events.index("delete") < device.events.index("master_read") < device.events.index("input")
            assert len(reads) == expected_reads, name
        checks.append(name)

    check("home_hint_cleared_before_master", Device(), expected_reads=1)
    check("operation_hint_cleared_before_master", Device(foreground=operation), expected_reads=1)
    check("empty_text_also_explicitly_cleared", Device(text=""), expected_reads=1)
    check("wrong_synthetic_password_same_real_input_path", Device(), wrong=True, expected_reads=1)
    for name, changes, code in (
        ("unknown_nonempty_denied", {"text": "unrecognized"}, "password_field_not_empty"),
        ("masked_existing_password_denied", {"text": "\u2022" * 32}, "password_field_not_empty"),
        ("unknown_hint_denied", {"hint": "Other"}, "password_field_metadata_changed"),
        ("missing_hint_denied", {"hint": ""}, "password_field_metadata_changed"),
        ("disabled_denied", {"enabled": "false"}, "password_field_metadata_changed"),
        ("duplicate_field_denied", {"copies": 2}, "password_field_not_unique"),
        ("nonpassword_denied", {"password": "false"}, "password_field_not_unique"),
        ("foreign_field_denied", {"package": "other"}, "password_field_not_unique"),
        ("wrong_activity_denied", {"foreground": (live.PROVIDER, "other")}, "password_activity_changed"),
        ("wrong_apk_denied", {"hash": "0" * 64}, "input_provider_artifact_changed")):
        check(name, Device(**changes), code)
    for name, at, changes, code in (
        ("focus_lost_after_tap", 2, {"focused": "false"}, "password_focus_changed"),
        ("activity_changed_after_select_all", 3, {"foreground": operation}, "password_activity_changed"),
        ("unknown_text_after_delete", 4, {"text": "unrecognized"}, "password_field_not_empty"),
        ("apk_changed_after_delete", 4, {"hash": "0" * 64}, "input_provider_artifact_changed")):
        device = Device()
        device.hook = lambda d, at=at, changes=changes: d.state.update(changes) if d.ui_count == at else None
        check(name, device, code)
    device = Device(); device.hook = lambda d: d.state.update(text="\u2022" * 33) if d.ui_count == 5 else None
    check("post_input_append_length_denied", device, "password_input_length_unconfirmed", expected_reads=1)
    device = Device(); original_ui = device.ui
    def missing_text():
        foreground, nodes = original_ui()
        for node in nodes: node.attrib.pop("text", None)
        return foreground, nodes
    device.ui = missing_text
    check("missing_text_attribute_denied", device, "password_field_metadata_changed")
    print(json.dumps({"scope": "host_only_actual_input_method_with_ui_stubs", "checks": checks,
                      "passed": len(checks), "core_driver_sha256": DRIVER_SHA256,
                      "input_helper_sha256": sha(Path(__file__).read_bytes()),
                      "adb_calls": 0, "network_calls": 0, "phone_qualified": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Failed as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True)); sys.exit(1)
    except Exception:
        # An ADB/FD/parser exception may contain paths or external stderr.
        # Preserve its occurrence without exposing arbitrary exception text.
        print(json.dumps({"ok": False, "error": "input_helper_operation_failed"}, sort_keys=True)); sys.exit(1)
