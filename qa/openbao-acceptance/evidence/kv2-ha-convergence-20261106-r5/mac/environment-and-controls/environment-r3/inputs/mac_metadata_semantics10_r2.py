import time
START = time.monotonic()
import ast
import copy
import email.parser
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import unittest
import zipfile

SOURCE_TEXT = '#!/usr/bin/env python3\n"""Create one pinned, isolated Mac capture Python environment; never capture data."""\nfrom __future__ import annotations\nimport time\nSTART = time.monotonic()\nWORK_END = START + 150.0\nimport email.parser\nimport hashlib\nimport importlib\nimport json\nimport os\nfrom pathlib import Path\nimport platform\nimport signal\nimport stat\nimport subprocess\nimport sys\nimport sysconfig\nimport zipfile\n\nROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")\nINPUT = ROOT / "control/formal-kv2-python-env-inputs-r3"\nOUT = ROOT / "control/formal-kv2-python-env-50-0-2-r3"\nTRANSFER_ROOT = ROOT / "control/formal-kv2-public-wheels-from-rog-r1"\nTRANSFER_ID = (16777244, 72739337, 501, 0o700)\nPLAN_FILE = INPUT / "fixed-wheel-plan.json"\nPLAN_PIN = (13911, "ce036ee3d7879389eb23c6811b4ab2c2e23bf2221bf5315aaf78d9df40af2b49")\nCUSTODY = None\nFIRED = False\nINTERRUPTED = False\nCREATED = False\nREPORT = {\n    "schema": "heptabao.mac-create-only-capture-python-environment.v1",\n    "status": "failed", "work_budget_seconds": 150, "runtime_budget_seconds": 180,\n    "cleanup_and_receipt_reserve_seconds": 30, "deadline_renewed": False,\n    "automatic_retry": False, "global_install": False,\n    "existing_environments_modified": False, "repository_requirements_modified": False,\n    "business_database_opened": False, "provider_or_j3160_called": False,\n    "service_modified": False, "product_executed": False,\n    "capture_controls_qualified": False, "formal_kv2_qualified": False,\n    "elapsed_observation_before_receipt_publication": True,\n    "durable_completion_authority": "separate_original_runtime_terminal_with_180_second_cap",\n    "steps": [],\n}\nPRIVATE = {"schema": REPORT["schema"], "steps": []}\n\nclass Refused(RuntimeError):\n    pass\n\nclass Interrupted(KeyboardInterrupt):\n    pass\n\ndef need(condition, label):\n    if not condition:\n        raise Refused(label)\n\ndef checkpoint(end=WORK_END):\n    if FIRED or INTERRUPTED or time.monotonic() >= min(end, WORK_END):\n        raise Interrupted()\n\ndef interrupted(signum, frame):\n    global FIRED, INTERRUPTED\n    if signum == signal.SIGALRM:\n        FIRED = True\n    else:\n        INTERRUPTED = True\n    owner = getattr(CUSTODY, "_ACTIVE", None) if CUSTODY is not None else None\n    if owner is not None:\n        owner._interrupt(signum, frame)\n        return\n    raise Interrupted()\n\ndef unique(pairs):\n    out = {}\n    for key, value in pairs:\n        need(key not in out, "duplicate_json_key")\n        out[key] = value\n    return out\n\ndef sha(raw):\n    return hashlib.sha256(raw).hexdigest()\n\ndef identity(st):\n    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,\n            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)\n\ndef read_pinned(path, expected, *, private=False):\n    checkpoint()\n    path = Path(path)\n    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_input")\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)\n    try:\n        before = os.fstat(fd)\n        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1\n             and before.st_size == expected[0], "regular_pinned_input")\n        if private:\n            need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,\n                 "private_input_custody")\n        blocks, count = [], 0\n        while True:\n            checkpoint()\n            block = os.read(fd, 65536)\n            if not block:\n                break\n            count += len(block)\n            need(count <= expected[0], "input_read_bound")\n            blocks.append(block)\n        raw = b"".join(blocks)\n        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())\n             and len(raw) == expected[0] and sha(raw) == expected[1], "input_pin_changed")\n        return raw\n    finally:\n        os.close(fd)\n\ndef sync_dir(path):\n    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    try:\n        os.fsync(fd)\n    finally:\n        os.close(fd)\n\ndef owned_directory(path, *, private):\n    path = Path(path)\n    st = path.lstat()\n    need(path.resolve(strict=True) == path and stat.S_ISDIR(st.st_mode)\n         and st.st_uid == os.geteuid()\n         and (stat.S_IMODE(st.st_mode) == 0o700 if private else not st.st_mode & 0o022),\n         "owned_canonical_directory")\n    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))\n\ndef new_directory(path):\n    owned_directory(path.parent, private=False)\n    need(not os.path.lexists(path), "create_only_directory")\n    path.mkdir(mode=0o700)\n    sync_dir(path.parent)\n    return owned_directory(path, private=True)\n\ndef write_new(path, raw):\n    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n    try:\n        with os.fdopen(fd, "wb", closefd=False) as stream:\n            stream.write(raw)\n            stream.flush()\n            os.fsync(fd)\n    finally:\n        os.close(fd)\n    sync_dir(path.parent)\n    return {"bytes": len(raw), "sha256": sha(raw)}\n\ndef json_bytes(value):\n    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\\n").encode()\n\ndef clean_env():\n    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",\n            "TMPDIR": str(OUT / "tmp"), "PIP_CONFIG_FILE": "/dev/null",\n            "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"}\n\ndef source_version(path):\n    st = Path(path).lstat()\n    return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"\n\ndef validate_offline_provenance(plan, before):\n    transfer = plan["transferred_public_wheels"]\n    need(transfer["schema"] == "heptabao.fixed-public-wheel-transfer-binding.v1"\n         and Path(transfer["root"]) == TRANSFER_ROOT\n         and tuple(transfer["root_identity"]) == TRANSFER_ID\n         and owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,\n         "fixed_transferred_wheel_directory")\n    receipt_pin, terminal_pin = transfer["download_result"], transfer["download_terminal"]\n    proof = {}\n    for label, item in (("result", receipt_pin), ("terminal", terminal_pin)):\n        path = INPUT / item["filename"]\n        need(path.parent == INPUT and path.name == item["filename"], "fixed_provenance_filename")\n        raw = read_pinned(path, (item["bytes"], item["sha256"]), private=True)\n        before[str(path)] = raw\n        proof[label] = json.loads(raw, object_pairs_hook=unique)\n    result, terminal = proof["result"], proof["terminal"]\n    need(result["schema"] == "heptabao.rog-fixed-public-mac-wheel-download.v1"\n         and result["status"] == "passed" and result["all_four_wheels_verified"] is True\n         and result["deadline_fired"] is False and result["interrupted"] is False\n         and result["source_metadata_already_bound"] is True\n         and result["work_seconds"] == 150 and result["runtime_seconds"] == 180\n         and result["per_wheel_seconds"] == 20 and result["original_count"] == 0,\n         "completed_fixed_public_download_receipt")\n    need(terminal["job_id"] == "1a1b17e4e51-fc05-7921"\n         and terminal["state"] == "succeeded" and terminal["exit_code"] == 0\n         and terminal["timed_out"] is False and terminal["cancelled"] is False\n         and terminal["output_complete"] is True and terminal["output_durable"] is True\n         and terminal["terminal_publication_confirmed"] is True,\n         "durable_fixed_public_download_terminal")\n    projects = [p["project"] for p in plan["packages"]]\n    need(projects == ["pip", "cryptography", "cffi", "pycparser"]\n         and set(transfer["files"]) == set(projects)\n         and [row["project"] for row in result["steps"]] == projects\n         and set(result["final_pins"]) == set(projects), "exact_four_transferred_wheels")\n    for package, step in zip(plan["packages"], result["steps"]):\n        wheel = package["wheel"]\n        actual = transfer["files"][package["project"]]\n        expected = {"bytes": wheel["bytes"], "sha256": wheel["sha256"],\n                    "mode": 0o600, "owner_uid": 1000, "links": 1}\n        need(result["final_pins"][package["project"]] == expected\n             and step["filename"] == wheel["filename"] and step["phase"] == "complete"\n             and step["verified"] is True and step["response_code"] == 200\n             and step["headers_received"] is True\n             and step["readback"] == expected\n             and step["received_bytes"] == wheel["bytes"]\n             and actual["filename"] == wheel["filename"]\n             and actual["bytes"] == wheel["bytes"] and actual["sha256"] == wheel["sha256"]\n             and actual["mode"] == 0o600 and actual["owner_uid"] == 501\n             and actual["links"] == 1 and type(actual["version"]) is str\n             and source_version(TRANSFER_ROOT / wheel["filename"]) == actual["version"],\n             "download_and_transfer_wheel_binding")\n    prior = plan["prior_failed_attempt"]\n    need(prior["job_id"] == "1a1b17696b2-fc05-78ea"\n         and Path(prior["root"]) == ROOT / "control/formal-kv2-python-env-50-0-2-r1",\n         "retained_prior_failure_binding")\n    prior_result = None\n    for label, item in prior["retained_files"].items():\n        path = Path(prior["root"]) / item["relative_path"]\n        need(path.resolve(strict=True).is_relative_to(Path(prior["root"])), "prior_failure_file_scope")\n        raw = read_pinned(path, (item["bytes"], item["sha256"]), private=True)\n        before[str(path)] = raw\n        if label == "result":\n            prior_result = json.loads(raw, object_pairs_hook=unique)\n    need(prior_result is not None and prior_result["status"] == "failed"\n         and prior_result["environment_ready"] is False\n         and prior_result["phase"] == "download_fixed_wheels"\n         and prior_result["steps"] == [], "prior_attempt_remains_failed")\n    REPORT["offline_input_binding"] = {\n        "download_job_id": terminal["job_id"], "download_result_sha256": receipt_pin["sha256"],\n        "download_terminal_sha256": terminal_pin["sha256"],\n        "receiver_root_identity": list(TRANSFER_ID), "wheels": len(projects),\n        "new_network_requests": False, "prior_failed_attempt_reclassified": False,\n    }\n    return transfer\n\ndef copy_fixed_wheel(wheel, actual):\n    checkpoint()\n    end = min(WORK_END, time.monotonic() + 20.0)\n    source = TRANSFER_ROOT / wheel["filename"]\n    target = OUT / "wheels" / wheel["filename"]\n    need(source.parent == TRANSFER_ROOT and target.parent == OUT / "wheels",\n         "fixed_wheel_file_scope")\n    signal.setitimer(signal.ITIMER_REAL, max(0.001, end - time.monotonic()))\n    try:\n        need(owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID\n             and source_version(source) == actual["version"], "transferred_wheel_identity_changed")\n        raw = read_pinned(source, (wheel["bytes"], wheel["sha256"]), private=True)\n        checkpoint(end)\n        write_new(target, raw)\n        need(read_pinned(target, (wheel["bytes"], wheel["sha256"]), private=True) == raw,\n             "copied_wheel_readback")\n        need(source_version(source) == actual["version"]\n             and owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,\n             "transferred_wheel_changed_during_copy")\n        checkpoint(end)\n        return raw\n    finally:\n        if not FIRED and not INTERRUPTED:\n            signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))\n\ndef wheel_metadata(package):\n    wheel = package["wheel"]\n    path = OUT / "wheels" / wheel["filename"]\n    with zipfile.ZipFile(path) as archive:\n        members = archive.infolist()\n        names = [item.filename for item in members]\n        need(len(members) <= 10000 and len(names) == len(set(names))\n             and sum(item.file_size for item in members) <= 128 * 1024**2, "wheel_member_bound")\n        for item in members:\n            parts = item.filename.rstrip("/").split("/")\n            need(item.filename and not item.filename.startswith("/")\n                 and not any(part in ("", ".", "..") for part in parts)\n                 and not "\\\\" in item.filename and not item.flag_bits & 1\n                 and stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK,\n                 "wheel_member_custody")\n        metadata = [item for item in members if item.filename.endswith(".dist-info/METADATA")]\n        need(len(metadata) == 1 and metadata[0].file_size <= 131072, "wheel_metadata_bound")\n        raw = archive.read(metadata[0])\n        bound = package["wheel_core_metadata"]\n        need(len(raw) == bound["bytes"] and sha(raw) == bound["sha256"],\n             "original_wheel_core_metadata_pin_mismatch")\n        message = email.parser.BytesParser().parsebytes(raw)\n        need(all(len(message.get_all(name, [])) == 1\n                 for name in ("Name", "Version", "Requires-Python")),\n             "single_core_metadata_identity_headers_required")\n        actual = {"name": message["Name"].lower().replace("_", "-"),\n                  "version": message["Version"], "requires_python": message["Requires-Python"],\n                  "requires_dist": message.get_all("Requires-Dist", [])}\n        need(actual == bound["fields"] and actual["name"] == package["project"]\n             and actual["version"] == package["version"], "exact_original_wheel_core_metadata")\n        return actual\n\ndef metadata_semantics(package, actual, requirement_type, specifier_type):\n    need(actual["name"] == package["project"] and actual["version"] == package["version"],\n         "core_metadata_name_or_version_mismatch")\n    need(specifier_type(actual["requires_python"]) == specifier_type(package["requires_python"]),\n         "core_metadata_python_constraint_mismatch")\n    left_raw, right_raw = actual["requires_dist"], package["requires_dist"]\n    need(type(left_raw) is list and type(right_raw) is list\n         and len(left_raw) == len(right_raw)\n         and all(type(value) is str for value in left_raw + right_raw),\n         "core_metadata_dependency_count_or_type_mismatch")\n    left = [requirement_type(value) for value in left_raw]\n    right = [requirement_type(value) for value in right_raw]\n    need(all(not value.url and not value.extras for value in left + right),\n         "core_metadata_dependency_url_or_extra_refused")\n    for values in (left, right):\n        need(all(not any(value == previous for previous in values[:index])\n                 for index, value in enumerate(values)), "duplicate_core_metadata_dependency")\n    need(all(sum(value == expected for expected in right) == 1 for value in left),\n         "core_metadata_dependency_constraint_or_marker_mismatch")\n\ndef verify_all_core_semantics(plan, observed):\n    pip_package = next(p for p in plan["packages"] if p["project"] == "pip")\n    wheel = pip_package["wheel"]\n    path = OUT / "wheels" / wheel["filename"]\n    read_pinned(path, (wheel["bytes"], wheel["sha256"]), private=True)\n    need(not any(name == "pip" or name.startswith("pip.") for name in sys.modules),\n         "unmodified_pinned_requirement_parser")\n    original_path = list(sys.path)\n    sys.path.insert(0, str(path))\n    try:\n        from pip._vendor import packaging\n        from pip._vendor.packaging.requirements import Requirement\n        from pip._vendor.packaging.specifiers import SpecifierSet\n        prefix = str(path) + "/pip/_vendor/packaging/"\n        need(all(str(sys.modules[name].__file__).startswith(prefix) for name in (\n            "pip._vendor.packaging.requirements", "pip._vendor.packaging.specifiers")),\n            "fixed_vendored_parser_origin")\n        need(set(observed) == {p["project"] for p in plan["packages"]}\n             and len(observed) == 4, "complete_four_core_metadata_observations")\n        for package in plan["packages"]:\n            metadata_semantics(package, observed[package["project"]], Requirement, SpecifierSet)\n        REPORT["core_metadata_semantics"] = {\n            "packages": 4, "complete_constraints_equal": True,\n            "checked_before_venv_and_install": True,\n            "current_python_satisfaction_used_as_equivalence": False,\n            "canonical_duplicates_refused": True, "direct_urls_and_project_extras_refused": True,\n            "parser_pip_wheel_sha256": wheel["sha256"],\n            "vendored_packaging_version": packaging.__version__,\n        }\n    finally:\n        sys.path[:] = original_path\n\ndef run_step(owner, name, arguments, budget):\n    checkpoint()\n    begin = time.monotonic()\n    end = min(WORK_END, begin + float(budget))\n    signal.setitimer(signal.ITIMER_REAL, max(0.001, end - time.monotonic()))\n    row = {"name": name, "budget_seconds": budget, "returncode": None, "completed": False}\n    REPORT["steps"].append(row)\n    private = {"name": name, "argv": arguments}\n    PRIVATE["steps"].append(private)\n    out_path, err_path = OUT / (name + ".stdout"), OUT / (name + ".stderr")\n    try:\n        with out_path.open("xb") as output, err_path.open("xb") as error:\n            child = subprocess.Popen(arguments, cwd=OUT, env=clean_env(), stdin=subprocess.DEVNULL,\n                                     stdout=output, stderr=error)\n            try:\n                row["returncode"] = child.wait(timeout=max(0.001, end - time.monotonic()))\n            finally:\n                if child.returncode is None:\n                    child.kill()\n                    child.wait(timeout=5)\n                row["original_wait_completed"] = child.custody["original_wait_completed"]\n                row["original_wait_count"] = child.custody["original_wait_count"]\n                row["no_live_members_before_reap"] = child.custody.get("no_live_members_before_reap")\n                row["custody_gaps"] = list(child.custody["gaps"])\n        checkpoint(end)\n        need(row["returncode"] == 0, "owned_step_failed")\n        need(row["original_wait_completed"] is True and row["original_wait_count"] == 1\n             and row["no_live_members_before_reap"] is True and not row["custody_gaps"],\n             "owned_step_custody")\n        row["completed"] = True\n    finally:\n        row["elapsed_seconds"] = time.monotonic() - begin\n        for key, path in (("stdout", out_path), ("stderr", err_path)):\n            if path.is_file():\n                need(path.stat().st_size <= 2 * 1024**2, "owned_step_output_bound")\n                raw = path.read_bytes()\n                private[key] = {"bytes": len(raw), "sha256": sha(raw)}\n                need(len(raw) <= 2 * 1024**2, "owned_step_output_bound")\n        if not FIRED and not INTERRUPTED:\n            signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))\n\nOFFLINE_INSTALL = r\'\'\'\nimport sys,os,json,hashlib,runpy,zipfile,email.parser\nfrom pathlib import Path\nplan=json.loads(Path(sys.argv[1]).read_text())\nroot=Path(plan["destination"]); env=root/"venv"\nassert Path(sys.prefix).resolve()==env and Path(sys.base_prefix).resolve()!=env\nassert os.environ.get("PIP_CONFIG_FILE")==os.devnull\nwheels=root/"wheels"; packages=plan["packages"]\npip_pkg=next(p for p in packages if p["project"]=="pip")\npip_wheel=wheels/pip_pkg["wheel"]["filename"]\nassert hashlib.sha256(pip_wheel.read_bytes()).hexdigest()==pip_pkg["wheel"]["sha256"]\nsys.path.insert(0,str(pip_wheel))\ndef audit(event,args):\n    if event in ("socket.connect","socket.getaddrinfo","subprocess.Popen","os.system","os.posix_spawn"):\n        raise RuntimeError("offline_installer_effect_refused")\nsys.addaudithook(audit)\nfrom pip._vendor.packaging.tags import sys_tags,parse_tag\nfrom pip._vendor.packaging.utils import parse_wheel_filename\nfrom pip._vendor.packaging.requirements import Requirement\nfrom pip._vendor.packaging.specifiers import SpecifierSet\nfrom pip._vendor.packaging.markers import default_environment\nfrom pip._internal.configuration import Configuration\nconfiguration=Configuration(isolated=True); configuration.load()\nassert not list(configuration.items())\nenvironment=default_environment(); environment["extra"]=""\nfor key,value in plan["runtime_marker_environment"].items():\n    assert environment[key]==value\ntags=set(sys_tags()); selected={p["project"]:p["version"] for p in packages}\nedges=[]; inactive=[]\nfor package in packages:\n    name,version,build,wheel_tags=parse_wheel_filename(package["wheel"]["filename"])\n    assert name==package["project"] and str(version)==package["version"] and tags.intersection(wheel_tags)\n    assert SpecifierSet(package["requires_python"]).contains(environment["python_full_version"])\n    for value in package["requires_dist"]:\n        requirement=Requirement(value)\n        assert not requirement.url and not requirement.extras\n        if requirement.marker and not requirement.marker.evaluate(environment):\n            inactive.append({"from":package["project"],"requirement":value})\n            continue\n        assert requirement.name in selected and requirement.specifier.contains(selected[requirement.name])\n        edges.append({"from":package["project"],"to":requirement.name,"requirement":value})\nassert edges==plan["selected_dependency_edges"] and inactive==plan["inactive_markers"]\nprint(json.dumps({"closure_validated":True,"actual_tag_count":len(tags),"selected":selected,\n                  "inactive_markers":inactive},sort_keys=True),flush=True)\nrequirements=root/"requirements.fixed.txt"\nsys.argv=["pip","--isolated","--disable-pip-version-check","--require-virtualenv",\n    "install","--no-index","--no-deps","--only-binary=:all:","--no-cache-dir","--no-compile",\n    "--require-hashes","--no-warn-script-location","-r",str(requirements)]\nrunpy.run_module("pip",run_name="__main__")\n\'\'\'\n\nVERIFY = r\'\'\'\nimport sys,os,json,importlib,importlib.metadata,sysconfig\nfrom pathlib import Path\nplan=json.loads(Path(sys.argv[1]).read_text())\nroot=Path(plan["destination"]); env=root/"venv"\nassert Path(sys.prefix).resolve()==env and Path(sys.base_prefix).resolve()!=env\nassert sys.version_info[:3]==(3,14,3) and sys.platform=="darwin"\nassert "include-system-site-packages = false" in (env/"pyvenv.cfg").read_text()\nassert all(Path(sysconfig.get_path(kind)).resolve().is_relative_to(env) for kind in ("purelib","platlib"))\ndef audit(event,args):\n    if event in ("socket.connect","socket.getaddrinfo","subprocess.Popen","os.system","os.posix_spawn"):\n        raise RuntimeError("environment_verify_effect_refused")\nsys.addaudithook(audit)\nwanted={p["project"]:p["version"] for p in plan["packages"]}\nactual={d.metadata["Name"].lower().replace("_","-"):d.version for d in importlib.metadata.distributions()}\nassert actual==wanted\nfor name in ("cryptography","cffi","pycparser","pip","_cffi_backend"):\n    module=importlib.import_module(name)\n    assert Path(module.__file__).resolve().is_relative_to(env)\nfrom cryptography.fernet import Fernet,InvalidToken\nfrom cryptography.hazmat.backends.openssl.backend import backend\ncipher=Fernet(Fernet.generate_key()); plain=b"owned-synthetic-capture-runtime-qualification"\ntoken=cipher.encrypt(plain); assert cipher.decrypt(token)==plain\nfor wrong_cipher,wrong_token in ((Fernet(Fernet.generate_key()),token),(cipher,token[:-3]+b"abc")):\n    try: wrong_cipher.decrypt(wrong_token)\n    except InvalidToken: pass\n    else: raise AssertionError("fernet_negative_guard")\nfrom pip._internal.configuration import Configuration\ncfg=Configuration(isolated=True);cfg.load();assert not list(cfg.items())\nfrom pip._internal.operations.check import check_package_set,create_package_set_from_installed\npackage_set,parsing_problems=create_package_set_from_installed()\nmissing,conflicting=check_package_set(package_set)\nassert not parsing_problems and not missing and not conflicting\nprint(json.dumps({"environment_ready":True,"versions":actual,"fernet_roundtrip":True,\n "wrong_key_rejected":True,"tampering_rejected":True,"dependency_check":True,\n "no_global_packages":True,"openssl_version":backend.openssl_version_text(),\n "business_database_opened":False,"capture_controls_qualified":False},sort_keys=True))\n\'\'\'\n\ndef main():\n    global CUSTODY, CREATED\n    os.umask(0o077)\n    need(sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3)\n         and platform.machine() == "arm64" and not sysconfig.get_config_var("Py_GIL_DISABLED"),\n         "fixed_mac_python_platform")\n    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)\n         and signal.getsignal(signal.SIGALRM) == signal.SIG_DFL, "foreign_alarm")\n    previous = {s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}\n    for s in previous:\n        signal.signal(s, interrupted)\n    signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))\n    owner = None\n    before = {}\n    try:\n        need(len(sys.argv) == 2 and len(sys.argv[1]) == 64\n             and all(c in "0123456789abcdef" for c in sys.argv[1]), "external_controller_pin_required")\n        controller = INPUT / "mac_fixed_capture_environment.py"\n        need(Path(__file__).resolve() == controller, "fixed_controller_path")\n        before["controller"] = read_pinned(controller, (controller.lstat().st_size, sys.argv[1]), private=True)\n        REPORT["controller"] = {"bytes": len(before["controller"]), "sha256": sha(before["controller"])}\n        REPORT["fixed_plan"] = {"bytes": PLAN_PIN[0], "sha256": PLAN_PIN[1]}\n        plan_raw = read_pinned(PLAN_FILE, PLAN_PIN, private=True)\n        plan = json.loads(plan_raw, object_pairs_hook=unique)\n        need(plan["schema"] == "heptabao.mac-create-only-capture-python-environment-plan.v1"\n             and plan["destination"] == str(OUT) and plan["input_parent"] == str(INPUT)\n             and plan["budgets"] == {"work_seconds":150,"runtime_seconds":180,\n                "cleanup_and_receipt_reserve_seconds":30,"per_copy_seconds":20,\n                "venv_seconds":15,"install_seconds":35,"verification_seconds":10},\n             "fixed_environment_plan")\n        python = plan["python"]\n        need(Path(sys.executable).resolve() == Path(python["executable"]), "fixed_python_path")\n        before["python"] = read_pinned(python["executable"], (python["binary_bytes"], python["binary_sha256"]))\n        qa = Path(plan["custody_source"])\n        for name, pin in plan["custody_pins"].items():\n            before[name] = read_pinned(qa / name, (pin["bytes"], pin["sha256"]))\n        for package in plan["packages"]:\n            pin = package["metadata"]\n            raw = read_pinned(pin["path"], (pin["bytes"], pin["sha256"]))\n            metadata = json.loads(raw, object_pairs_hook=unique)\n            info = metadata["info"]\n            need(info["name"].lower().replace("_","-") == package["project"]\n                 and info["version"] == package["version"] and not metadata.get("vulnerabilities")\n                 and (info.get("requires_dist") or []) == package["requires_dist"]\n                 and info["requires_python"] == package["requires_python"], "fixed_pypi_metadata")\n            wheel = package["wheel"]\n            matches = [x for x in metadata["urls"] if x["filename"] == wheel["filename"]]\n            need(len(matches) == 1 and matches[0]["url"] == wheel["url"]\n                 and matches[0]["size"] == wheel["bytes"] and matches[0]["digests"]["sha256"] == wheel["sha256"]\n                 and matches[0]["yanked"] is False and matches[0]["packagetype"] == "bdist_wheel",\n                 "fixed_wheel_metadata")\n            before[pin["path"]] = raw\n            core = package["wheel_core_metadata"]\n            before[core["path"]] = read_pinned(core["path"], (core["bytes"], core["sha256"]), private=True)\n        prior = plan["retained_metadata_failure"]\n        need(prior["job_id"] == "1a1b1a60246-fc05-7a15"\n             and Path(prior["path"]) == ROOT / "control/formal-kv2-python-env-50-0-2-r2/result.public.json",\n             "retained_metadata_failure_binding")\n        raw = read_pinned(prior["path"], (prior["bytes"], prior["sha256"]), private=True)\n        before[prior["path"]] = raw\n        failure = json.loads(raw, object_pairs_hook=unique)\n        need(failure["status"] == "failed" and failure["environment_ready"] is False\n             and failure["error_label"] == "wheel_and_pypi_metadata_mismatch"\n             and failure["steps"] == [], "prior_metadata_attempt_remains_failed")\n        transfer = validate_offline_provenance(plan, before)\n        need("owned_process" not in sys.modules and "kv2_dr_process_custody" not in sys.modules,\n             "unmodified_custody_import")\n        sys.path.insert(0, str(qa))\n        import owned_process\n        CUSTODY = importlib.import_module("kv2_dr_process_custody")\n        root_identity = new_directory(OUT)\n        CREATED = True\n        PRIVATE["directory_identity"] = root_identity\n        for name in ("tmp", "wheels"):\n            new_directory(OUT / name)\n        write_new(OUT / "fixed-wheel-plan.json", plan_raw)\n        need(os.statvfs(OUT).f_bavail * os.statvfs(OUT).f_frsize >= 128 * 1024**2,\n             "environment_disk_headroom")\n        REPORT["phase"] = "copy_verified_transferred_wheels"\n        observed_core = {}\n        for package in plan["packages"]:\n            wheel = package["wheel"]\n            raw = copy_fixed_wheel(wheel, transfer["files"][package["project"]])\n            before[str(TRANSFER_ROOT / wheel["filename"])] = raw\n            observed_core[package["project"]] = wheel_metadata(package)\n        REPORT["phase"] = "verify_complete_core_metadata_semantics"\n        verify_all_core_semantics(plan, observed_core)\n        REPORT["wheel_pins"] = {p["project"]:{"version":p["version"],"bytes":p["wheel"]["bytes"],\n                                           "sha256":p["wheel"]["sha256"]} for p in plan["packages"]}\n        lines = [p["project"] + " @ " + (OUT / "wheels" / p["wheel"]["filename"]).as_uri()\n                 + " --hash=sha256:" + p["wheel"]["sha256"] for p in plan["packages"]]\n        write_new(OUT / "requirements.fixed.txt", ("\\n".join(lines)+"\\n").encode())\n        write_new(OUT / "offline_install.py", OFFLINE_INSTALL.encode())\n        write_new(OUT / "verify_environment.py", VERIFY.encode())\n        with CUSTODY.activated() as owner:\n            REPORT["phase"] = "create_new_venv"\n            run_step(owner, "create-venv", [python["executable"], "-I", "-B", "-m", "venv",\n                    "--without-pip", "--copies", str(OUT / "venv")], 15)\n            venv_python = OUT / "venv/bin/python3"\n            need(venv_python.resolve(strict=True) == venv_python, "copied_venv_interpreter")\n            REPORT["phase"] = "offline_install"\n            run_step(owner, "offline-install", [str(venv_python), "-I", "-B",\n                    str(OUT / "offline_install.py"), str(OUT / "fixed-wheel-plan.json")], 35)\n            REPORT["phase"] = "verify_new_environment"\n            run_step(owner, "verify-environment", [str(venv_python), "-I", "-B",\n                    str(OUT / "verify_environment.py"), str(OUT / "fixed-wheel-plan.json")], 10)\n            owner.assert_retired()\n        PRIVATE["process_custody"] = owner.receipt()\n        need(PRIVATE["process_custody"]["passed_process_custody"] is True\n             and PRIVATE["process_custody"]["finished"] is True, "complete_process_custody")\n        checkpoint()\n        for key, raw in before.items():\n            if key == "controller":\n                path = controller\n            elif key == "python":\n                path = python["executable"]\n            elif key in plan["custody_pins"]:\n                path = qa / key\n            else:\n                path = key\n            need(read_pinned(path, (len(raw), sha(raw))) == raw, "original_input_changed")\n        for package in plan["packages"]:\n            wheel = package["wheel"]\n            read_pinned(OUT / "wheels" / wheel["filename"], (wheel["bytes"], wheel["sha256"]), private=True)\n        for package in plan["packages"]:\n            wheel = package["wheel"]\n            need(source_version(TRANSFER_ROOT / wheel["filename"])\n                 == transfer["files"][package["project"]]["version"],\n                 "transferred_wheel_changed_after_install")\n        need(owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,\n             "transferred_wheel_directory_changed")\n        REPORT["prior_failed_attempt_bound_file_contents_unchanged"] = True\n        need(owned_directory(OUT, private=True) == root_identity, "environment_root_changed")\n        checkpoint()\n        REPORT.update(status="passed",phase="complete",environment_ready=True,\n                      original_inputs_unchanged=True,all_owned_processes_retired=True,\n                      installed_packages={p["project"]:p["version"] for p in plan["packages"]})\n    except BaseException as error:\n        REPORT.update(status="failed",environment_ready=False,error_type=type(error).__name__,\n                      error_label=str(error) if isinstance(error,Refused) else "environment_preparation_failed")\n    finally:\n        if owner is not None:\n            try:\n                PRIVATE["process_custody"] = owner.finish()\n            except BaseException as error:\n                REPORT.update(status="failed",environment_ready=False,cleanup_error_type=type(error).__name__)\n        if FIRED or INTERRUPTED or time.monotonic() >= WORK_END:\n            REPORT.update(status="failed",environment_ready=False)\n        REPORT.update(deadline_fired=FIRED,interrupted=INTERRUPTED,\n                      elapsed_seconds_before_receipt=time.monotonic()-START)\n        signal.setitimer(signal.ITIMER_REAL,0)\n        for s,handler in previous.items():\n            signal.signal(s,handler)\n        if CREATED:\n            PRIVATE["public_result"] = REPORT\n            write_new(OUT / "receipt.private.json",json_bytes(PRIVATE))\n            write_new(OUT / "result.public.json",json_bytes(REPORT))\n        print(json.dumps(REPORT,sort_keys=True,allow_nan=False),flush=True)\n    return 0 if REPORT["status"] == "passed" else 1\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n\n'
SOURCE_PIN = (33884, '7446010e142d381c524eea804c2a6c03a3f7e075d4143a8b66817f2b4f300985')
PLAN_TEXT = '{\n  "budgets": {\n    "cleanup_and_receipt_reserve_seconds": 30,\n    "install_seconds": 35,\n    "per_copy_seconds": 20,\n    "runtime_seconds": 180,\n    "venv_seconds": 15,\n    "verification_seconds": 10,\n    "work_seconds": 150\n  },\n  "capture_controls": {\n    "expected_tests": 18,\n    "platform_validation_pending": true,\n    "runtime_seconds": 60,\n    "script": {\n      "bytes": 57280,\n      "sha256": "9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972"\n    },\n    "tests": {\n      "bytes": 23809,\n      "sha256": "0b93d597b9fd525470951cb7b49cdb6707c11fc38b5e42f0d06bcedc7e0395f6"\n    },\n    "work_seconds": 52\n  },\n  "custody_pins": {\n    "kv2_dr_process_custody.py": {\n      "bytes": 26131,\n      "sha256": "669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008"\n    },\n    "owned_process.py": {\n      "bytes": 28442,\n      "sha256": "0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"\n    }\n  },\n  "custody_source": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-dr25-a2577-r2/qa/openbao-acceptance",\n  "dependency_decision": {\n    "advisory_urls": [\n      "https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2",\n      "https://github.com/pyca/cryptography/security/advisories/GHSA-p423-j2cm-9vmq",\n      "https://mail.python.org/archives/list/security-announce@python.org/thread/WIEA34D4TABF2UNQJAOMXKCICSPBE2DJ/",\n      "https://mail.python.org/archives/list/security-announce@python.org/thread/L2BNQGGVQCEV7DROOORQ7WFKKFF2OOQX/"\n    ],\n    "documentation_urls": [\n      "https://cryptography.io/en/50.0.2/installation/",\n      "https://pip.pypa.io/en/stable/topics/configuration/"\n    ],\n    "existing_environments_unchanged": true,\n    "existing_qualification_unchanged": true,\n    "known_fernet_failure_claimed": false,\n    "latest_tracking": false,\n    "repo_requirement_cryptography_46_0_4_unchanged": true,\n    "selected_versions_frozen": true\n  },\n  "destination": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-50-0-2-r3",\n  "forbidden_effects": [\n    "global_install",\n    "existing_environment_changes",\n    "repository_dependency_changes",\n    "business_database_reads",\n    "provider_calls",\n    "J3160_calls",\n    "service_changes",\n    "product_tests",\n    "credential_capture",\n    "cutover",\n    "cleanup_of_existing_assets"\n  ],\n  "inactive_markers": [\n    {\n      "from": "cryptography",\n      "requirement": "typing-extensions>=4.13.2; python_full_version < \\"3.11\\""\n    },\n    {\n      "from": "cryptography",\n      "requirement": "bcrypt>=3.1.5; extra == \\"ssh\\""\n    }\n  ],\n  "input_parent": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-inputs-r3",\n  "metadata_runs": [\n    {\n      "exit_code": 0,\n      "id": "1a1b1585bda-fc05-77e5",\n      "scope": "public_metadata_only",\n      "state": "succeeded",\n      "work_seconds": 15.6004969\n    },\n    {\n      "exit_code": 0,\n      "id": "1a1b15eb59c-fc05-7813",\n      "scope": "public_metadata_only",\n      "state": "succeeded",\n      "work_seconds": 6.486295375041664\n    }\n  ],\n  "observed_at_date": "2026-11-06",\n  "packages": [\n    {\n      "extras": [],\n      "metadata": {\n        "bytes": 6671,\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r2/pip-26.3.pypi.original.json",\n        "sha256": "9cee103938ec9d9fb6201ecd0eb8a51b1893e01358f75c162d7c7cf6a9d8fa20"\n      },\n      "project": "pip",\n      "requires_dist": [],\n      "requires_python": ">=3.10",\n      "version": "26.3",\n      "wheel": {\n        "actual_interpreter_tag_compatible": true,\n        "bytes": 1950951,\n        "filename": "pip-26.3-py3-none-any.whl",\n        "requires_python": ">=3.10",\n        "sha256": "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13",\n        "url": "https://files.pythonhosted.org/packages/07/25/ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/pip-26.3-py3-none-any.whl",\n        "yanked": false\n      },\n      "wheel_core_metadata": {\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-wheel-core-metadata-originals-r1/pip.METADATA.original",\n        "bytes": 4632,\n        "sha256": "ad63a8564cd158c8de9e6a912e92776b4abc56cfa2d8286ef4c35bfb9cb9e439",\n        "fields": {\n          "name": "pip",\n          "version": "26.3",\n          "requires_python": ">=3.10",\n          "requires_dist": []\n        }\n      }\n    },\n    {\n      "extras": [],\n      "metadata": {\n        "bytes": 57201,\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r2/cryptography-50.0.2.pypi.original.json",\n        "sha256": "7423990cc0948676ef47a71ea62a476ece4c76245e6bebd1c3a71f03c4ffc0f4"\n      },\n      "project": "cryptography",\n      "requires_dist": [\n        "cffi>=2.0.0; platform_python_implementation != \\"PyPy\\"",\n        "typing-extensions>=4.13.2; python_full_version < \\"3.11\\"",\n        "bcrypt>=3.1.5; extra == \\"ssh\\""\n      ],\n      "requires_python": "!=3.9.0,!=3.9.1,>=3.9",\n      "version": "50.0.2",\n      "wheel": {\n        "actual_interpreter_tag_compatible": true,\n        "bytes": 3914904,\n        "filename": "cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl",\n        "requires_python": "!=3.9.0,!=3.9.1,>=3.9",\n        "sha256": "fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb",\n        "url": "https://files.pythonhosted.org/packages/e5/56/d194340cc4a57535e82e1bee9e89667ac4b7c13b5d3f59686deae3094dd5/cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl",\n        "yanked": false\n      },\n      "wheel_core_metadata": {\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-wheel-core-metadata-originals-r1/cryptography.METADATA.original",\n        "bytes": 4394,\n        "sha256": "047cfc71226409de4318b360aef15c63a2adf609731e3dcf7fe932f14ea042ee",\n        "fields": {\n          "name": "cryptography",\n          "version": "50.0.2",\n          "requires_python": ">=3.9, !=3.9.0, !=3.9.1",\n          "requires_dist": [\n            "cffi>=2.0.0 ; platform_python_implementation != \'PyPy\'",\n            "typing-extensions>=4.13.2 ; python_full_version < \'3.11\'",\n            "bcrypt>=3.1.5 ; extra == \'ssh\'"\n          ]\n        }\n      }\n    },\n    {\n      "extras": [],\n      "metadata": {\n        "bytes": 75565,\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r1/cffi-2.0.0.pypi.original.json",\n        "sha256": "176060f17977cb6a9df47b3ee7f97ee40d688832f30593649b465e8d064f4530"\n      },\n      "project": "cffi",\n      "requires_dist": [\n        "pycparser; implementation_name != \\"PyPy\\""\n      ],\n      "requires_python": ">=3.9",\n      "version": "2.0.0",\n      "wheel": {\n        "actual_interpreter_tag_compatible": true,\n        "bytes": 181487,\n        "filename": "cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl",\n        "requires_python": ">=3.9",\n        "sha256": "c654de545946e0db659b3400168c9ad31b5d29593291482c43e3564effbcee13",\n        "url": "https://files.pythonhosted.org/packages/59/dd/27e9fa567a23931c838c6b02d0764611c62290062a6d4e8ff7863daf9730/cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl",\n        "yanked": false\n      },\n      "wheel_core_metadata": {\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-wheel-core-metadata-originals-r1/cffi.METADATA.original",\n        "bytes": 2559,\n        "sha256": "b98ce7e3417af089bc12d5c73412d9b3b1683ccf8ec73c986c35ac8c9be1ba39",\n        "fields": {\n          "name": "cffi",\n          "version": "2.0.0",\n          "requires_python": ">=3.9",\n          "requires_dist": [\n            "pycparser; implementation_name != \\"PyPy\\""\n          ]\n        }\n      }\n    },\n    {\n      "extras": [],\n      "metadata": {\n        "bytes": 3154,\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-dependency-plan-r1/pycparser-2.23.pypi.original.json",\n        "sha256": "2f8b35ee20ccc932a73315a4fea04b3b88a17a66b23c5305af534a9a6d1f20a2"\n      },\n      "project": "pycparser",\n      "requires_dist": [],\n      "requires_python": ">=3.8",\n      "version": "2.23",\n      "wheel": {\n        "actual_interpreter_tag_compatible": true,\n        "bytes": 118140,\n        "filename": "pycparser-2.23-py3-none-any.whl",\n        "requires_python": ">=3.8",\n        "sha256": "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",\n        "url": "https://files.pythonhosted.org/packages/a0/e3/59cd50310fc9b59512193629e1984c1f95e5c8ae6e5d8c69532ccc65a7fe/pycparser-2.23-py3-none-any.whl",\n        "yanked": false\n      },\n      "wheel_core_metadata": {\n        "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-wheel-core-metadata-originals-r1/pycparser.METADATA.original",\n        "bytes": 993,\n        "sha256": "a2c9a11ccc5ade7e6c3f0bf959e529cb23e79bbe9ea215d8199c8a1a659b3c57",\n        "fields": {\n          "name": "pycparser",\n          "version": "2.23",\n          "requires_python": ">=3.8",\n          "requires_dist": []\n        }\n      }\n    }\n  ],\n  "prior_failed_attempt": {\n    "job_id": "1a1b17696b2-fc05-78ea",\n    "not_resumed_or_reclassified": true,\n    "retained_files": {\n      "partial_pip": {\n        "bytes": 65536,\n        "relative_path": "wheels/pip-26.3-py3-none-any.whl",\n        "sha256": "f9f506f3b803cd45000ff9d21f7d87869d61bb748328c78f14e3b87ead2dfc4f"\n      },\n      "result": {\n        "bytes": 1245,\n        "relative_path": "result.public.json",\n        "sha256": "1095a215d0f3dc8a79d3cccaecacd85c900f8aa389ca93e14d510cbe1c0a9bc4"\n      }\n    },\n    "root": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-50-0-2-r1",\n    "status": "failed"\n  },\n  "purpose": "isolated dependency environment for current whole-SQLite capture controls; no business capture",\n  "python": {\n    "binary_bytes": 34640,\n    "binary_sha256": "cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13",\n    "executable": "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14",\n    "gil_disabled": false,\n    "machine": "arm64",\n    "platform": "macosx-26.0-arm64",\n    "version": "3.14.3"\n  },\n  "runtime_marker_environment": {\n    "extra": "",\n    "implementation_name": "cpython",\n    "platform_machine": "arm64",\n    "platform_python_implementation": "CPython",\n    "python_full_version": "3.14.3",\n    "python_version": "3.14",\n    "sys_platform": "darwin"\n  },\n  "schema": "heptabao.mac-create-only-capture-python-environment-plan.v1",\n  "selected_dependency_edges": [\n    {\n      "from": "cryptography",\n      "requirement": "cffi>=2.0.0; platform_python_implementation != \\"PyPy\\"",\n      "to": "cffi"\n    },\n    {\n      "from": "cffi",\n      "requirement": "pycparser; implementation_name != \\"PyPy\\"",\n      "to": "pycparser"\n    }\n  ],\n  "transferred_public_wheels": {\n    "download_result": {\n      "bytes": 4005,\n      "filename": "rog-download.result.public.json",\n      "sha256": "77ac4489798f4186faa63d54901b9c9adc3f4a9535db85590a717ece2a4d52cf"\n    },\n    "download_terminal": {\n      "bytes": 731,\n      "filename": "rog-download.runtime-terminal.original.json",\n      "sha256": "3634d8688e9251c3b0a145a214ca6f32f3245f1ff7b78efcb5da0407fc1affed"\n    },\n    "files": {\n      "cffi": {\n        "bytes": 181487,\n        "filename": "cffi-2.0.0-cp314-cp314-macosx_11_0_arm64.whl",\n        "links": 1,\n        "mode": 384,\n        "owner_uid": 501,\n        "sha256": "c654de545946e0db659b3400168c9ad31b5d29593291482c43e3564effbcee13",\n        "version": "16777244:72739407:181487:1793980456167683373:1793980527732357594"\n      },\n      "cryptography": {\n        "bytes": 3914904,\n        "filename": "cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl",\n        "links": 1,\n        "mode": 384,\n        "owner_uid": 501,\n        "sha256": "fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb",\n        "version": "16777244:72739418:3914904:1793981433134989023:1793981469338796944"\n      },\n      "pip": {\n        "bytes": 1950951,\n        "filename": "pip-26.3-py3-none-any.whl",\n        "links": 1,\n        "mode": 384,\n        "owner_uid": 501,\n        "sha256": "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13",\n        "version": "16777244:72739421:1950951:1793981366034099222:1793981434036642587"\n      },\n      "pycparser": {\n        "bytes": 118140,\n        "filename": "pycparser-2.23-py3-none-any.whl",\n        "links": 1,\n        "mode": 384,\n        "owner_uid": 501,\n        "sha256": "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",\n        "version": "16777244:72739367:118140:1793980020216636518:1793980078790564466"\n      }\n    },\n    "root": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-public-wheels-from-rog-r1",\n    "root_identity": [\n      16777244,\n      72739337,\n      501,\n      448\n    ],\n    "schema": "heptabao.fixed-public-wheel-transfer-binding.v1"\n  },\n  "retained_metadata_failure": {\n    "job_id": "1a1b1a60246-fc05-7a15",\n    "path": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/formal-kv2-python-env-50-0-2-r2/result.public.json",\n    "bytes": 1728,\n    "sha256": "86ede481d9cb5ccf10e16d1b1e9ce14c0ff8c88c419778015ad08a38b82ce003",\n    "not_resumed_or_reclassified": true\n  }\n}\n'
PLAN_PIN = (13911, 'ce036ee3d7879389eb23c6811b4ab2c2e23bf2221bf5315aaf78d9df40af2b49')
ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
OUT = ROOT / "control/formal-kv2-wheel-core-metadata-guards-r1"
FIRED = False
CREATED = False
EFFECTS = []
OBSERVED = {}
PACKAGES = {}
SCOPE = {}
Requirement = None
SpecifierSet = None
EXPECTED = [
    "test_01_all_four_original_metadata_complete_semantics_and_crypto_text_difference",
    "test_02_python_constraint_changes_that_still_allow_current_python_are_refused",
    "test_03_dependency_minimum_change_is_refused",
    "test_04_missing_currently_inactive_dependency_is_refused",
    "test_05_new_currently_inactive_dependency_is_refused",
    "test_06_canonical_duplicates_on_both_sides_are_refused",
    "test_07_direct_url_on_both_sides_is_refused",
    "test_08_project_extra_on_both_sides_is_refused",
    "test_09_changed_dependency_marker_is_refused",
    "test_10_name_and_version_changes_are_refused",
]
REPORT = {"schema": "heptabao.pinned-wheel-core-metadata-semantic-guards.v1",
          "status": "failed", "expected_tests": 10, "work_seconds": 52, "runtime_seconds": 60,
          "business_source_opened": False, "network_called": False, "packages_installed": False,
          "capture_controls18_executed": False, "installer_executed": False,
          "subprocesses_started": False, "original_count": 0, "deadline_renewed": False,
          "original_failed_attempts_reclassified": False}


class Deadline(KeyboardInterrupt):
    pass


def check():
    if FIRED or time.monotonic() >= START + 52:
        raise Deadline()


def alarm(_signum, _frame):
    global FIRED
    FIRED = True
    raise Deadline()


def audit(event, _args):
    if event in ("socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.posix_spawn"):
        EFFECTS.append(event)
        raise RuntimeError("metadata_guard_effect_refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def read(path, pin):
    check()
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == pin[0]
        parts, size = [], 0
        while True:
            check()
            part = os.read(fd, 65536)
            if not part:
                break
            size += len(part)
            assert size <= pin[0]
            parts.append(part)
        raw = b"".join(parts)
        assert (len(raw), sha(raw)) == tuple(pin)
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
        return raw
    finally:
        os.close(fd)


def write(name, raw):
    path = OUT / name
    assert path.parent == OUT
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    assert path.read_bytes() == raw
    return {"bytes": len(raw), "sha256": sha(raw)}


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run_semantics(package, actual):
    return SCOPE["metadata_semantics"](package, actual, Requirement, SpecifierSet)


class MetadataGuards(unittest.TestCase):
    def pair(self):
        return copy.deepcopy(PACKAGES["cryptography"]), copy.deepcopy(OBSERVED["cryptography"])

    def refused(self, package, actual, label):
        with self.assertRaisesRegex(SCOPE["Refused"], "^" + label + "$"):
            run_semantics(package, actual)

    def test_01_all_four_original_metadata_complete_semantics_and_crypto_text_difference(self):
        self.assertEqual(sorted(PACKAGES), ["cffi", "cryptography", "pip", "pycparser"])
        for name in PACKAGES:
            with self.subTest(project=name):
                self.assertIsNone(run_semantics(PACKAGES[name], OBSERVED[name]))
        package, actual = self.pair()
        self.assertNotEqual(package["requires_python"], actual["requires_python"])
        self.assertNotEqual(package["requires_dist"], actual["requires_dist"])

    def test_02_python_constraint_changes_that_still_allow_current_python_are_refused(self):
        for candidate in (">=3.9", ">=3.9, !=3.8.0, !=3.9.1"):
            with self.subTest(candidate=candidate):
                package, actual = self.pair()
                actual["requires_python"] = candidate
                self.assertTrue(SpecifierSet(package["requires_python"]).contains("3.14.3"))
                self.assertTrue(SpecifierSet(candidate).contains("3.14.3"))
                self.refused(package, actual, "core_metadata_python_constraint_mismatch")

    def test_03_dependency_minimum_change_is_refused(self):
        package, actual = self.pair()
        actual["requires_dist"] = [value.replace("cffi>=2.0.0", "cffi>=1.0.0")
                                   for value in actual["requires_dist"]]
        self.refused(package, actual, "core_metadata_dependency_constraint_or_marker_mismatch")

    def test_04_missing_currently_inactive_dependency_is_refused(self):
        package, actual = self.pair()
        removed = [value for value in actual["requires_dist"] if Requirement(value).name == "bcrypt"]
        self.assertEqual(len(removed), 1)
        self.assertFalse(Requirement(removed[0]).marker.evaluate({"extra": ""}))
        actual["requires_dist"] = [value for value in actual["requires_dist"] if value not in removed]
        self.refused(package, actual, "core_metadata_dependency_count_or_type_mismatch")

    def test_05_new_currently_inactive_dependency_is_refused(self):
        package, actual = self.pair()
        value = "unrequested>=1; python_version < '2'"
        self.assertFalse(Requirement(value).marker.evaluate())
        actual["requires_dist"].append(value)
        self.refused(package, actual, "core_metadata_dependency_count_or_type_mismatch")

    def test_06_canonical_duplicates_on_both_sides_are_refused(self):
        package, actual = self.pair()
        original = next(value for value in actual["requires_dist"] if Requirement(value).name == "cffi")
        canonical = str(Requirement(original))
        self.assertNotEqual(original, canonical)
        package["requires_dist"].append(original)
        actual["requires_dist"].append(canonical)
        self.refused(package, actual, "duplicate_core_metadata_dependency")

    def test_07_direct_url_on_both_sides_is_refused(self):
        package, actual = self.pair()
        package["requires_dist"] = actual["requires_dist"] = ["cffi @ https://example.invalid/cffi.whl"]
        self.refused(package, actual, "core_metadata_dependency_url_or_extra_refused")

    def test_08_project_extra_on_both_sides_is_refused(self):
        package, actual = self.pair()
        package["requires_dist"] = actual["requires_dist"] = ["cffi[unrequested]>=2.0.0"]
        self.refused(package, actual, "core_metadata_dependency_url_or_extra_refused")

    def test_09_changed_dependency_marker_is_refused(self):
        package, actual = self.pair()
        actual["requires_dist"] = [value.replace("!= 'PyPy'", "== 'PyPy'")
                                   for value in actual["requires_dist"]]
        self.refused(package, actual, "core_metadata_dependency_constraint_or_marker_mismatch")

    def test_10_name_and_version_changes_are_refused(self):
        for key, value in (("name", "cryptography-other"), ("version", "50.0.3")):
            with self.subTest(field=key):
                package, actual = self.pair()
                actual[key] = value
                self.refused(package, actual, "core_metadata_name_or_version_mismatch")


class ExactResult(unittest.TextTestResult):
    def startTest(self, test):
        check()
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        check()


def main():
    global CREATED, SCOPE, Requirement, SpecifierSet
    previous = None
    armed = False
    original_path = list(sys.path)
    log = io.StringIO()
    result = None
    inputs = {}
    try:
        os.umask(0o077)
        assert sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3)
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        previous = signal.getsignal(signal.SIGALRM)
        assert previous == signal.SIG_DFL
        signal.signal(signal.SIGALRM, alarm)
        armed = True
        signal.setitimer(signal.ITIMER_REAL, max(.001, START + 52 - time.monotonic()))
        sys.addaudithook(audit)
        source_raw, plan_raw = SOURCE_TEXT.encode(), PLAN_TEXT.encode()
        assert (len(source_raw), sha(source_raw)) == tuple(SOURCE_PIN)
        assert (len(plan_raw), sha(plan_raw)) == tuple(PLAN_PIN)
        plan = json.loads(plan_raw)
        parent = OUT.parent.lstat()
        assert OUT.parent.resolve(strict=True) == OUT.parent and stat.S_ISDIR(parent.st_mode)
        assert parent.st_uid == 501 and not parent.st_mode & 0o022 and not os.path.lexists(OUT)
        OUT.mkdir(mode=0o700)
        CREATED = True
        sync(OUT.parent)
        write("candidate-installer.original.py", source_raw)
        write("fixed-wheel-plan.original.json", plan_raw)
        tree = ast.parse(SOURCE_TEXT)
        wanted = {"Refused", "need", "metadata_semantics"}
        chosen = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                  and node.name in wanted]
        assert {node.name for node in chosen} == wanted and len(chosen) == 3
        SCOPE = {"__builtins__": __builtins__}
        exec(compile(ast.Module(body=chosen, type_ignores=[]), "candidate-semantics-only", "exec"), SCOPE)
        for package in plan["packages"]:
            name = package["project"]
            assert name not in PACKAGES
            PACKAGES[name] = package
            pypi = package["metadata"]
            path = pypi["path"]
            raw = read(path, (pypi["bytes"], pypi["sha256"]))
            inputs[path] = raw
            actual = json.loads(raw)["info"]
            assert actual["name"].lower().replace("_", "-") == name
            assert actual["version"] == package["version"]
            assert actual["requires_python"] == package["requires_python"]
            assert (actual.get("requires_dist") or []) == package["requires_dist"]
            core = package["wheel_core_metadata"]
            raw = read(core["path"], (core["bytes"], core["sha256"]))
            inputs[core["path"]] = raw
            message = email.parser.BytesParser().parsebytes(raw)
            assert all(len(message.get_all(label, [])) == 1 for label in ("Name", "Version", "Requires-Python"))
            OBSERVED[name] = {"name": message["Name"].lower().replace("_", "-"),
                              "version": message["Version"], "requires_python": message["Requires-Python"],
                              "requires_dist": message.get_all("Requires-Dist", [])}
            assert OBSERVED[name] == core["fields"]
        wheel = PACKAGES["pip"]["wheel"]
        pip_path = Path(plan["transferred_public_wheels"]["root"]) / wheel["filename"]
        pip_raw = read(pip_path, (wheel["bytes"], wheel["sha256"]))
        inputs[str(pip_path)] = pip_raw
        assert not any(name == "pip" or name.startswith("pip.") for name in sys.modules)
        sys.path.insert(0, str(pip_path))
        from pip._vendor import packaging
        from pip._vendor.packaging.requirements import Requirement as FixedRequirement
        from pip._vendor.packaging.specifiers import SpecifierSet as FixedSpecifierSet
        Requirement, SpecifierSet = FixedRequirement, FixedSpecifierSet
        prefix = str(pip_path) + "/pip/_vendor/packaging/"
        assert all(str(sys.modules[name].__file__).startswith(prefix) for name in (
            "pip._vendor.packaging.requirements", "pip._vendor.packaging.specifiers"))
        REPORT["parser"] = {"pip_wheel_sha256": wheel["sha256"],
                            "packaging_version": packaging.__version__, "module_origin_verified": True,
                            "modules": {}}
        with zipfile.ZipFile(io.BytesIO(pip_raw)) as archive:
            for name in ("requirements.py", "specifiers.py"):
                raw = archive.read("pip/_vendor/packaging/" + name)
                REPORT["parser"]["modules"][name] = {"bytes": len(raw), "sha256": sha(raw)}
        names = unittest.defaultTestLoader.getTestCaseNames(MetadataGuards)
        assert names == EXPECTED and len(set(names)) == 10
        REPORT["exact_names"] = names
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(MetadataGuards)
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=ExactResult).run(suite)
        assert result.testsRun == 10 and result.wasSuccessful()
        assert not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
        for path, raw in inputs.items():
            assert read(path, (len(raw), sha(raw))) == raw
        assert not EFFECTS
        check()
        REPORT.update(status="passed", original_inputs_unchanged=True, all_four_actual_metadata_equal=True)
    except BaseException as error:
        REPORT.update(status="failed", error_type=type(error).__name__)
    finally:
        if FIRED or time.monotonic() >= START + 52:
            REPORT["status"] = "failed"
        if result is not None:
            REPORT["observed"] = {"tests": result.testsRun, "failures": len(result.failures),
                                  "errors": len(result.errors), "skipped": len(result.skipped),
                                  "expected_failures": len(result.expectedFailures),
                                  "unexpected_successes": len(result.unexpectedSuccesses)}
        REPORT.update(deadline_fired=FIRED, effects_attempted=EFFECTS,
                      elapsed_seconds_before_receipt=time.monotonic() - START)
        sys.path[:] = original_path
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        if CREATED:
            REPORT["log"] = write("guards.log", log.getvalue().encode())
            write("result.public.json", (json.dumps(REPORT, sort_keys=True, indent=2) + "\n").encode())
            sync(OUT)
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
