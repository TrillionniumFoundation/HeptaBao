#!/usr/bin/env python3
"""Create one pinned, isolated Mac capture Python environment; never capture data."""
from __future__ import annotations
import time
START = time.monotonic()
WORK_END = START + 150.0
import email.parser
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import sysconfig
import zipfile

ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
INPUT = ROOT / "control/formal-kv2-python-env-inputs-r3"
OUT = ROOT / "control/formal-kv2-python-env-50-0-2-r3"
TRANSFER_ROOT = ROOT / "control/formal-kv2-public-wheels-from-rog-r1"
TRANSFER_ID = (16777244, 72739337, 501, 0o700)
PLAN_FILE = INPUT / "fixed-wheel-plan.json"
PLAN_PIN = (13911, "ce036ee3d7879389eb23c6811b4ab2c2e23bf2221bf5315aaf78d9df40af2b49")
CUSTODY = None
FIRED = False
INTERRUPTED = False
CREATED = False
REPORT = {
    "schema": "heptabao.mac-create-only-capture-python-environment.v1",
    "status": "failed", "work_budget_seconds": 150, "runtime_budget_seconds": 180,
    "cleanup_and_receipt_reserve_seconds": 30, "deadline_renewed": False,
    "automatic_retry": False, "global_install": False,
    "existing_environments_modified": False, "repository_requirements_modified": False,
    "business_database_opened": False, "provider_or_j3160_called": False,
    "service_modified": False, "product_executed": False,
    "capture_controls_qualified": False, "formal_kv2_qualified": False,
    "elapsed_observation_before_receipt_publication": True,
    "durable_completion_authority": "separate_original_runtime_terminal_with_180_second_cap",
    "steps": [],
}
PRIVATE = {"schema": REPORT["schema"], "steps": []}

class Refused(RuntimeError):
    pass

class Interrupted(KeyboardInterrupt):
    pass

def need(condition, label):
    if not condition:
        raise Refused(label)

def checkpoint(end=WORK_END):
    if FIRED or INTERRUPTED or time.monotonic() >= min(end, WORK_END):
        raise Interrupted()

def interrupted(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    owner = getattr(CUSTODY, "_ACTIVE", None) if CUSTODY is not None else None
    if owner is not None:
        owner._interrupt(signum, frame)
        return
    raise Interrupted()

def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def read_pinned(path, expected, *, private=False):
    checkpoint()
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected[0], "regular_pinned_input")
        if private:
            need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                 "private_input_custody")
        blocks, count = [], 0
        while True:
            checkpoint()
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            need(count <= expected[0], "input_read_bound")
            blocks.append(block)
        raw = b"".join(blocks)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and len(raw) == expected[0] and sha(raw) == expected[1], "input_pin_changed")
        return raw
    finally:
        os.close(fd)

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def owned_directory(path, *, private):
    path = Path(path)
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(st.st_mode)
         and st.st_uid == os.geteuid()
         and (stat.S_IMODE(st.st_mode) == 0o700 if private else not st.st_mode & 0o022),
         "owned_canonical_directory")
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

def new_directory(path):
    owned_directory(path.parent, private=False)
    need(not os.path.lexists(path), "create_only_directory")
    path.mkdir(mode=0o700)
    sync_dir(path.parent)
    return owned_directory(path, private=True)

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)
    return {"bytes": len(raw), "sha256": sha(raw)}

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def clean_env():
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "TMPDIR": str(OUT / "tmp"), "PIP_CONFIG_FILE": "/dev/null",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"}

def source_version(path):
    st = Path(path).lstat()
    return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"

def validate_offline_provenance(plan, before):
    transfer = plan["transferred_public_wheels"]
    need(transfer["schema"] == "heptabao.fixed-public-wheel-transfer-binding.v1"
         and Path(transfer["root"]) == TRANSFER_ROOT
         and tuple(transfer["root_identity"]) == TRANSFER_ID
         and owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,
         "fixed_transferred_wheel_directory")
    receipt_pin, terminal_pin = transfer["download_result"], transfer["download_terminal"]
    proof = {}
    for label, item in (("result", receipt_pin), ("terminal", terminal_pin)):
        path = INPUT / item["filename"]
        need(path.parent == INPUT and path.name == item["filename"], "fixed_provenance_filename")
        raw = read_pinned(path, (item["bytes"], item["sha256"]), private=True)
        before[str(path)] = raw
        proof[label] = json.loads(raw, object_pairs_hook=unique)
    result, terminal = proof["result"], proof["terminal"]
    need(result["schema"] == "heptabao.rog-fixed-public-mac-wheel-download.v1"
         and result["status"] == "passed" and result["all_four_wheels_verified"] is True
         and result["deadline_fired"] is False and result["interrupted"] is False
         and result["source_metadata_already_bound"] is True
         and result["work_seconds"] == 150 and result["runtime_seconds"] == 180
         and result["per_wheel_seconds"] == 20 and result["original_count"] == 0,
         "completed_fixed_public_download_receipt")
    need(terminal["job_id"] == "1a1b17e4e51-fc05-7921"
         and terminal["state"] == "succeeded" and terminal["exit_code"] == 0
         and terminal["timed_out"] is False and terminal["cancelled"] is False
         and terminal["output_complete"] is True and terminal["output_durable"] is True
         and terminal["terminal_publication_confirmed"] is True,
         "durable_fixed_public_download_terminal")
    projects = [p["project"] for p in plan["packages"]]
    need(projects == ["pip", "cryptography", "cffi", "pycparser"]
         and set(transfer["files"]) == set(projects)
         and [row["project"] for row in result["steps"]] == projects
         and set(result["final_pins"]) == set(projects), "exact_four_transferred_wheels")
    for package, step in zip(plan["packages"], result["steps"]):
        wheel = package["wheel"]
        actual = transfer["files"][package["project"]]
        expected = {"bytes": wheel["bytes"], "sha256": wheel["sha256"],
                    "mode": 0o600, "owner_uid": 1000, "links": 1}
        need(result["final_pins"][package["project"]] == expected
             and step["filename"] == wheel["filename"] and step["phase"] == "complete"
             and step["verified"] is True and step["response_code"] == 200
             and step["headers_received"] is True
             and step["readback"] == expected
             and step["received_bytes"] == wheel["bytes"]
             and actual["filename"] == wheel["filename"]
             and actual["bytes"] == wheel["bytes"] and actual["sha256"] == wheel["sha256"]
             and actual["mode"] == 0o600 and actual["owner_uid"] == 501
             and actual["links"] == 1 and type(actual["version"]) is str
             and source_version(TRANSFER_ROOT / wheel["filename"]) == actual["version"],
             "download_and_transfer_wheel_binding")
    prior = plan["prior_failed_attempt"]
    need(prior["job_id"] == "1a1b17696b2-fc05-78ea"
         and Path(prior["root"]) == ROOT / "control/formal-kv2-python-env-50-0-2-r1",
         "retained_prior_failure_binding")
    prior_result = None
    for label, item in prior["retained_files"].items():
        path = Path(prior["root"]) / item["relative_path"]
        need(path.resolve(strict=True).is_relative_to(Path(prior["root"])), "prior_failure_file_scope")
        raw = read_pinned(path, (item["bytes"], item["sha256"]), private=True)
        before[str(path)] = raw
        if label == "result":
            prior_result = json.loads(raw, object_pairs_hook=unique)
    need(prior_result is not None and prior_result["status"] == "failed"
         and prior_result["environment_ready"] is False
         and prior_result["phase"] == "download_fixed_wheels"
         and prior_result["steps"] == [], "prior_attempt_remains_failed")
    REPORT["offline_input_binding"] = {
        "download_job_id": terminal["job_id"], "download_result_sha256": receipt_pin["sha256"],
        "download_terminal_sha256": terminal_pin["sha256"],
        "receiver_root_identity": list(TRANSFER_ID), "wheels": len(projects),
        "new_network_requests": False, "prior_failed_attempt_reclassified": False,
    }
    return transfer

def copy_fixed_wheel(wheel, actual):
    checkpoint()
    end = min(WORK_END, time.monotonic() + 20.0)
    source = TRANSFER_ROOT / wheel["filename"]
    target = OUT / "wheels" / wheel["filename"]
    need(source.parent == TRANSFER_ROOT and target.parent == OUT / "wheels",
         "fixed_wheel_file_scope")
    signal.setitimer(signal.ITIMER_REAL, max(0.001, end - time.monotonic()))
    try:
        need(owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID
             and source_version(source) == actual["version"], "transferred_wheel_identity_changed")
        raw = read_pinned(source, (wheel["bytes"], wheel["sha256"]), private=True)
        checkpoint(end)
        write_new(target, raw)
        need(read_pinned(target, (wheel["bytes"], wheel["sha256"]), private=True) == raw,
             "copied_wheel_readback")
        need(source_version(source) == actual["version"]
             and owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,
             "transferred_wheel_changed_during_copy")
        checkpoint(end)
        return raw
    finally:
        if not FIRED and not INTERRUPTED:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))

def wheel_metadata(package):
    wheel = package["wheel"]
    path = OUT / "wheels" / wheel["filename"]
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        need(len(members) <= 10000 and len(names) == len(set(names))
             and sum(item.file_size for item in members) <= 128 * 1024**2, "wheel_member_bound")
        for item in members:
            parts = item.filename.rstrip("/").split("/")
            need(item.filename and not item.filename.startswith("/")
                 and not any(part in ("", ".", "..") for part in parts)
                 and not "\\" in item.filename and not item.flag_bits & 1
                 and stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK,
                 "wheel_member_custody")
        metadata = [item for item in members if item.filename.endswith(".dist-info/METADATA")]
        need(len(metadata) == 1 and metadata[0].file_size <= 131072, "wheel_metadata_bound")
        raw = archive.read(metadata[0])
        bound = package["wheel_core_metadata"]
        need(len(raw) == bound["bytes"] and sha(raw) == bound["sha256"],
             "original_wheel_core_metadata_pin_mismatch")
        message = email.parser.BytesParser().parsebytes(raw)
        need(all(len(message.get_all(name, [])) == 1
                 for name in ("Name", "Version", "Requires-Python")),
             "single_core_metadata_identity_headers_required")
        actual = {"name": message["Name"].lower().replace("_", "-"),
                  "version": message["Version"], "requires_python": message["Requires-Python"],
                  "requires_dist": message.get_all("Requires-Dist", [])}
        need(actual == bound["fields"] and actual["name"] == package["project"]
             and actual["version"] == package["version"], "exact_original_wheel_core_metadata")
        return actual

def metadata_semantics(package, actual, requirement_type, specifier_type):
    need(actual["name"] == package["project"] and actual["version"] == package["version"],
         "core_metadata_name_or_version_mismatch")
    need(specifier_type(actual["requires_python"]) == specifier_type(package["requires_python"]),
         "core_metadata_python_constraint_mismatch")
    left_raw, right_raw = actual["requires_dist"], package["requires_dist"]
    need(type(left_raw) is list and type(right_raw) is list
         and len(left_raw) == len(right_raw)
         and all(type(value) is str for value in left_raw + right_raw),
         "core_metadata_dependency_count_or_type_mismatch")
    left = [requirement_type(value) for value in left_raw]
    right = [requirement_type(value) for value in right_raw]
    need(all(not value.url and not value.extras for value in left + right),
         "core_metadata_dependency_url_or_extra_refused")
    for values in (left, right):
        need(all(not any(value == previous for previous in values[:index])
                 for index, value in enumerate(values)), "duplicate_core_metadata_dependency")
    need(all(sum(value == expected for expected in right) == 1 for value in left),
         "core_metadata_dependency_constraint_or_marker_mismatch")

def verify_all_core_semantics(plan, observed):
    pip_package = next(p for p in plan["packages"] if p["project"] == "pip")
    wheel = pip_package["wheel"]
    path = OUT / "wheels" / wheel["filename"]
    read_pinned(path, (wheel["bytes"], wheel["sha256"]), private=True)
    need(not any(name == "pip" or name.startswith("pip.") for name in sys.modules),
         "unmodified_pinned_requirement_parser")
    original_path = list(sys.path)
    sys.path.insert(0, str(path))
    try:
        from pip._vendor import packaging
        from pip._vendor.packaging.requirements import Requirement
        from pip._vendor.packaging.specifiers import SpecifierSet
        prefix = str(path) + "/pip/_vendor/packaging/"
        need(all(str(sys.modules[name].__file__).startswith(prefix) for name in (
            "pip._vendor.packaging.requirements", "pip._vendor.packaging.specifiers")),
            "fixed_vendored_parser_origin")
        need(set(observed) == {p["project"] for p in plan["packages"]}
             and len(observed) == 4, "complete_four_core_metadata_observations")
        for package in plan["packages"]:
            metadata_semantics(package, observed[package["project"]], Requirement, SpecifierSet)
        REPORT["core_metadata_semantics"] = {
            "packages": 4, "complete_constraints_equal": True,
            "checked_before_venv_and_install": True,
            "current_python_satisfaction_used_as_equivalence": False,
            "canonical_duplicates_refused": True, "direct_urls_and_project_extras_refused": True,
            "parser_pip_wheel_sha256": wheel["sha256"],
            "vendored_packaging_version": packaging.__version__,
        }
    finally:
        sys.path[:] = original_path

def run_step(owner, name, arguments, budget):
    checkpoint()
    begin = time.monotonic()
    end = min(WORK_END, begin + float(budget))
    signal.setitimer(signal.ITIMER_REAL, max(0.001, end - time.monotonic()))
    row = {"name": name, "budget_seconds": budget, "returncode": None, "completed": False}
    REPORT["steps"].append(row)
    private = {"name": name, "argv": arguments}
    PRIVATE["steps"].append(private)
    out_path, err_path = OUT / (name + ".stdout"), OUT / (name + ".stderr")
    try:
        with out_path.open("xb") as output, err_path.open("xb") as error:
            child = subprocess.Popen(arguments, cwd=OUT, env=clean_env(), stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=error)
            try:
                row["returncode"] = child.wait(timeout=max(0.001, end - time.monotonic()))
            finally:
                if child.returncode is None:
                    child.kill()
                    child.wait(timeout=5)
                row["original_wait_completed"] = child.custody["original_wait_completed"]
                row["original_wait_count"] = child.custody["original_wait_count"]
                row["no_live_members_before_reap"] = child.custody.get("no_live_members_before_reap")
                row["custody_gaps"] = list(child.custody["gaps"])
        checkpoint(end)
        need(row["returncode"] == 0, "owned_step_failed")
        need(row["original_wait_completed"] is True and row["original_wait_count"] == 1
             and row["no_live_members_before_reap"] is True and not row["custody_gaps"],
             "owned_step_custody")
        row["completed"] = True
    finally:
        row["elapsed_seconds"] = time.monotonic() - begin
        for key, path in (("stdout", out_path), ("stderr", err_path)):
            if path.is_file():
                need(path.stat().st_size <= 2 * 1024**2, "owned_step_output_bound")
                raw = path.read_bytes()
                private[key] = {"bytes": len(raw), "sha256": sha(raw)}
                need(len(raw) <= 2 * 1024**2, "owned_step_output_bound")
        if not FIRED and not INTERRUPTED:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))

OFFLINE_INSTALL = r'''
import sys,os,json,hashlib,runpy,zipfile,email.parser
from pathlib import Path
plan=json.loads(Path(sys.argv[1]).read_text())
root=Path(plan["destination"]); env=root/"venv"
assert Path(sys.prefix).resolve()==env and Path(sys.base_prefix).resolve()!=env
assert os.environ.get("PIP_CONFIG_FILE")==os.devnull
wheels=root/"wheels"; packages=plan["packages"]
pip_pkg=next(p for p in packages if p["project"]=="pip")
pip_wheel=wheels/pip_pkg["wheel"]["filename"]
assert hashlib.sha256(pip_wheel.read_bytes()).hexdigest()==pip_pkg["wheel"]["sha256"]
sys.path.insert(0,str(pip_wheel))
def audit(event,args):
    if event in ("socket.connect","socket.getaddrinfo","subprocess.Popen","os.system","os.posix_spawn"):
        raise RuntimeError("offline_installer_effect_refused")
sys.addaudithook(audit)
from pip._vendor.packaging.tags import sys_tags,parse_tag
from pip._vendor.packaging.utils import parse_wheel_filename
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.specifiers import SpecifierSet
from pip._vendor.packaging.markers import default_environment
from pip._internal.configuration import Configuration
configuration=Configuration(isolated=True); configuration.load()
assert not list(configuration.items())
environment=default_environment(); environment["extra"]=""
for key,value in plan["runtime_marker_environment"].items():
    assert environment[key]==value
tags=set(sys_tags()); selected={p["project"]:p["version"] for p in packages}
edges=[]; inactive=[]
for package in packages:
    name,version,build,wheel_tags=parse_wheel_filename(package["wheel"]["filename"])
    assert name==package["project"] and str(version)==package["version"] and tags.intersection(wheel_tags)
    assert SpecifierSet(package["requires_python"]).contains(environment["python_full_version"])
    for value in package["requires_dist"]:
        requirement=Requirement(value)
        assert not requirement.url and not requirement.extras
        if requirement.marker and not requirement.marker.evaluate(environment):
            inactive.append({"from":package["project"],"requirement":value})
            continue
        assert requirement.name in selected and requirement.specifier.contains(selected[requirement.name])
        edges.append({"from":package["project"],"to":requirement.name,"requirement":value})
assert edges==plan["selected_dependency_edges"] and inactive==plan["inactive_markers"]
print(json.dumps({"closure_validated":True,"actual_tag_count":len(tags),"selected":selected,
                  "inactive_markers":inactive},sort_keys=True),flush=True)
requirements=root/"requirements.fixed.txt"
sys.argv=["pip","--isolated","--disable-pip-version-check","--require-virtualenv",
    "install","--no-index","--no-deps","--only-binary=:all:","--no-cache-dir","--no-compile",
    "--require-hashes","--no-warn-script-location","-r",str(requirements)]
runpy.run_module("pip",run_name="__main__")
'''

VERIFY = r'''
import sys,os,json,importlib,importlib.metadata,sysconfig
from pathlib import Path
plan=json.loads(Path(sys.argv[1]).read_text())
root=Path(plan["destination"]); env=root/"venv"
assert Path(sys.prefix).resolve()==env and Path(sys.base_prefix).resolve()!=env
assert sys.version_info[:3]==(3,14,3) and sys.platform=="darwin"
assert "include-system-site-packages = false" in (env/"pyvenv.cfg").read_text()
assert all(Path(sysconfig.get_path(kind)).resolve().is_relative_to(env) for kind in ("purelib","platlib"))
def audit(event,args):
    if event in ("socket.connect","socket.getaddrinfo","subprocess.Popen","os.system","os.posix_spawn"):
        raise RuntimeError("environment_verify_effect_refused")
sys.addaudithook(audit)
wanted={p["project"]:p["version"] for p in plan["packages"]}
actual={d.metadata["Name"].lower().replace("_","-"):d.version for d in importlib.metadata.distributions()}
assert actual==wanted
for name in ("cryptography","cffi","pycparser","pip","_cffi_backend"):
    module=importlib.import_module(name)
    assert Path(module.__file__).resolve().is_relative_to(env)
from cryptography.fernet import Fernet,InvalidToken
from cryptography.hazmat.backends.openssl.backend import backend
cipher=Fernet(Fernet.generate_key()); plain=b"owned-synthetic-capture-runtime-qualification"
token=cipher.encrypt(plain); assert cipher.decrypt(token)==plain
for wrong_cipher,wrong_token in ((Fernet(Fernet.generate_key()),token),(cipher,token[:-3]+b"abc")):
    try: wrong_cipher.decrypt(wrong_token)
    except InvalidToken: pass
    else: raise AssertionError("fernet_negative_guard")
from pip._internal.configuration import Configuration
cfg=Configuration(isolated=True);cfg.load();assert not list(cfg.items())
from pip._internal.operations.check import check_package_set,create_package_set_from_installed
package_set,parsing_problems=create_package_set_from_installed()
missing,conflicting=check_package_set(package_set)
assert not parsing_problems and not missing and not conflicting
print(json.dumps({"environment_ready":True,"versions":actual,"fernet_roundtrip":True,
 "wrong_key_rejected":True,"tampering_rejected":True,"dependency_check":True,
 "no_global_packages":True,"openssl_version":backend.openssl_version_text(),
 "business_database_opened":False,"capture_controls_qualified":False},sort_keys=True))
'''

def main():
    global CUSTODY, CREATED
    os.umask(0o077)
    need(sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3)
         and platform.machine() == "arm64" and not sysconfig.get_config_var("Py_GIL_DISABLED"),
         "fixed_mac_python_platform")
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
         and signal.getsignal(signal.SIGALRM) == signal.SIG_DFL, "foreign_alarm")
    previous = {s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    for s in previous:
        signal.signal(s, interrupted)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_END - time.monotonic()))
    owner = None
    before = {}
    try:
        need(len(sys.argv) == 2 and len(sys.argv[1]) == 64
             and all(c in "0123456789abcdef" for c in sys.argv[1]), "external_controller_pin_required")
        controller = INPUT / "mac_fixed_capture_environment.py"
        need(Path(__file__).resolve() == controller, "fixed_controller_path")
        before["controller"] = read_pinned(controller, (controller.lstat().st_size, sys.argv[1]), private=True)
        REPORT["controller"] = {"bytes": len(before["controller"]), "sha256": sha(before["controller"])}
        REPORT["fixed_plan"] = {"bytes": PLAN_PIN[0], "sha256": PLAN_PIN[1]}
        plan_raw = read_pinned(PLAN_FILE, PLAN_PIN, private=True)
        plan = json.loads(plan_raw, object_pairs_hook=unique)
        need(plan["schema"] == "heptabao.mac-create-only-capture-python-environment-plan.v1"
             and plan["destination"] == str(OUT) and plan["input_parent"] == str(INPUT)
             and plan["budgets"] == {"work_seconds":150,"runtime_seconds":180,
                "cleanup_and_receipt_reserve_seconds":30,"per_copy_seconds":20,
                "venv_seconds":15,"install_seconds":35,"verification_seconds":10},
             "fixed_environment_plan")
        python = plan["python"]
        need(Path(sys.executable).resolve() == Path(python["executable"]), "fixed_python_path")
        before["python"] = read_pinned(python["executable"], (python["binary_bytes"], python["binary_sha256"]))
        qa = Path(plan["custody_source"])
        for name, pin in plan["custody_pins"].items():
            before[name] = read_pinned(qa / name, (pin["bytes"], pin["sha256"]))
        for package in plan["packages"]:
            pin = package["metadata"]
            raw = read_pinned(pin["path"], (pin["bytes"], pin["sha256"]))
            metadata = json.loads(raw, object_pairs_hook=unique)
            info = metadata["info"]
            need(info["name"].lower().replace("_","-") == package["project"]
                 and info["version"] == package["version"] and not metadata.get("vulnerabilities")
                 and (info.get("requires_dist") or []) == package["requires_dist"]
                 and info["requires_python"] == package["requires_python"], "fixed_pypi_metadata")
            wheel = package["wheel"]
            matches = [x for x in metadata["urls"] if x["filename"] == wheel["filename"]]
            need(len(matches) == 1 and matches[0]["url"] == wheel["url"]
                 and matches[0]["size"] == wheel["bytes"] and matches[0]["digests"]["sha256"] == wheel["sha256"]
                 and matches[0]["yanked"] is False and matches[0]["packagetype"] == "bdist_wheel",
                 "fixed_wheel_metadata")
            before[pin["path"]] = raw
            core = package["wheel_core_metadata"]
            before[core["path"]] = read_pinned(core["path"], (core["bytes"], core["sha256"]), private=True)
        prior = plan["retained_metadata_failure"]
        need(prior["job_id"] == "1a1b1a60246-fc05-7a15"
             and Path(prior["path"]) == ROOT / "control/formal-kv2-python-env-50-0-2-r2/result.public.json",
             "retained_metadata_failure_binding")
        raw = read_pinned(prior["path"], (prior["bytes"], prior["sha256"]), private=True)
        before[prior["path"]] = raw
        failure = json.loads(raw, object_pairs_hook=unique)
        need(failure["status"] == "failed" and failure["environment_ready"] is False
             and failure["error_label"] == "wheel_and_pypi_metadata_mismatch"
             and failure["steps"] == [], "prior_metadata_attempt_remains_failed")
        transfer = validate_offline_provenance(plan, before)
        need("owned_process" not in sys.modules and "kv2_dr_process_custody" not in sys.modules,
             "unmodified_custody_import")
        sys.path.insert(0, str(qa))
        import owned_process
        CUSTODY = importlib.import_module("kv2_dr_process_custody")
        root_identity = new_directory(OUT)
        CREATED = True
        PRIVATE["directory_identity"] = root_identity
        for name in ("tmp", "wheels"):
            new_directory(OUT / name)
        write_new(OUT / "fixed-wheel-plan.json", plan_raw)
        need(os.statvfs(OUT).f_bavail * os.statvfs(OUT).f_frsize >= 128 * 1024**2,
             "environment_disk_headroom")
        REPORT["phase"] = "copy_verified_transferred_wheels"
        observed_core = {}
        for package in plan["packages"]:
            wheel = package["wheel"]
            raw = copy_fixed_wheel(wheel, transfer["files"][package["project"]])
            before[str(TRANSFER_ROOT / wheel["filename"])] = raw
            observed_core[package["project"]] = wheel_metadata(package)
        REPORT["phase"] = "verify_complete_core_metadata_semantics"
        verify_all_core_semantics(plan, observed_core)
        REPORT["wheel_pins"] = {p["project"]:{"version":p["version"],"bytes":p["wheel"]["bytes"],
                                           "sha256":p["wheel"]["sha256"]} for p in plan["packages"]}
        lines = [p["project"] + " @ " + (OUT / "wheels" / p["wheel"]["filename"]).as_uri()
                 + " --hash=sha256:" + p["wheel"]["sha256"] for p in plan["packages"]]
        write_new(OUT / "requirements.fixed.txt", ("\n".join(lines)+"\n").encode())
        write_new(OUT / "offline_install.py", OFFLINE_INSTALL.encode())
        write_new(OUT / "verify_environment.py", VERIFY.encode())
        with CUSTODY.activated() as owner:
            REPORT["phase"] = "create_new_venv"
            run_step(owner, "create-venv", [python["executable"], "-I", "-B", "-m", "venv",
                    "--without-pip", "--copies", str(OUT / "venv")], 15)
            venv_python = OUT / "venv/bin/python3"
            need(venv_python.resolve(strict=True) == venv_python, "copied_venv_interpreter")
            REPORT["phase"] = "offline_install"
            run_step(owner, "offline-install", [str(venv_python), "-I", "-B",
                    str(OUT / "offline_install.py"), str(OUT / "fixed-wheel-plan.json")], 35)
            REPORT["phase"] = "verify_new_environment"
            run_step(owner, "verify-environment", [str(venv_python), "-I", "-B",
                    str(OUT / "verify_environment.py"), str(OUT / "fixed-wheel-plan.json")], 10)
            owner.assert_retired()
        PRIVATE["process_custody"] = owner.receipt()
        need(PRIVATE["process_custody"]["passed_process_custody"] is True
             and PRIVATE["process_custody"]["finished"] is True, "complete_process_custody")
        checkpoint()
        for key, raw in before.items():
            if key == "controller":
                path = controller
            elif key == "python":
                path = python["executable"]
            elif key in plan["custody_pins"]:
                path = qa / key
            else:
                path = key
            need(read_pinned(path, (len(raw), sha(raw))) == raw, "original_input_changed")
        for package in plan["packages"]:
            wheel = package["wheel"]
            read_pinned(OUT / "wheels" / wheel["filename"], (wheel["bytes"], wheel["sha256"]), private=True)
        for package in plan["packages"]:
            wheel = package["wheel"]
            need(source_version(TRANSFER_ROOT / wheel["filename"])
                 == transfer["files"][package["project"]]["version"],
                 "transferred_wheel_changed_after_install")
        need(owned_directory(TRANSFER_ROOT, private=True) == TRANSFER_ID,
             "transferred_wheel_directory_changed")
        REPORT["prior_failed_attempt_bound_file_contents_unchanged"] = True
        need(owned_directory(OUT, private=True) == root_identity, "environment_root_changed")
        checkpoint()
        REPORT.update(status="passed",phase="complete",environment_ready=True,
                      original_inputs_unchanged=True,all_owned_processes_retired=True,
                      installed_packages={p["project"]:p["version"] for p in plan["packages"]})
    except BaseException as error:
        REPORT.update(status="failed",environment_ready=False,error_type=type(error).__name__,
                      error_label=str(error) if isinstance(error,Refused) else "environment_preparation_failed")
    finally:
        if owner is not None:
            try:
                PRIVATE["process_custody"] = owner.finish()
            except BaseException as error:
                REPORT.update(status="failed",environment_ready=False,cleanup_error_type=type(error).__name__)
        if FIRED or INTERRUPTED or time.monotonic() >= WORK_END:
            REPORT.update(status="failed",environment_ready=False)
        REPORT.update(deadline_fired=FIRED,interrupted=INTERRUPTED,
                      elapsed_seconds_before_receipt=time.monotonic()-START)
        signal.setitimer(signal.ITIMER_REAL,0)
        for s,handler in previous.items():
            signal.signal(s,handler)
        if CREATED:
            PRIVATE["public_result"] = REPORT
            write_new(OUT / "receipt.private.json",json_bytes(PRIVATE))
            write_new(OUT / "result.public.json",json_bytes(REPORT))
        print(json.dumps(REPORT,sort_keys=True,allow_nan=False),flush=True)
    return 0 if REPORT["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())

