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

SOURCE_TEXT = "SOURCE_BINDING"
SOURCE_PIN = "SOURCE_PIN_BINDING"
PLAN_TEXT = "PLAN_BINDING"
PLAN_PIN = "PLAN_PIN_BINDING"
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
