"""Reproduce controller admission guards only; no Bao executable is launched."""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time

ROOT = Path("/home/qian/heptabao-x230-successor-admission-20261106-r1")
os.umask(0o077)
assert ROOT.resolve(strict=True) == ROOT
info = ROOT.stat()
assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
payload = json.loads((ROOT / "recovery-inputs.private.json").read_bytes())
pins = {}
for item in payload["files"]:
    relative = Path(item["path"])
    assert not relative.is_absolute() and ".." not in relative.parts
    path = ROOT / relative
    raw = item["content"].encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    if item.get("sha256"):
        assert digest == item["sha256"], "original_input_hash_mismatch"
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    assert path.parent.resolve(strict=True) == path.parent
    if os.path.lexists(path):
        before = path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
        assert path.read_bytes() == raw, "existing_output_must_match_exact_reconstruction"
    else:
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    path.chmod(0o600)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    pins[item["path"]] = {"sha256": digest, "bytes": len(raw),
                          "reconstructed": item.get("reconstructed", False)}
test_path = ROOT / "qa/openbao-acceptance/tests/test_x230_current_candidate_qualification.py"
controller_path = ROOT / "qa/openbao-acceptance/x230_current_candidate_qualification.py"
compile(controller_path.read_bytes(), str(controller_path), "exec")
compile(test_path.read_bytes(), str(test_path), "exec")
temp = ROOT / "test-temporary"
temp.mkdir(mode=0o700)
argv = [sys.executable, "-I", "-S", "-B", "-m", "unittest", "discover",
        "-s", str(test_path.parent), "-p", test_path.name, "-v"]
env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
       "TMPDIR": str(temp),
       "HEPTABAO_X230_FAILED_RECEIPT": str(ROOT / "evidence/mac09-failed.original.public.json")}
start = time.monotonic()
stdout = ROOT / "evidence/admission-tests.stdout"
stderr = ROOT / "evidence/admission-tests.stderr"
with stdout.open("xb") as out, stderr.open("xb") as err:
    process = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             cwd=ROOT, timeout=45, check=False)
    out.flush(); err.flush(); os.fsync(out.fileno()); os.fsync(err.fileno())
text = stderr.read_text()
count = re.search(r"^Ran (\d+) tests in [^\n]+$", text, re.MULTILINE)
passed_lines = re.findall(r"^test_[^\n]+ \.\.\. ok$", text, re.MULTILINE)
unchanged = all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin["sha256"]
                for name, pin in pins.items())
original_refusal_tests = [
    "test_original_mac09_failed_receipt_is_rejected_without_rewriting",
    "test_original_failed_mac_report_blocks_main_before_fixture_execution",
]
actual_refusals = all(any(line.startswith(name + " ") for line in passed_lines) for name in original_refusal_tests)
passed = (process.returncode == 0 and count is not None and int(count[1]) == 24
          and len(passed_lines) == 24 and text.rstrip().endswith("OK")
          and unchanged and actual_refusals)
report = {
    "schema": "heptabao.x230-reconstructed-controller-admission-tests.v1",
    "status": "passed" if passed else "failed",
    "host": platform.node(), "platform": sys.platform, "python": sys.version,
    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "argv": argv, "child_exit_code": process.returncode,
    "tests_run": int(count[1]) if count else None, "tests_passed": len(passed_lines),
    "skipped": 0 if len(passed_lines) == 24 else None,
    "elapsed_seconds": round(time.monotonic() - start, 6),
    "inputs": pins, "inputs_unchanged": unchanged,
    "original_failed_receipt_refused_in_parser_and_before_fixture_launch": actual_refusals,
    "original_failed_receipt_sha256": "17d184d27c043a59e952ad3235497c066d8a2374d9a4d9fe816cee79eff80d0d",
    "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
    "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(),
    "cloud_previous_22_result_transferred_to_reconstruction": False,
    "positive_parser_receipts_are_fictional": True,
    "production_changed": False, "candidate_binary_executed": False,
    "oracle_binary_executed": False, "full34_executed": False, "comparison69_executed": False,
    "normal_107_build_qualified": False, "production_cutover": False,
    "legacy_cleanup_qualified": False, "full_replacement_qualified": False,
}
target = ROOT / "evidence/admission-tests.result.public.json"
with target.open("xb") as stream:
    stream.write((json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    stream.flush(); os.fsync(stream.fileno())
print(json.dumps({"status": report["status"], "tests_run": report["tests_run"], "tests_passed": report["tests_passed"],
                  "original_failed_receipt_refused": actual_refusals, "bao_started": False,
                  "result": str(target)}), flush=True)
raise SystemExit(0 if passed else 1)
