"""Isolation and redaction tests for the V6 syscall timing summarizer."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("strace_summary.py")
spec = importlib.util.spec_from_file_location("strace_summary", SCRIPT)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, content):
        path = self.root / name
        path.write_text(content)
        return path

    def test_counts_timing_and_drops_paths(self):
        p = self.write("trace", '''[pid 31] 1760000000.000001 openat(AT_FDCWD, "/secret/root-token", O_RDONLY) = 4 <0.000011>
[pid 31] 1760000000.000002 fsync(4) = 0 <0.002000>
[pid 32] 1760000000.000003 fsync(5) = -1 EIO (Input/output error) <0.000300>
[pid 31] 1760000000.000004 linkat(1, "secret", 1, "secret2", 0) = 0 <0.000020>
[pid 31] 1760000000.000005 futex(7, 7) = 0 <0.000002>
''')
        data = parser.parse_trace([p])
        self.assertEqual(data["operations"]["fsync"]["count"], 2)
        self.assertEqual(data["operations"]["fsync"]["error_count"], 1)
        self.assertEqual(data["operations"]["fsync"]["errno_counts"], {"EIO": 1})
        self.assertAlmostEqual(data["operations"]["fsync"]["cumulative_thread_ms"], 2.3)
        self.assertEqual(data["operations"]["openat"]["count"], 1)
        self.assertNotIn("futex", data["operations"])
        self.assertNotIn("root-token", json.dumps(data))
        self.assertNotIn("secret", json.dumps(data))
        self.assertEqual(data["qualified_for_v6_ha"], False)

    def test_resumed_syscall_is_counted_once(self):
        p = self.write("trace", '''[pid 2] 1760000000.0 fsync(3 <unfinished ...>
[pid 2] 1760000000.2 <... fsync resumed>) = 0 <0.400111>
''')
        data = parser.parse_trace([p])
        self.assertEqual(data["operations"]["fsync"]["count"], 1)
        self.assertEqual(data["unfinished_or_resumed_without_timing"], 1)

    def test_phase_redaction_only(self):
        p = self.write("server", '''password=do-not-log HBV6-SNAPSHOT-PHASE phase=authenticate-pack elapsed_ms=3042
HBV6-RESTORE-STAGE objects=512 elapsed_ms=4220 token=never-include
''')
        data = parser.parse_phase_logs([p])
        self.assertEqual(data["phase_durations"], [{"phase": "authenticate-pack", "elapsed_ms": 3042}])
        self.assertEqual(data["staged_object_checkpoints"], [{"objects": 512, "elapsed_ms": 4220}])
        self.assertNotIn("never-include", json.dumps(data))
        self.assertNotIn("password", json.dumps(data))

    def test_missing_timings_fail_closed(self):
        p = self.write("trace", 'fsync(3) = 0\n')
        with self.assertRaisesRegex(ValueError, "no completed"):
            parser.parse_trace([p])

    def test_cli_refuses_overwrite(self):
        trace = self.write("trace", '123 fsync(3) = 0 <0.001000>\n')
        target = self.write("report", "KEEP ME")
        command = [sys.executable, str(SCRIPT), "--trace", str(trace), "--output", str(target)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(target.read_text(), "KEEP ME")
        self.assertNotIn(str(target), result.stderr)

    def test_multi_file_aggregate(self):
        a = self.write("a", '111 openat(1, "a", 2) = 3 <0.001>\n')
        b = self.write("b", '222 openat(1, "b", 2) = 5 <0.002>\n')
        result = parser.parse_trace([a, b])
        self.assertEqual(result["trace_file_count"], 2)
        self.assertEqual(result["operations"]["openat"]["count"], 2)
        self.assertEqual(len(result["input_sha256_in_input_order"]), 2)


if __name__ == "__main__":
    unittest.main()
