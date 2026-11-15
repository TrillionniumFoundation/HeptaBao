#!/usr/bin/env python3
"""Host Java stubs only: fixed source mapping and closed diagnostic privacy."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = Path('/workspace/scratch/848006513f75/HeptaBao')
PROVIDER = REPO / 'clients/android-passkey/provider/java/org/heptabao/passkey/preview'
CORE = REPO / 'clients/android-passkey/common/java/org/heptabao/passkey/core'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


os.umask(0o077)
diag_raw = (PROVIDER / 'StageDiagnostics.java').read_bytes()
diag = diag_raw.decode()
sources = {name: (PROVIDER / name).read_bytes() for name in ('VaultFiles.java', 'DocumentIO.java', 'HomeActivity.java')}
for field, name in (('VAULT_SOURCE_SHA256', 'VaultFiles.java'), ('DOCUMENT_SOURCE_SHA256', 'DocumentIO.java')):
    pinned = re.search(field + r' = "([0-9a-f]{64})"', diag).group(1)
    assert sha(sources[name]) == pinned, 'mapping_source_hash_mismatch'
assert sha(sources['HomeActivity.java']) == '90e3ea0753c5edb28db406f5b1c0845a8dec17e4d778651c62b17814869b3657'
bindings = re.findall(r'bind\((DOCUMENT|VAULT|GUARD), "([^"]+)", ([0-9]+), Site\.([A-Z_]+)\), // (.+)', diag)
assert len(bindings) == 41, 'mapping_inventory_changed'
seen = set()
for owner, method, number, site, fragment in bindings:
    name = 'DocumentIO.java' if owner == 'DOCUMENT' else 'VaultFiles.java'
    line = int(number)
    assert (owner, method, line) not in seen, 'duplicate_site_binding'
    seen.add((owner, method, line))
    assert fragment in sources[name].decode().splitlines()[line - 1], 'mapped_source_line_changed'

workspace = ROOT / 'host-java-r2'; workspace.mkdir(mode=0o700, exist_ok=False)
src = workspace / 'src'; classes = workspace / 'classes'; classes.mkdir(mode=0o700)
save(src / 'org/heptabao/passkey/preview/StageDiagnostics.java', diag_raw)
save(src / 'org/heptabao/passkey/core/Failure.java', (CORE / 'Failure.java').read_bytes())
save(src / 'android/system/ErrnoException.java', b'''package android.system;
public final class ErrnoException extends Exception {
  public final int errno;
  public ErrnoException(String message, int errno) { super(message); this.errno = errno; }
}''')
save(src / 'android/system/OsConstants.java', b'''package android.system;
public final class OsConstants {
  public static final int EPERM=1, ENOENT=2, EINTR=4, EIO=5, EBADF=9,
    EACCES=13, ENFILE=23, EMFILE=24, EINVAL=22, ENOSPC=28, EROFS=30,
    EOPNOTSUPP=95, ECANCELED=125;
}''')
save(src / 'android/os/OperationCanceledException.java', b'''package android.os;
public final class OperationCanceledException extends RuntimeException {
  public OperationCanceledException(String message) { super(message); }
}''')
save(src / 'org/heptabao/passkey/preview/StageDiagnosticsHost.java', r'''package org.heptabao.passkey.preview;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.os.OperationCanceledException;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import org.heptabao.passkey.core.Failure;
public final class StageDiagnosticsHost {
  private static final String MARK = "SYNTHETIC_CANARY_content://private/path?password=redacted";
  private static final String VAULT = "org.heptabao.passkey.preview.VaultFiles";
  private static final String DOCUMENT = "org.heptabao.passkey.preview.DocumentIO";
  private static final List<String> checks = new ArrayList<>();
  private static StackTraceElement frame(String owner, String method, int line) {
    return new StackTraceElement(owner, method, MARK, line);
  }
  private static <T extends Exception> T at(T error, String owner, String method, int line) {
    error.setStackTrace(new StackTraceElement[]{frame("android.system.Os", "nativeCall", 1), frame(owner, method, line)});
    return error;
  }
  private static void equal(String name, String expected, Exception error) {
    Failure mapped = StageDiagnostics.failure(error);
    if (!expected.equals(mapped.code) || mapped.code.contains(MARK) || mapped.getCause() != null)
      throw new AssertionError(name);
    checks.add(name);
  }
  public static void main(String[] args) throws Exception {
    Failure guard = new Failure("unsafe_directory");
    if (StageDiagnostics.failure(guard) != guard) throw new AssertionError("original_failure_identity");
    checks.add("original_failure_identity");
    equal("exact_site_errno_without_message", "stage_failed:FILES_CHMOD:ERRNO:EACCES",
      at(new ErrnoException(MARK, OsConstants.EACCES), VAULT, "privateFiles", 66));
    equal("missing_line_is_unknown", "stage_failed:UNKNOWN:IO:NONE", at(new IOException(MARK), VAULT, "privateFiles", -1));
    equal("nearby_line_is_not_guessed", "stage_failed:UNKNOWN:IO:NONE", at(new IOException(MARK), VAULT, "privateFiles", 65));
    equal("wrong_method_is_unknown", "stage_failed:UNKNOWN:IO:NONE", at(new IOException(MARK), VAULT, "otherMethod", 66));
    IOException first = new IOException(MARK);
    first.setStackTrace(new StackTraceElement[]{frame("org.heptabao.passkey.core.Unmapped", "secret", 1), frame(VAULT, "privateFiles", 66)});
    equal("unknown_first_application_frame_does_not_fall_through", "stage_failed:UNKNOWN:IO:NONE", first);
    IOException wrapped = new IOException(MARK, new ErrnoException(MARK, OsConstants.EIO));
    equal("nested_errno_with_outer_kind", "stage_failed:SAF_READ:IO:EIO", at(wrapped, VAULT, "readContent", 258));
    Exception depth3 = new Exception(MARK, new Exception(MARK, new ErrnoException(MARK, OsConstants.ENOSPC)));
    equal("third_throwable_errno_bounded", "stage_failed:PUBLISH_WRITE_SYNC:OTHER:ENOSPC", at(depth3, VAULT, "publish", 122));
    Exception depth4 = new Exception(MARK, new Exception(MARK, new Exception(MARK, new ErrnoException(MARK, OsConstants.ENOSPC))));
    equal("fourth_throwable_not_inspected", "stage_failed:SAF_OPEN:OTHER:NONE", at(depth4, DOCUMENT, "open", 58));
    Exception a = new Exception(MARK), b = new Exception(MARK); a.initCause(b); b.initCause(a);
    equal("cyclic_causes_terminate", "stage_failed:SAF_OPEN:OTHER:NONE", at(a, DOCUMENT, "open", 58));
    equal("unknown_errno_does_not_expose_number", "stage_failed:SAF_FSTAT:ERRNO:OTHER",
      at(new ErrnoException(MARK, 987654321), VAULT, "readContent", 254));
    Exception[] kinds = {new FileNotFoundException(MARK), new OperationCanceledException(MARK), new SecurityException(MARK),
      new IllegalArgumentException(MARK), new IllegalStateException(MARK), new Exception(MARK)};
    String[] expected = {"FILE_NOT_FOUND", "CANCELLED", "SECURITY", "ARGUMENT", "STATE", "OTHER"};
    for (int i=0; i<kinds.length; i++) {
      Failure result = StageDiagnostics.failure(at(kinds[i], DOCUMENT, "open", 58));
      if (!result.code.equals("stage_failed:SAF_OPEN:"+expected[i]+":NONE")) throw new AssertionError("closed_kind_taxonomy");
    }
    checks.add("closed_kind_taxonomy");
    IOException distant = new IOException(MARK); StackTraceElement[] trace = new StackTraceElement[17];
    for (int i=0; i<16; i++) trace[i] = frame("unrelated."+MARK, "untrusted", i);
    trace[16] = frame(VAULT, "privateFiles", 66); distant.setStackTrace(trace);
    equal("trace_inspection_bounded", "stage_failed:UNKNOWN:IO:NONE", distant);
    Exception noMessages = new Exception() {
      @Override public String getMessage() { throw new AssertionError("message_access_forbidden"); }
      @Override public String toString() { throw new AssertionError("to_string_forbidden"); }
    };
    noMessages.addSuppressed(new Exception(MARK));
    equal("message_and_suppressed_data_never_read", "stage_failed:FILES_FSYNC:OTHER:NONE", at(noMessages, VAULT, "privateFiles", 71));
    StringBuilder out = new StringBuilder("{\"passed\":").append(checks.size()).append(",\"checks\":[");
    for (int i=0; i<checks.size(); i++) { if(i>0)out.append(',');out.append('"').append(checks.get(i)).append('"'); }
    System.out.println(out.append("]}").toString());
  }
}'''.encode())
java = '/usr/bin/java'
compile_command = [java, '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-d', str(classes)]
compile_command += [str(path) for path in sorted(src.rglob('*.java'))]
compiled = subprocess.run(compile_command, capture_output=True, timeout=45)
assert compiled.returncode == 0, 'host_stub_compile_failed'
executed = subprocess.run([java, '-cp', str(classes), 'org.heptabao.passkey.preview.StageDiagnosticsHost'], capture_output=True, timeout=15)
assert executed.returncode == 0 and executed.stderr == b'', 'host_stub_checks_failed'
checks = json.loads(executed.stdout)
assert checks['passed'] == 14
report = {'schema': 1, 'scope': 'host_stub_stage_diagnostics_only', 'mapped_source_entries': len(bindings),
          'source_sha256': {name: sha(raw) for name, raw in sources.items()},
          'diagnostic_source_sha256': sha(diag_raw), 'test_script_sha256': sha(Path(__file__).read_bytes()),
          'host_java_executable_sha256': sha(Path(java).resolve().read_bytes()), 'compile_exit_code': compiled.returncode,
          'host_compile_scope': 'Java 21 with minimal Android type stubs; not an SDK/API compatibility build',
          'earlier_host_setup': 'The local stripped JRE compiler rejected --release 8 because its historical API files are unavailable. Android APK builder remains unchanged.',
          **checks, 'adb_calls': 0, 'android_runtime_exercised': False, 'phone_qualified': False,
          'production_qualified': False, 'external_review': False,
          'source_line_note': 'Exact source pins and fragments checked. Actual APK line-table preservation still requires its real build inspection; absent or unknown lines yield UNKNOWN.'}
save(ROOT / 'host-check.public.json', (json.dumps(report, sort_keys=True, indent=2)+'\n').encode())
save(ROOT / 'host-check.stdout.original.json', executed.stdout)
fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)
print(json.dumps(report, sort_keys=True))
