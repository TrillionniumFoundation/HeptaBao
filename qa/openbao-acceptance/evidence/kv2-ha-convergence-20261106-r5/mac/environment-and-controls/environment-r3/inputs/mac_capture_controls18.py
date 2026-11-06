#!/usr/bin/env python3
"""Exactly 18 synthetic capture controls in the newly pinned Darwin environment."""
from __future__ import annotations
import time
START = time.monotonic()
WORK_END = START + 52.0
import contextlib
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
import tempfile
import unittest

ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
INPUT = ROOT / "control/formal-kv2-python-env-inputs-r3"
ENVIRONMENT = ROOT / "control/formal-kv2-python-env-50-0-2-r3"
OUT = ROOT / "control/formal-kv2-capture-controls-18-r1"
INTERNAL = Path("/Users/qianqi/heptabao-formal-kv2-capture-controls-18-r1")
QA = ROOT / "source-dr25-a2577-r2/qa/openbao-acceptance"
PLAN_PIN = (13911, "ce036ee3d7879389eb23c6811b4ab2c2e23bf2221bf5315aaf78d9df40af2b49")
INSTALLER_PIN = (33884, "7446010e142d381c524eea804c2a6c03a3f7e075d4143a8b66817f2b4f300985")
PINS = {
    "mac_current_sqlite_capture.py": (57280, "9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972"),
    "test_mac_current_sqlite_capture.py": (23809, "0b93d597b9fd525470951cb7b49cdb6707c11fc38b5e42f0d06bcedc7e0395f6"),
}
CUSTODY_PINS = {
    "kv2_dr_process_custody.py": (26131, "669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008"),
    "owned_process.py": (28442, "0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"),
}
EXPECTED_NAMES = [
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_absent_main_with_stray_wal_is_refused_before_output_creation",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_backup_refuses_replaced_original_source_directory_identity",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_changed_non_auth_table_blocks_whole_database_backup",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_changed_safety_cohort_keeps_partial_copies_unqualified",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_fresh_restore_uses_authenticated_origin_without_original_source_or_capture_paths",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_full_workflow_restores_non_auth_tables_all_auth_rows_and_absences",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_hardlinked_source_database_is_refused",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_live_wal_transaction_is_captured_from_real_separate_owned_writer",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_missing_agent_cannot_be_hidden_by_rewriting_capture_denominator",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_missing_configured_agent_is_rejected_before_any_copy",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_original_total_deadline_does_not_start_capture_or_reset_on_failure",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_present_transport_requires_a_separate_current_operation_fence",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_public_result_never_exports_source_names_hashes_or_credential_values",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_same_filesystem_key_rejects_then_whole_workflow_cannot_resume",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_same_source_or_capture_filesystem_archive_refuses_even_with_other_filesystem_key",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_unavailable_encryption_refuses_before_source_configuration_or_copy",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_wrong_key_and_corrupt_archive_never_create_restore_destination",
    "test_mac_current_sqlite_capture.CurrentCaptureControls.test_zero_length_main_requires_absent_sidecars_at_both_capture_boundaries"
]
CUSTODY = None
LAST_RESULT = None
FIRED = False
INTERRUPTED = False
CREATED = False
REPORT = {
    "schema": "heptabao.mac-current-sqlite-capture-controls.v1",
    "status": "failed", "expected_tests": 18, "work_budget_seconds": 52,
    "runtime_budget_seconds": 60, "deadline_renewed": False, "automatic_retry": False,
    "scope": "owned_synthetic_sqlite_and_real_internal_external_filesystems",
    "business_capture_executed": False, "business_source_opened": False,
    "product_or_sdk_executed": False, "provider_or_j3160_called": False,
    "service_modified": False, "formal_kv2_qualified": False,
    "cross_database_atomic_snapshot_qualified": False, "all_known_writers_fenced": False,
    "elapsed_observation_before_receipt_publication": True,
    "durable_completion_authority": "separate_original_runtime_terminal_with_60_second_cap",
}
PRIVATE = {"schema": REPORT["schema"]}

class Refused(RuntimeError):
    pass

class WorkInterrupted(KeyboardInterrupt):
    pass

def need(condition, label):
    if not condition:
        raise Refused(label)

def checkpoint():
    if FIRED or INTERRUPTED or time.monotonic() >= WORK_END:
        raise WorkInterrupted()

def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    owner = getattr(CUSTODY, "_ACTIVE", None) if CUSTODY is not None else None
    if owner is not None:
        owner._interrupt(signum, frame)
        return
    raise WorkInterrupted()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(st):
    return (st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_nlink,
            st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def read_pin(path, pin):
    checkpoint()
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path, "canonical_input")
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and before.st_size==pin[0] and 0<=pin[0]<=131072, "bounded_regular_input")
        chunks=[]; count=0
        while True:
            checkpoint()
            block=os.read(fd,65536)
            if not block: break
            count+=len(block)
            need(count<=pin[0],"input_read_cap")
            chunks.append(block)
        raw=b"".join(chunks)
        need(len(raw)==pin[0] and sha(raw)==pin[1]
             and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),"input_pin_changed")
        return raw
    finally:
        os.close(fd)

def directory(path, private=True):
    path=Path(path); info=path.lstat()
    need(path.resolve(strict=True)==path and stat.S_ISDIR(info.st_mode)
         and info.st_uid==os.geteuid()
         and (stat.S_IMODE(info.st_mode)==0o700 if private else not info.st_mode&0o022),
         "owned_canonical_directory")
    return (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))

def new_directory(path):
    directory(path.parent,private=False)
    need(not os.path.lexists(path),"create_only_directory")
    path.mkdir(mode=0o700)
    return directory(path)

def write_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
    finally: os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def flatten(suite):
    names=[]
    for item in suite:
        names.extend(flatten(item) if isinstance(item,unittest.TestSuite) else [item.id()])
    return names

class ExactResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        global LAST_RESULT
        super().__init__(*args,**kwargs)
        self.started=[];self.actual=[]
        LAST_RESULT=self
    def startTest(self,test):
        checkpoint();super().startTest(test);self.started.append(test.id())
    def addSuccess(self,test):
        self.actual.append({"test":test.id(),"status":"passed"});super().addSuccess(test)
    def addFailure(self,test,err):
        self.actual.append({"test":test.id(),"status":"failed","error_type":err[0].__name__})
        super().addFailure(test,err)
    def addError(self,test,err):
        self.actual.append({"test":test.id(),"status":"error","error_type":err[0].__name__})
        super().addError(test,err)
    def addSkip(self,test,reason):
        self.actual.append({"test":test.id(),"status":"skipped"});super().addSkip(test,reason)
    def addExpectedFailure(self,test,err):
        self.actual.append({"test":test.id(),"status":"expected_failure"})
        super().addExpectedFailure(test,err)
    def addUnexpectedSuccess(self,test):
        self.actual.append({"test":test.id(),"status":"unexpected_success"})
        super().addUnexpectedSuccess(test)
    def stopTest(self,test):
        super().stopTest(test);checkpoint()

def main():
    global CUSTODY,CREATED
    os.umask(0o077)
    need(sys.platform=="darwin" and os.geteuid()==501 and sys.version_info[:3]==(3,14,3)
         and platform.machine()=="arm64","fixed_mac_interpreter")
    need(Path(sys.executable).resolve()==ENVIRONMENT/"venv/bin/python3"
         and Path(sys.prefix).resolve()==ENVIRONMENT/"venv","actual_new_venv_required")
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
         and signal.getsignal(signal.SIGALRM)==signal.SIG_DFL,"foreign_alarm")
    previous={s:signal.getsignal(s) for s in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    for s in previous: signal.signal(s,interrupt)
    signal.setitimer(signal.ITIMER_REAL,max(0.001,WORK_END-time.monotonic()))
    owner=None
    before={}
    try:
        need(len(sys.argv)==5 and all(len(value)==64 and all(c in "0123456789abcdef" for c in value)
                                     for value in sys.argv[1:4]),"three_external_input_hashes_required")
        controller=INPUT/"mac_capture_controls18.py"
        need(Path(__file__).resolve()==controller,"fixed_controller_path")
        before[str(controller)]=read_pin(controller,(controller.lstat().st_size,sys.argv[1]))
        before[str(INPUT/"fixed-wheel-plan.json")]=read_pin(INPUT/"fixed-wheel-plan.json",PLAN_PIN)
        before[str(INPUT/"mac_fixed_capture_environment.py")]=read_pin(INPUT/"mac_fixed_capture_environment.py",INSTALLER_PIN)
        result_path=ENVIRONMENT/"result.public.json"
        terminal_path=INPUT/"environment-terminal.original.json"
        before[str(result_path)]=read_pin(result_path,(result_path.lstat().st_size,sys.argv[2]))
        before[str(terminal_path)]=read_pin(terminal_path,(terminal_path.lstat().st_size,sys.argv[3]))
        result=json.loads(before[str(result_path)]);terminal=json.loads(before[str(terminal_path)])
        need(result["schema"]=="heptabao.mac-create-only-capture-python-environment.v1"
             and result["status"]=="passed" and result["environment_ready"] is True
             and result["original_inputs_unchanged"] is True and result["all_owned_processes_retired"] is True
             and result["deadline_fired"] is False and result["interrupted"] is False
             and result["controller"]=={"bytes":INSTALLER_PIN[0],"sha256":INSTALLER_PIN[1]}
             and result["fixed_plan"]=={"bytes":PLAN_PIN[0],"sha256":PLAN_PIN[1]},
             "successful_pinned_environment_receipt_required")
        need(terminal["job_id"]==sys.argv[4] and terminal["state"]=="succeeded" and terminal["exit_code"]==0
             and terminal["timed_out"] is False and terminal["cancelled"] is False
             and terminal["output_complete"] is True and terminal["output_durable"] is True
             and terminal["terminal_publication_confirmed"] is True,"durable_environment_terminal_required")
        REPORT["environment_binding"]={"job_id":sys.argv[4],"receipt_sha256":sys.argv[2],
                                      "terminal_sha256":sys.argv[3],"controller_sha256":INSTALLER_PIN[1]}
        for name,pin in PINS.items(): before[str(INPUT/name)]=read_pin(INPUT/name,pin)
        for name,pin in CUSTODY_PINS.items(): before[str(QA/name)]=read_pin(QA/name,pin)
        need(not any(name in sys.modules for name in ("owned_process","kv2_dr_process_custody",
                   "test_mac_current_sqlite_capture","current_capture")),"fresh_pinned_module_import")
        sys.path[:0]=[str(INPUT),str(QA)]
        import owned_process
        CUSTODY=importlib.import_module("kv2_dr_process_custody")
        original_popen=subprocess.Popen; original_killpg=os.killpg
        root_identity=new_directory(OUT);CREATED=True
        internal_identity=new_directory(INTERNAL)
        new_directory(OUT/"archive-fixtures");new_directory(INTERNAL/"tmp")
        need(root_identity[0]!=internal_identity[0],"real_internal_external_filesystems_required")
        PRIVATE["directory_identities"]={"output":root_identity,"internal_fixture":internal_identity}
        # Only the disposable controller process and its one synthetic writer use this environment.
        os.environ.clear()
        os.environ.update({"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C",
                           "TMPDIR":str(INTERNAL/"tmp"),
                           "HEPTABAO_CAPTURE_TEST_ARCHIVE_PARENT":str(OUT/"archive-fixtures")})
        tempfile.tempdir=str(INTERNAL/"tmp")
        module=importlib.import_module("test_mac_current_sqlite_capture")
        loader=unittest.TestLoader()
        suite=loader.loadTestsFromTestCase(module.CurrentCaptureControls)
        names=flatten(suite)
        need(not loader.errors and suite.countTestCases()==18 and sorted(names)==EXPECTED_NAMES
             and len(set(names))==18,"exact_18_test_selection")
        REPORT["enumeration"]={"unique":18,"names":names}
        with (OUT/"controls.stdout").open("x") as output,(OUT/"controls.stderr").open("x") as error:
            with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
                with CUSTODY.activated() as owner:
                    suite_result=unittest.TextTestRunner(stream=error,verbosity=2,resultclass=ExactResult).run(suite)
                    owner.assert_retired()
        receipt=owner.receipt()
        PRIVATE["process_custody"]=receipt
        need(receipt["passed_process_custody"] is True and receipt["finished"] is True
             and receipt["original_count"]==1 and all(row["original_wait_count"]==1
             and row["original_wait_completed"] is True and row.get("no_live_members_before_reap") is True
             and not row["gaps"] for row in receipt["children"]),"one_synthetic_writer_complete_custody")
        need(suite_result.testsRun==18 and suite_result.wasSuccessful()
             and not suite_result.skipped and not suite_result.expectedFailures
             and not suite_result.unexpectedSuccesses and len(suite_result.actual)==18
             and all(row["status"]=="passed" for row in suite_result.actual),"complete_18_controls_required")
        need(subprocess.Popen is original_popen and os.killpg is original_killpg
             and CUSTODY._ACTIVE is None,"original_process_hooks_restored")
        need(directory(OUT)==root_identity and directory(INTERNAL)==internal_identity
             and not list((OUT/"archive-fixtures").iterdir())
             and not list((INTERNAL/"tmp").iterdir()),"owned_fixture_cleanup_boundary")
        for path,raw in before.items(): read_pin(path,(len(raw),sha(raw)))
        checkpoint()
        REPORT.update(status="passed",actual_darwin_capture_controls_qualified=True,
                      inputs_unchanged=True,real_two_filesystems=True,owned_fixtures_retired=True,
                      all_owned_processes_retired=True)
    except BaseException as error:
        REPORT.update(status="failed",actual_darwin_capture_controls_qualified=False,
                      error_type=type(error).__name__,error_label=str(error) if isinstance(error,Refused)
                      else "capture_controls_failed")
    finally:
        if owner is not None:
            try: PRIVATE["process_custody"]=owner.finish()
            except BaseException as error:
                REPORT.update(status="failed",actual_darwin_capture_controls_qualified=False,
                              cleanup_error_type=type(error).__name__)
        if LAST_RESULT is not None:
            REPORT["controls"]={"tests_run":LAST_RESULT.testsRun,"started":list(LAST_RESULT.started),
                "completed":list(LAST_RESULT.actual),"failures":len(LAST_RESULT.failures),
                "errors":len(LAST_RESULT.errors),"skipped":len(LAST_RESULT.skipped),
                "expected_failures":len(LAST_RESULT.expectedFailures),
                "unexpected_successes":len(LAST_RESULT.unexpectedSuccesses)}
        if FIRED or INTERRUPTED or time.monotonic()>=WORK_END:
            REPORT.update(status="failed",actual_darwin_capture_controls_qualified=False)
        REPORT.update(deadline_fired=FIRED,interrupted=INTERRUPTED,
                      elapsed_seconds_before_receipt=time.monotonic()-START)
        signal.setitimer(signal.ITIMER_REAL,0)
        for s,handler in previous.items():signal.signal(s,handler)
        if CREATED:
            for filename in ("controls.stdout","controls.stderr"):
                path=OUT/filename
                if path.is_file():
                    need(path.stat().st_size<=2*1024**2,"bounded_control_log")
                    raw=path.read_bytes()
                    PRIVATE[filename]={"bytes":len(raw),"sha256":sha(raw)}
            PRIVATE["public_result"]=REPORT
            write_new(OUT/"receipt.private.json",(json.dumps(PRIVATE,sort_keys=True,indent=2)+"\n").encode())
            write_new(OUT/"result.public.json",(json.dumps(REPORT,sort_keys=True,indent=2)+"\n").encode())
        print(json.dumps(REPORT,sort_keys=True),flush=True)
    return 0 if REPORT["status"]=="passed" else 1

if __name__=="__main__":
    raise SystemExit(main())

