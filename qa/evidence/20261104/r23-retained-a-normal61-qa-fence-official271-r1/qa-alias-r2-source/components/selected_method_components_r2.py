"""Pure selected-method checks; no target file or locator main is touched."""
import ast
import copy
import hashlib
import json
import os as real_os
from pathlib import Path
import stat
import types

source=Path(__file__).with_name("artifact_alias_observer_r2.py").read_text()
parsed=ast.parse(source)
compile(parsed,"<alias-observer>","exec")
ns={"__name__":"definitions_only"}
exec(compile(ast.Module(body=[n for n in parsed.body if not isinstance(n,ast.If)],
                        type_ignores=[]),"<selected-alias-observer>","exec"),ns)
Observation=ns["Observation"]; Refused=ns["Refused"]
base=types.SimpleNamespace(st_dev=66306,st_ino=31633993,st_uid=1000,st_gid=1000,
    st_mode=stat.S_IFREG|0o700,st_nlink=2,st_size=4616576,
    st_mtime_ns=1793869496670294192,st_ctime_ns=1793869496695294129)
captured=ns["full_id"](base)
name="heptabao_native_h2_qa-0123456789abcdef"
rows=[]
class Entries:
    def __init__(self,names,fail_close=False):
        self.names=names;self.close_calls=0;self.fail_close=fail_close
    def __iter__(self):
        return iter([types.SimpleNamespace(name=n) for n in self.names])
    def close(self):
        self.close_calls+=1
        if self.fail_close:raise OSError(5,"synthetic-close")

def trial(label,fn,code=None):
    try:
        fn()
    except Refused as exc:
        assert code==str(exc),(label,str(exc))
    else:assert code is None,label
    rows.append({"name":label,"passed":True})

def finder(names,values,expected=None,fail_close=False):
    iterator=Entries(names,fail_close); calls=[]
    def lstat(n,**kwargs):
        calls.append(n);return values[n]
    ns["os"]=types.SimpleNamespace(scandir=lambda _fd:iterator,fsencode=real_os.fsencode,stat=lstat)
    observation=Observation()
    if expected:
        try:observation.find_alias(99,captured)
        except Refused as exc:
            assert str(exc)==expected
        else:raise AssertionError("refusal missing")
        assert iterator.close_calls==1
        return
    result=observation.find_alias(99,captured)
    assert result[0]==name and iterator.close_calls==1 and observation.scandir_closed
    return calls

trial("one-exact-alias",lambda:finder([name],{name:base}))
trial("missing-alias",lambda:finder(["other"],{},expected="link_count_not_fully_accounted_for"))
trial("two-alias-names-refused",lambda:finder(
    [name,"heptabao_native_h2_qa-fedcba9876543210"],
    {name:base,"heptabao_native_h2_qa-fedcba9876543210":base},
    expected="link_count_not_fully_accounted_for"))
drift=copy.copy(base);drift.st_ctime_ns+=1
trial("same-inode-full9-drift-refused",lambda:finder([name],{name:drift},
    expected="alias_census_identity"))
other=copy.copy(base);other.st_ino+=1
trial("unselected-inode-not-opened",lambda:finder(
    [name,"heptabao_native_h2_qa-fedcba9876543210","secret.txt"],
    {name:base,"heptabao_native_h2_qa-fedcba9876543210":other}))
def expired():
    seen=[]
    ns["os"]=types.SimpleNamespace(scandir=lambda _fd:seen.append(True))
    observation=Observation();observation.until=0
    try:observation.find_alias(99,captured)
    except Refused as exc:assert str(exc)=="original_read_deadline"
    else:raise AssertionError("deadline accepted")
    assert seen==[]
trial("expired-before-scandir",expired)
def iterator_failure():
    iterator=Entries([name],True)
    ns["os"]=types.SimpleNamespace(scandir=lambda _fd:iterator,
        fsencode=real_os.fsencode,stat=lambda *_a,**_kw:base)
    observation=Observation()
    try:observation.find_alias(99,captured)
    except OSError:pass
    else:raise AssertionError("iterator close failure accepted")
    observation.close_all_once();observation.close_all_once()
    assert iterator.close_calls==1 and observation.scandir_closed is False
    assert observation.scandir_close_attempted and not observation.closures_proven()
trial("iterator-close-failure-not-complete",iterator_failure)
def close_failure():
    calls=[]
    def close(fd):
        calls.append(fd)
        if fd==2:raise OSError(5,"synthetic-close")
    ns["os"]=types.SimpleNamespace(close=close)
    observation=Observation()
    for fd in (1,2,3):
        row={"ordinal":fd,"role":"synthetic","close_attempted":False,
             "closed":False,"close_errno":None,"close_error":None}
        observation.fds[fd]=row;observation.fd_rows.append(row)
    observation.opened=3
    observation.close_all_once();observation.close_all_once()
    assert calls==[3,2,1] and observation.closed==2 and observation.close_failures==1
    assert observation.fds=={} and not observation.closures_proven()
trial("failed-close-is-once-and-not-clean",close_failure)
# Additional cases are restricted to cancellation, registration and read bounds.
Signals=ns["Signals"];Cancelled=ns["Cancelled"]
def caught_cancel(operation):
    try:operation()
    except Cancelled:pass
    else:raise AssertionError("cancellation missing")

def open_cancel_registered():
    signals=Signals();signals.protected=1;observation=Observation(signals)
    closed=[]
    def opened(*_a,**_kw):
        signals.handler(15,None);return 71
    ns["os"]=types.SimpleNamespace(open=opened,close=closed.append)
    assert observation.open_fd("synthetic",0,"synthetic")==71
    assert observation.opened==1 and 71 in observation.fds
    caught_cancel(observation.remaining)
    observation.close_all_once();observation.close_all_once()
    assert closed==[71] and observation.closures_proven() and signals.pending==15
    assert signals.protected==1
trial("signal-after-open-registers-before-cancel-and-closes-once",open_cancel_registered)

def open_registration_unknown():
    class RejectRegistration(dict):
        def __setitem__(self,_key,_value):raise MemoryError("synthetic")
    observation=Observation();observation.fds=RejectRegistration()
    closed=[]
    ns["os"]=types.SimpleNamespace(open=lambda *_a,**_kw:72,close=closed.append)
    try:observation.open_fd("synthetic",0,"synthetic")
    except MemoryError:pass
    else:raise AssertionError("registration failure accepted")
    observation.close_all_once()
    assert observation.open_registration_unknown and not observation.closures_proven()
    assert closed==[] and observation.opened==observation.closed==0
trial("open-registration-exception-retains-unknown-not-fake-closed",open_registration_unknown)

def scandir_cancel_registered():
    signals=Signals();signals.protected=1;observation=Observation(signals)
    iterator=Entries([name])
    def scan(_fd):signals.handler(15,None);return iterator
    ns["os"]=types.SimpleNamespace(scandir=scan,fsencode=real_os.fsencode)
    caught_cancel(lambda:observation.find_alias(99,captured))
    observation.close_all_once();observation.close_all_once()
    assert iterator.close_calls==1 and observation.scandir_created
    assert observation.scandir_closed and not observation.scandir_open_unknown
    assert observation.closures_proven() and signals.pending==15
trial("signal-after-scandir-registers-and-closes-once",scandir_cancel_registered)

def scandir_acquisition_unknown():
    def scan(_fd):raise MemoryError("synthetic")
    ns["os"]=types.SimpleNamespace(scandir=scan)
    observation=Observation()
    try:observation.find_alias(99,captured)
    except MemoryError:pass
    else:raise AssertionError("scandir failure accepted")
    observation.close_all_once()
    assert observation.scandir_open_unknown and not observation.scandir_created
    assert not observation.scandir_close_attempted and not observation.closures_proven()
trial("scandir-acquisition-exception-retains-unknown",scandir_acquisition_unknown)

def cleanup_signals():
    signals=Signals();signals.protected=1;observation=Observation(signals)
    available=iter((81,82,83));closed=[]
    ns["os"]=types.SimpleNamespace(open=lambda *_a,**_kw:next(available))
    for _ in range(3):observation.open_fd("synthetic",0,"synthetic")
    def close(fd):
        assert fd not in observation.fds
        signals.handler(15,None);closed.append(fd)
    ns["os"]=types.SimpleNamespace(close=close)
    signals.handler(2,None)  # pending before entry to finally cleanup
    observation.close_all_once();observation.close_all_once()
    assert closed==[83,82,81] and observation.closures_proven()
    assert signals.pending==2 and signals.protected==1
trial("pending-and-repeated-signal-cannot-escape-cleanup-or-repeat-close",cleanup_signals)

limit_names=("EXPECTED_BYTES","EXPECTED_SHA256","MAX_BODY_BYTES", 
             "MAX_EOF_PROBE_BYTES","MAX_RETURNED_BYTES")
limits={key:ns[key] for key in limit_names}
assert limits["MAX_BODY_BYTES"]==9233152
assert limits["MAX_EOF_PROBE_BYTES"]==2 and limits["MAX_RETURNED_BYTES"]==9233154

def with_small_body(operation):
    ns.update(EXPECTED_BYTES=2,EXPECTED_SHA256=hashlib.sha256(b"ok").hexdigest(),
              MAX_BODY_BYTES=4,MAX_EOF_PROBE_BYTES=2,MAX_RETURNED_BYTES=6)
    try:operation()
    finally:ns.update(limits)

def hash_synthetic(observation,chunks,on_read=None):
    pending=list(chunks);calls=[]
    def read(_fd,count):
        calls.append(count)
        if on_read:on_read(observation,count)
        assert pending,"unexpected extra read"
        return pending.pop(0)
    ns["os"]=types.SimpleNamespace(read=read,fstat=lambda _fd:base,
        stat=lambda *_a,**_kw:base)
    return calls,pending

def two_copies_and_eof():
    observation=Observation();calls,pending=hash_synthetic(observation,[b"ok",b"",b"ok",b""])
    for _ in range(2):
        assert observation.hash_file(99,98,"fixed",captured)==hashlib.sha256(b"ok").hexdigest()
    assert calls==[2,1,2,1] and pending==[]
    assert observation.body_bytes_read==observation.bytes_read==4
    assert observation.eof_bytes_read==0 and observation.eof_probe_calls==2
trial("two-bodies-and-two-eof-probes-have-separate-fixed-limits",lambda:with_small_body(two_copies_and_eof))

def trailing_eof_counted():
    observation=Observation();calls,_=hash_synthetic(observation,[b"ok",b"x"])
    try:observation.hash_file(99,98,"fixed",captured)
    except Refused as exc:assert str(exc)=="artifact_trailing_bytes"
    else:raise AssertionError("tail accepted")
    assert calls==[2,1] and observation.body_bytes_read==2
    assert observation.eof_bytes_read==1 and observation.bytes_read==3
trial("unexpected-eof-byte-is-counted-before-refusal",lambda:with_small_body(trailing_eof_counted))

def oversized_body_counted():
    observation=Observation();calls,_=hash_synthetic(observation,[b"bad"])
    try:observation.hash_file(99,98,"fixed",captured)
    except Refused as exc:assert str(exc)=="artifact_short_or_oversized_read"
    else:raise AssertionError("oversized read accepted")
    assert calls==[2] and observation.bytes_read==observation.body_bytes_read==3
    assert observation.eof_probe_calls==0
trial("returned-body-bytes-counted-before-invalid-length-refusal",lambda:with_small_body(oversized_body_counted))

def eof_remaining_admission():
    observation=Observation()
    def exhaust(row,_count):row.eof_probe_calls=2
    calls,pending=hash_synthetic(observation,[b"ok"],exhaust)
    try:observation.hash_file(99,98,"fixed",captured)
    except Refused as exc:assert str(exc)=="eof_probe_bytes_admission"
    else:raise AssertionError("exhausted eof budget accepted")
    assert calls==[2] and pending==[] and observation.bytes_read==2
trial("exhausted-eof-allowance-refuses-before-next-read",lambda:with_small_body(eof_remaining_admission))

def read_cancel_accounted():
    signals=Signals();signals.protected=1;observation=Observation(signals)
    def cancel(_row,_count):signals.handler(15,None)
    calls,pending=hash_synthetic(observation,[b"ok"],cancel)
    caught_cancel(lambda:observation.hash_file(99,98,"fixed",captured))
    assert calls==[2] and pending==[]
    assert observation.bytes_read==observation.body_bytes_read==2
    assert observation.eof_probe_calls==0 and signals.protected==1
trial("cancel-after-read-still-accounts-returned-bytes",lambda:with_small_body(read_cancel_accounted))

print(json.dumps({"schema":"heptabao.qa-r2.artifact-alias.pure-components.v2",
 "source_bytes":len(source.encode()),"source_sha256":hashlib.sha256(source.encode()).hexdigest(),
 "status":"passed-source-components-only","cases":rows,"case_count":len(rows),
 "retained_original_case_names":8,"added_targeted_case_names":10,
 "artifact_or_target_reads":0,"main_calls":0,"real_os_alias_reads":0,
 "real_signal_install_or_delivery":0,
 "scope":"selected methods with synthetic os metadata/signals; no actual alias claim"},
 indent=2,sort_keys=True))
