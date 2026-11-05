"""Pure selected-method checks; no target file or locator main is touched."""
import ast
import copy
import hashlib
import json
import os as real_os
from pathlib import Path
import stat
import types

source=Path(__file__).with_name("artifact_alias_observer_r1.py").read_text()
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
    assert result[0]==name and iterator.close_calls==1 and observation.iterator_closed
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
    assert iterator.close_calls==1 and observation.iterator_closed is False
trial("iterator-close-failure-not-complete",iterator_failure)
def close_failure():
    calls=[]
    def close(fd):
        calls.append(fd)
        if fd==2:raise OSError(5,"synthetic-close")
    ns["os"]=types.SimpleNamespace(close=close)
    observation=Observation();observation.fds=[1,2,3];observation.opened=3
    observation.close_all_once();observation.close_all_once()
    assert calls==[3,2,1] and observation.closed==2 and observation.close_errors==1
    assert observation.fds==[]
trial("failed-close-is-once-and-not-clean",close_failure)
print(json.dumps({"schema":"heptabao.qa-r2.artifact-alias.pure-components.v1",
 "source_bytes":len(source.encode()),"source_sha256":hashlib.sha256(source.encode()).hexdigest(),
 "status":"passed-source-components-only","cases":rows,"case_count":len(rows),
 "artifact_or_target_reads":0,"main_calls":0,"real_os_alias_reads":0,
 "scope":"selected methods with synthetic os metadata; no actual alias claim"},
 indent=2,sort_keys=True))

