#!/usr/bin/env python3
import contextlib, errno, json, os, select, socket, sqlite3, sys, time
from pathlib import Path
START=time.monotonic()
ROOT=Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r1")
sys.path.insert(0,str(ROOT/"qa"))
import authbus_current_auth_wal as auth
case=sys.argv[1]
assert case in auth.CASES
until=float(sys.argv[2])
live=ROOT/"cases"/case/"live"
source=live/"agents/main/agent/openclaw-agent.sqlite"
report={"schema":"heptabao.authbus-auth-wal-owned-case.r1","case":case,"ok":False,
        "productionInputsRead":False,"providerCalled":False,"refreshDispatched":False,
        "credentialValuesOrDigestsIncluded":False,"kernelDenials":[]}
def require(condition,code):
    if not condition:raise RuntimeError(code)
try:
    require(time.monotonic()<until,"original_child_deadline")
    for name,path,flags in (
        ("main_write",source,os.O_WRONLY),
        ("wal_write",Path(str(source)+"-wal"),os.O_WRONLY),
        ("sidecar_create",Path(str(source)+"-journal.probe"),os.O_WRONLY|os.O_CREAT|os.O_EXCL)):
        try:
            fd=os.open(path,flags,0o600)
        except OSError as error:
            require(error.errno in (errno.EPERM,errno.EACCES),"kernel_write_refusal_required")
            report["kernelDenials"].append({"case":name,"denied":True,"errno":error.errno})
        else:
            os.close(fd);raise RuntimeError("kernel_write_not_denied")
    sock=None
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(0.25)
        sock.connect(("127.0.0.1",9))
    except OSError as error:
        require(error.errno in (errno.EPERM,errno.EACCES),"kernel_network_refusal_required")
        report["kernelDenials"].append({"case":"loopback_connect","denied":True,"errno":error.errno})
    else:raise RuntimeError("kernel_network_not_denied")
    finally:
        if sock is not None:sock.close()
    inputs=auth.AuthInputs(until=until,critical=contextlib.nullcontext,cancelled=lambda:False,
                          live=live,synthetic=True)
    hook=None;denied=[]
    if case in ("A03","A05"):
        def hook(query_until,connection):
            print("AUTH_WAL_READ_BARRIER",flush=True)
            left=min(query_until,until)-time.monotonic()
            require(left>0 and bool(select.select([sys.stdin.buffer],[],[],left)[0]),
                    "bounded_original_barrier_reply")
            require(os.read(sys.stdin.fileno(),1)==b"1","one_barrier_reply")
    elif case=="A07":
        def hook(query_until,connection):
            for label,sql in (
                ("write","UPDATE auth_profile_store SET updated_at=9 WHERE store_key='primary'"),
                ("other_table","SELECT secret FROM unrelated_credentials"),
                ("attach","ATTACH DATABASE ':memory:' AS unapproved")):
                try:inputs.execute(connection,sql,until=query_until,label="denied-"+label)
                except sqlite3.DatabaseError as error:
                    require(getattr(error,"sqlite_errorcode",None)==sqlite3.SQLITE_AUTH,
                            "authorizer_exact_auth_denial")
                    denied.append(label)
                else:raise RuntimeError("authorizer_operation_admitted")
    requested=["not-authorized"] if case=="A04" else ["selected"]
    value,public=auth.attempt_auth(inputs,agent="main",authorized_profiles=["selected"],
                                   requested_profiles=requested,after_read=hook)
    report["capture"]=public
    expected_success=case in ("A01","A02","A07")
    report["expectedSuccess"]=expected_success
    require(public["allOwnedDescriptorsClosed"] and not public["closeErrors"],
            "all_original_reader_resources_closed")
    if expected_success:
        require(public["ok"] and value is not None,"expected_auth_capture_success")
        require(set(value["profiles"])=={"selected"},"only_registered_profile_returned")
        require(value["profiles"]["selected"]["access"]=="fixture-committed",
                "committed_wal_generation_returned")
        require(value["profiles"]["selected"]["access"]!="fixture-uncommitted",
                "uncommitted_generation_not_returned")
        report["registeredCommittedGenerationMatched"]=True
        report["unselectedAndUncommittedValuesAbsent"]=True
    else:
        require(not public["ok"] and value is None and public["capturedProfileCount"]==0,
                "refused_capture_publishes_no_value")
        code=(public.get("error") or {}).get("code")
        expected={
            "A03":{"registry_wal_full_leaf_changed","registry_wal_full_parent_changed","current_input_fd_name_or_metadata_changed"},
            "A04":{"profile_not_authorized"},
            "A05":{"registry_wal_full_leaf_changed","current_input_fd_name_or_metadata_changed"},
            "A06":{"auth_existing_shm_required"},
            "A08":{"ambiguous_duplicate_json_key"},
            "A09":{"current_input_custody"},
        }
        if case in expected:require(code in expected[case],"exact_expected_capture_refusal")
        if case=="A10":
            require((public.get("error") or {}).get("sqliteName")=="SQLITE_TOOBIG",
                    "actual_sqlite_length_bound_refusal")
        if case=="A04":require(public["connectionAttemptCount"]==0,"unauthorized_before_connection")
    if case=="A07":
        require(denied==["write","other_table","attach"],"all_authorizer_refusals")
        report["sqlDenials"]=denied
    require(time.monotonic()<until,"original_child_deadline_after_closure")
    report["ok"]=True
except BaseException as error:
    report["errorType"]=type(error).__name__
    if isinstance(error,RuntimeError):report["errorCode"]=str(error)
finally:
    report["elapsedSeconds"]=round(time.monotonic()-START,6)
    print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report["ok"] else 1)
