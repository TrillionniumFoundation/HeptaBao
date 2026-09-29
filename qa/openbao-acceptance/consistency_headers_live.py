#!/usr/bin/env python3
"""Pinned OpenBao 2.7 middleware comparison and actual candidate Raft prerequisites.

Fresh loopback fixtures only. Index metadata is never an authentication or replay
permit. Reports contain case IDs, booleans and status codes, never credentials.
"""
from __future__ import annotations
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from native_snapshot_ha_live import SaveCluster
from official_openbao_launcher import oracle_environment, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
from sys_leader_live import Endpoint, Official, Instance

VERSION = "2.7.0"
MOUNT = "consistency-data"
PATH = MOUNT + "/data/retained"


def encoded(value):
    return base64.b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()


VALID_HEADERS = (
    ("absent", []),
    ("empty_index", [("X-Vault-Index", "")]),
    ("null_index", [("X-Vault-Index", encoded(None))]),
    ("empty_object", [("X-Vault-Index", encoded({}))]),
    ("foreign_index", [("X-Vault-Index", encoded({"cluster":"foreign", "value":"opaque"}))]),
    ("unknown_field", [("X-Vault-Index", encoded({"unknown":[1,2]}))]),
    ("case_insensitive", [("X-Vault-Index", encoded({"CLUSTER":"foreign", "VALUE":"opaque"}))]),
    ("fail", [("X-Vault-Inconsistent", "fail")]),
    ("forward", [("X-Vault-Inconsistent", "forward-active-node")]),
    ("await", [("X-Vault-Inconsistent", "await-state")]),
    ("await_fail", [("X-Vault-Inconsistent", "await-state"),("X-Vault-Inconsistent", "fail")]),
    ("await_forward", [("X-Vault-Inconsistent", "await-state"),("X-Vault-Inconsistent", "forward-active-node")]),
)
INVALID_HEADERS = (
    ("bad_base64", [("X-Vault-Index", "invalid")]),
    ("missing_padding", [("X-Vault-Index", "e30")]),
    ("array", [("X-Vault-Index", encoded([]))]),
    ("string", [("X-Vault-Index", encoded("not-an-object"))]),
    ("number_field", [("X-Vault-Index", encoded({"cluster":7}))]),
    ("duplicate_index", [("X-Vault-Index", ""),("X-Vault-Index", "")]),
    ("empty_policy", [("X-Vault-Inconsistent", "")]),
    ("comma_policy", [("X-Vault-Inconsistent", "await-state, fail")]),
    ("duplicate_fail", [("X-Vault-Inconsistent", "fail"),("X-Vault-Inconsistent", "fail")]),
    ("forward_fail", [("X-Vault-Inconsistent", "forward-active-node"),("X-Vault-Inconsistent", "fail")]),
    ("duplicate_await", [("X-Vault-Inconsistent", "await-state"),("X-Vault-Inconsistent", "await-state")]),
    ("three_policies", [("X-Vault-Inconsistent", "await-state"),("X-Vault-Inconsistent", "fail"),("X-Vault-Inconsistent", "fail")]),
)
COMMON_REQUIRED = frozenset({"initialize","unseal","mount","write","finite_issue",
    "finite_rejected","finite_unchanged","write_rejected","write_absent","index_is_not_auth",
    "restart_unseal","restart_retained","complete"}
    | {"valid_"+name for name,_ in VALID_HEADERS}
    | {"invalid_"+name+"_"+route for name,_ in INVALID_HEADERS for route in ("logical","leader")})
HA_REQUIRED = frozenset({"bootstrap","write_index","forwarded_write_index","forwarded_write_once",
    "future_fail","future_write_fail","future_write_absent","await_fail","await_bounded",
    "future_forward","forward_index","future_forward_not_auth","wrapped_forward","unwrap_once",
    "unwrap_replay_denied","finite_issue","finite_rejected","finite_unchanged",
    "restart_unseal","restart_local_frontier","restart_read","step_down","successor",
    "post_handoff_read","partitioned_watermark_not_authority","healed_read","stopped","complete"})


def call(endpoint, method, path, token="", body=None, headers=()):
    raw = None if body is None else json.dumps(body).encode()
    connection = http.client.HTTPSConnection("127.0.0.1",endpoint.port,context=endpoint.context,timeout=8)
    try:
        connection.putrequest(method,"/v1/"+path,skip_host=True,skip_accept_encoding=True)
        connection.putheader("Host","localhost")
        connection.putheader("Connection","close")
        if token: connection.putheader("X-Vault-Token",token)
        if raw is not None:
            connection.putheader("Content-Type","application/json")
            connection.putheader("Content-Length",str(len(raw)))
        for name,value in headers: connection.putheader(name,value)
        connection.endheaders(raw)
        response=connection.getresponse(); payload=response.read(65537)
        if len(payload)>65536: raise FixtureError("oversize_response")
        return response.status, json.loads(payload) if payload else {}, dict((k.lower(),v) for k,v in response.getheaders())
    finally: connection.close()


class Trace:
    def __init__(self): self.checks=[];self.statuses=[]
    def check(self,name,condition):
        self.checks.append({"case":name,"passed":condition is True})
        if condition is not True: raise FixtureError(name)
    def request(self,name,endpoint,method,path,expected,token="",body=None,headers=()):
        status,value,metadata=call(endpoint,method,path,token,body,headers)
        self.statuses.append({"case":name,"status":status})
        self.check(name,status==expected)
        return value,metadata


class RestartableOfficial(Official):
    def start(self):
        self.log=(self.root/"server.log").open("ab")
        self.process=subprocess.Popen([str(self.binary),"server","-config="+str(self.root/"server.json")],
            stdout=self.log,stderr=self.log,env=oracle_environment(self.root))
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:
                status,value,_=call(self.endpoint,"GET","sys/health")
                if status in (501,503) and value.get("version")==VERSION:return
            except (OSError,http.client.HTTPException):pass
            time.sleep(.05)
        raise FixtureError("official_readiness")


def common(instance,endpoint,trace):
    value,_=trace.request("initialize",endpoint,"POST","sys/init",200,body={"secret_shares":1,"secret_threshold":1})
    token,key=value["root_token"],value["keys_base64"][0]
    trace.request("unseal",endpoint,"POST","sys/unseal",200,body={"key":key})
    trace.request("mount",endpoint,"POST","sys/mounts/"+MOUNT,204,token,{"type":"kv","options":{"version":"2"}})
    trace.request("write",endpoint,"POST",PATH,200,token,{"data":{"fixture":"retained"}})
    for name,headers in VALID_HEADERS:
        value,_=trace.request("valid_"+name,endpoint,"GET",PATH,200,token,headers=headers)
        if value.get("data",{}).get("data")!={"fixture":"retained"}:raise FixtureError("wrong_readback")
    for name,headers in INVALID_HEADERS:
        for kind,path in (("logical",PATH),("leader","sys/leader")):
            value,_=trace.request("invalid_"+name+"_"+kind,endpoint,"GET",path,400,token,headers=headers)
            if not value.get("errors") or any(value.get(k) for k in ("data","auth","wrap_info")):
                raise FixtureError("invalid_header_released_response")
    bad=[("X-Vault-Index","invalid")]
    value,_=trace.request("finite_issue",endpoint,"POST","auth/token/create",200,token,{"policies":["default"],"num_uses":2,"ttl":600})
    limited=value["auth"]["client_token"]
    trace.request("finite_rejected",endpoint,"GET","auth/token/lookup-self",400,limited,headers=bad)
    # Use the complete response for readback; never put it in evidence.
    status,value,_=call(endpoint,"POST","auth/token/lookup",token,{"token":limited})
    trace.check("finite_unchanged",status==200 and value.get("data",{}).get("num_uses")==2)
    trace.request("write_rejected",endpoint,"POST",MOUNT+"/data/rejected",400,token,{"data":{"fixture":"must-not-commit"}},bad)
    trace.request("write_absent",endpoint,"GET",MOUNT+"/data/rejected",404,token)
    trace.request("index_is_not_auth",endpoint,"GET",PATH,403,"synthetic-invalid",headers=VALID_HEADERS[4][1])
    instance.stop();instance.start()
    trace.request("restart_unseal",endpoint,"POST","sys/unseal",200,body={"key":key})
    value,_=trace.request("restart_retained",endpoint,"GET",PATH,200,token,headers=VALID_HEADERS[10][1])
    if value.get("data",{}).get("data")!={"fixture":"retained"}:raise FixtureError("restart_wrong_readback")
    trace.check("complete",True)


def response_index(headers,cluster_id):
    text=headers.get("x-vault-index","")
    value=json.loads(base64.b64decode(text,validate=True))
    if value.get("cluster")!=cluster_id or not isinstance(value.get("value"),str):raise FixtureError("index_identity")
    if not value["value"].startswith("heptabao-raft-v1:"):raise FixtureError("index_backend")
    suffix=value["value"].removeprefix("heptabao-raft-v1:")
    if not suffix.isascii() or not suffix.isdigit() or str(int(suffix))!=suffix or not 0<int(suffix)<=2**64-1:
        raise FixtureError("index_frontier")
    return text,int(suffix)


def candidate_ha(binary,root,t):
    cluster=SaveCluster(binary,root)
    try:
        cluster.bootstrap();leader=cluster.leader();t.check("bootstrap",True)
        eps={n.node_id:Endpoint(n.http_port,cluster.root/"ca.crt") for n in cluster.nodes}
        current=lambda n:eps[n.node_id]
        token=cluster.root_token;standby=next(n for n in cluster.nodes if n is not leader)
        path="secret/data/consistency-live"
        value,h=t.request("write_index",current(leader),"POST",path,200,token,{"data":{"fixture":"retained"},"options":{"cas":0}})
        index,_=response_index(h,cluster.cluster_id)
        value,h=t.request("forwarded_write_index",current(standby),"POST",path+"-forward",200,token,{"data":{"fixture":"forwarded"},"options":{"cas":0}})
        forwarded,index_number=response_index(h,cluster.cluster_id)
        status,value,_=call(current(leader),"GET",path+"-forward",token)
        t.check("forwarded_write_once",status==200 and value.get("data",{}).get("metadata",{}).get("version")==1)
        future=[("X-Vault-Index",encoded({"cluster":cluster.cluster_id,"value":"heptabao-raft-v1:"+str(2**64-1)}))]
        t.request("future_fail",current(standby),"GET",path,429,token,headers=future)
        t.request("future_write_fail",current(standby),"POST",path+"-absent",429,token,{"data":{"fixture":"rejected"}},future)
        t.request("future_write_absent",current(leader),"GET",path+"-absent",404,token)
        start=time.monotonic()
        t.request("await_fail",current(standby),"GET",path,429,token,headers=future+[("X-Vault-Inconsistent","await-state")])
        t.check("await_bounded",.020<=time.monotonic()-start<2)
        forward=future+[("X-Vault-Inconsistent","forward-active-node")]
        value,h=t.request("future_forward",current(standby),"GET",path,200,token,headers=forward)
        response_index(h,cluster.cluster_id);t.check("forward_index",value.get("data",{}).get("data")=={"fixture":"retained"})
        t.request("future_forward_not_auth",current(standby),"GET",path,403,"synthetic-invalid",headers=forward)
        value,_=t.request("wrapped_forward",current(standby),"POST","sys/wrapping/wrap",200,token,{"fixture":"wrapped"},forward+[("X-Vault-Wrap-TTL","60s")])
        wrapping=value["wrap_info"]["token"]
        if value.get("data"):raise FixtureError("wrapping_disclosed")
        value,_=t.request("unwrap_once",current(standby),"POST","sys/wrapping/unwrap",200,wrapping,{})
        if value.get("data")!={"fixture":"wrapped"}:raise FixtureError("wrapped_value_changed")
        t.request("unwrap_replay_denied",current(leader),"POST","sys/wrapping/unwrap",403,wrapping,{})
        value,_=t.request("finite_issue",current(leader),"POST","auth/token/create",200,token,{"policies":["default"],"num_uses":2,"ttl":600})
        limited=value["auth"]["client_token"]
        t.request("finite_rejected",current(standby),"GET","auth/token/lookup-self",429,limited,headers=future)
        status,value,_=call(current(leader),"POST","auth/token/lookup",token,{"token":limited})
        t.check("finite_unchanged",status==200 and value.get("data",{}).get("num_uses")==2)
        standby.stop();standby.start()
        t.request("restart_unseal",current(standby),"POST","sys/unseal",200,body={"key":cluster.unseal_key})
        deadline=time.monotonic()+30
        while True:
            status,value,_=call(current(standby),"GET","sys/leader")
            if status==200 and value.get("raft_applied_index",0)>=index_number:break
            if time.monotonic()>=deadline:raise FixtureError("restart_frontier_timeout")
            time.sleep(.05)
        t.check("restart_local_frontier",True)
        t.request("restart_read",current(standby),"GET",path+"-forward",200,token,headers=[("X-Vault-Index",forwarded)])
        t.request("step_down",current(leader),"POST","sys/step-down",204,token,{})
        successor=cluster.leader();t.check("successor",successor is not leader)
        t.request("post_handoff_read",current(successor),"GET",path,200,token,headers=[("X-Vault-Index",index)])
        for link in cluster.links.values():link.set_blocked(True)
        time.sleep(3)
        t.request("partitioned_watermark_not_authority",current(successor),"GET",path,503,token,headers=[("X-Vault-Index",index)])
        cluster._heal();successor=cluster.leader()
        t.request("healed_read",current(successor),"GET",path,200,token,headers=[("X-Vault-Index",index)])
    finally:cluster.close()
    t.check("stopped",all(n.process is None for n in cluster.nodes));t.check("complete",True)


def main():
    os.umask(0o077)
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary",required=True,type=Path)
    parser.add_argument("--oracle-version",choices=(VERSION,),default=VERSION)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args();binary=args.binary.resolve(strict=True)
    output=args.output.absolute();admitted=admit_output(output)
    bao=verify_inputs(version=args.oracle_version);before=source_identity(ROOT,binary)
    work=Path(tempfile.mkdtemp(prefix="consistency270-",dir=output.parent))
    traces={};failures={};oracle_hash=file_hash(bao)
    def interrupted(signum,frame):raise FixtureError("interrupted")
    handlers={kind:signal.signal(kind,interrupted) for kind in (signal.SIGINT,signal.SIGTERM)}
    try:
        for side in ("candidate","official_pebbledb","official_raft"):
            trace=Trace();traces[side]=trace
            instance=(Instance(binary,work/side) if side=="candidate" else RestartableOfficial(bao,work/side,side=="official_raft"))
            endpoint=Endpoint(instance.port,instance.root/"ca.crt") if side=="candidate" else instance.endpoint
            try:
                instance.start();common(instance,endpoint,trace)
            except Exception as error: failures[side]=str(error) if isinstance(error,FixtureError) else type(error).__name__
            finally:instance.stop()
            if not complete_checks(trace.checks,len(COMMON_REQUIRED),required_cases=COMMON_REQUIRED):failures.setdefault(side,"incomplete_trace")
        trace=Trace();traces["candidate_ha"]=trace
        try:candidate_ha(binary,work/"candidate-ha",trace)
        except Exception as error:failures["candidate_ha"]=str(error) if isinstance(error,FixtureError) else type(error).__name__
        if not complete_checks(trace.checks,len(HA_REQUIRED),required_cases=HA_REQUIRED):failures.setdefault("candidate_ha","incomplete_trace")
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=source_identity(ROOT,binary)
    if before!=after or before["source_dirty"] or file_hash(bao)!=oracle_hash:failures["custody"]="source_binary_or_oracle_changed"
    matched=traces["candidate"].statuses==traces["official_pebbledb"].statuses==traces["official_raft"].statuses
    if not matched:failures["comparison"]="status_traces_differ"
    report={"schema":"heptabao.consistency270-live.v1","status":"failed" if failures else "passed",
        "failures":failures,"checks":{k:v.checks for k,v in traces.items()},"status_traces":{k:v.statuses for k,v in traces.items()},
        "source_identity":before,"source_identity_after":after,"oracle_version":VERSION,
        "oracle_binary_sha256":oracle_hash,"oracle_archive_sha256":file_hash(Path(os.environ["HB_ORACLE_ARCHIVE"])),
        "runner_sha256":file_hash(Path(__file__)),"common_status_traces_match":matched,
        "retained_failure_work_dir":str(work) if failures else None,
        "full_openbao_compatibility":False,"independent_qualification":False,"production_authority":False}
    if admit_output(output)!=admitted:raise ValueError("report_parent_changed")
    private_write(output,report,replace=False)
    if not failures:shutil.rmtree(work)
    print(json.dumps({"status":report["status"],"failures":failures,"checks":{k:len(v.checks) for k,v in traces.items()}}))
    return int(bool(failures))


if __name__=="__main__":raise SystemExit(main())
