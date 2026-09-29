#!/usr/bin/env python3
"""Real Python client against pinned OpenBao 2.7 services and existing Raft lifecycle.

Fresh private loopback fixtures only; reports never contain bearer or key data.
Local input refusals are not relabeled as HTTP observations.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile

from consistency_headers_live import (Trace, RestartableOfficial, Instance, Endpoint,
    VALID_HEADERS, INVALID_HEADERS, HA_REQUIRED, candidate_ha, VERSION,
    REQUEST_TIMEOUT, INITIALIZATION_TIMEOUT)
from core_isolation import ROOT, file_hash
from bao_http import SafeArgumentParser, private_write
from ha_destructive import FixtureError
from official_openbao_launcher import verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
sys.path.insert(0, str(ROOT/'clients/python'))
from heptabao.transport import Client, BaoError

COMMON = frozenset({'initialize','unseal','mount','write','index_not_auth','restart_unseal',
    'restart_read','finite_issue','finite_unchanged','stopped','complete'} |
    {'valid_'+name for name,_ in VALID_HEADERS} |
    {'local_reject_'+name for name,_ in INVALID_HEADERS})

class ClientTrace(Trace):
    def __init__(self, ca):
        super().__init__(); self.ca = ca

    def invoke(self, endpoint, method, path, token='', body=None, headers=(), timeout=REQUEST_TIMEOUT):
        indices=[]; behaviors=[]; wraps=[]
        for name,value in headers:
            name=name.lower()
            if name=='x-vault-index': indices.append(value)
            elif name=='x-vault-inconsistent': behaviors.append(value)
            elif name=='x-vault-wrap-ttl': wraps.append(value)
            else: raise FixtureError('unexpected_client_header')
        if len(indices)>1 or len(wraps)>1:
            raise BaoError('duplicate_consistency_index')
        client=Client(endpoint.address,str(self.ca),token or 'synthetic-unauthenticated',timeout=timeout)
        return client.request(method,'/v1/'+path,body,token=token,
            consistency_index=indices[0] if indices else None,
            inconsistent=tuple(behaviors),wrap_ttl=wraps[0] if wraps else None)

    def request(self,name,endpoint,method,path,expected,token='',body=None,headers=(),*,timeout=REQUEST_TIMEOUT):
        response=self.invoke(endpoint,method,path,token,body,headers,timeout)
        self.statuses.append({'case':name,'status':response.status})
        self.check(name,response.status==expected)
        if not response.consistency_valid: raise FixtureError('invalid_response_index')
        if response.status==429 and response.retry_after_seconds!=1:
            raise FixtureError('missing_retry_after')
        metadata={} if response.consistency_index is None else {'x-vault-index':response.consistency_index}
        return response.body,metadata


def common(instance,endpoint,t):
    value,_=t.request('initialize',endpoint,'POST','sys/init',200,
        body={'secret_shares':1,'secret_threshold':1},timeout=INITIALIZATION_TIMEOUT)
    token,key=value['root_token'],value['keys_base64'][0]
    t.request('unseal',endpoint,'POST','sys/unseal',200,body={'key':key})
    t.request('mount',endpoint,'POST','sys/mounts/client-consistency',204,token,
              {'type':'kv','options':{'version':'2'}})
    path='client-consistency/data/retained'
    t.request('write',endpoint,'POST',path,200,token,{'data':{'fixture':'retained'},'options':{'cas':0}})
    for name,headers in VALID_HEADERS:
        value,_=t.request('valid_'+name,endpoint,'GET',path,200,token,headers=headers)
        if value.get('data',{}).get('data')!={'fixture':'retained'}:
            raise FixtureError('incorrect_readback')
    value,_=t.request('finite_issue',endpoint,'POST','auth/token/create',200,token,
        {'policies':['default'],'num_uses':2,'ttl':600})
    limited=value['auth']['client_token']
    for name,headers in INVALID_HEADERS:
        try: t.invoke(endpoint,'GET','auth/token/lookup-self',limited,headers=headers)
        except BaoError as error:
            if error.code not in ('duplicate_consistency_index','invalid_consistency_index','invalid_consistency_behavior'):
                raise FixtureError('unexpected_client_failure') from None
            t.check('local_reject_'+name,True)
        else: t.check('local_reject_'+name,False)
    value,_=t.request('finite_unchanged',endpoint,'POST','auth/token/lookup',200,token,{'token':limited})
    if value.get('data',{}).get('num_uses')!=2: raise FixtureError('finite_token_consumed')
    t.request('index_not_auth',endpoint,'GET',path,403,'synthetic-invalid',headers=VALID_HEADERS[4][1])
    instance.stop();instance.start()
    t.request('restart_unseal',endpoint,'POST','sys/unseal',200,body={'key':key})
    value,_=t.request('restart_read',endpoint,'GET',path,200,token,headers=VALID_HEADERS[10][1])
    if value.get('data',{}).get('data')!={'fixture':'retained'}: raise FixtureError('restart_readback')


def main():
    os.umask(0o077)
    p=SafeArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True,type=Path)
    p.add_argument('--oracle-version',choices=(VERSION,),default=VERSION)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args(); binary=args.binary.resolve(strict=True)
    output=args.output.absolute(); admitted=admit_output(output)
    bao=verify_inputs(version=VERSION);before=source_identity(ROOT,binary)
    work=Path(tempfile.mkdtemp(prefix='client-consistency270-',dir=output.parent))
    traces={}; failures={}; oracle_hash=file_hash(bao)
    def interrupted(signum,frame): raise FixtureError('interrupted')
    handlers={k:signal.signal(k,interrupted) for k in (signal.SIGINT,signal.SIGTERM)}
    try:
        for side in ('candidate','official_pebbledb','official_raft'):
            t=ClientTrace(work/side/'ca.crt');traces[side]=t;instance=None
            try:
                instance=(Instance(binary,work/side) if side=='candidate' else
                          RestartableOfficial(bao,work/side,side=='official_raft'))
                endpoint=Endpoint(instance.port,instance.root/'ca.crt') if side=='candidate' else instance.endpoint
                instance.start();common(instance,endpoint,t)
            except Exception as error: failures[side]=str(error) if isinstance(error,FixtureError) else type(error).__name__
            finally:
                if instance is not None: instance.stop()
            stopped=instance is not None and (instance.process is None or instance.process.poll() is not None)
            t.checks.append({'case':'stopped','passed':stopped})
            t.checks.append({'case':'complete','passed':side not in failures and stopped})
            if not complete_checks(t.checks,len(COMMON),required_cases=COMMON):failures.setdefault(side,'incomplete_trace')
        t=ClientTrace(work/'candidate-ha'/'ca.crt');traces['candidate_ha']=t
        try: candidate_ha(binary,work/'candidate-ha',t)
        except Exception as error: failures['candidate_ha']=str(error) if isinstance(error,FixtureError) else type(error).__name__
        if not complete_checks(t.checks,len(HA_REQUIRED),required_cases=HA_REQUIRED):failures.setdefault('candidate_ha','incomplete_trace')
    finally:
        for k,h in handlers.items(): signal.signal(k,h)
    after=source_identity(ROOT,binary)
    if before!=after or before['source_dirty'] or file_hash(bao)!=oracle_hash:failures['custody']='source_or_binary_changed'
    matched=traces['candidate'].statuses==traces['official_pebbledb'].statuses==traces['official_raft'].statuses
    if not matched: failures['comparison']='status_traces_differ'
    report={'schema':'heptabao.python-client-consistency270.v1','status':'failed' if failures else 'passed',
        'failures':failures,'checks':{k:v.checks for k,v in traces.items()},
        'status_traces':{k:v.statuses for k,v in traces.items()},'source_identity':before,'source_identity_after':after,
        'oracle_version':VERSION,'oracle_binary_sha256':oracle_hash,
        'oracle_archive_sha256':file_hash(Path(os.environ['HB_ORACLE_ARCHIVE'])),
        'runner_sha256':file_hash(Path(__file__)),'status_traces_match':matched,
        'local_refusals_are_not_http_observations':True,'retained_failure_work_dir':str(work) if failures else None,
        'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failures:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'failures':failures,'checks':{k:len(v.checks) for k,v in traces.items()}}))
    return int(bool(failures))

if __name__=='__main__': raise SystemExit(main())
