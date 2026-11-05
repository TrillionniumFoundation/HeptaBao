#!/usr/bin/env python3
"""Compare the scoped native userpass/Token API batch contract with OpenBao2.6.2."""
from __future__ import annotations
import json, os, re, shutil, tempfile
from pathlib import Path
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files
import userpass_batch_contract as contract

BOOL_FIELDS=frozenset({'auth_present','wrapper_present','accessor_present','bearer_present','renewable','orphan',
    'canonical_metadata','entity_present','lookup_renewable','lookup_orphan','lookup_accessor_present',
    'lookup_canonical_metadata','lease_positive','ttl_positive','errors_present','observed'} |
    {p+'_le_'+str(n) for p in ('lease','ttl') for n in (20,30,75,120,300,600)})
INT_FIELDS=frozenset({'status','token_ttl','token_max_ttl','token_period','token_num_uses',
    'token_explicit_max_ttl','num_uses','explicit_max_ttl','period'})
STR_FIELDS=frozenset({'auth_type','lookup_type','configured_type','error_kind'})

def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    names=[]
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('case'),str) or not re.fullmatch('[a-z0-9_.]{1,140}',row['case']):return False
        names.append(row['case'])
        for key,value in row.items():
            if key=='case':continue
            if key in BOOL_FIELDS:
                if type(value) is not bool:return False
            elif key in INT_FIELDS:
                if type(value) is not int or value<0 or key=='status' and not 100<=value<=599:return False
            elif key in STR_FIELDS:
                allowed=set(contract.ERRORS.values())|{'other','none'} if key=='error_kind' else contract.TYPES|{'other'}
                if not isinstance(value,str) or value not in allowed:return False
            else:return False
        if row['case']!='complete' and 'status' not in row:return False
    return len(names)==len(set(names)) and contract.REQUIRED_CASES<=set(names) and rows[-1]=={'case':'complete','observed':True}

def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--build-source-commit')
    parser.add_argument('--expected-binary-sha256')
    parser.add_argument('--oracle-only',action='store_true')
    parser.add_argument('--work-parent',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not args.oracle_only and (args.binary is None or not re.fullmatch('[0-9a-f]{40}',args.build_source_commit or '')
            or not re.fullmatch('[0-9a-f]{64}',args.expected_binary_sha256 or '')):
        parser.error('candidate_binary_build_and_sha256_required')
    parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    binary=args.binary.resolve(strict=True) if args.binary else None
    if binary and file_hash(binary)!=args.expected_binary_sha256:parser.error('candidate_binary_sha256_mismatch')
    before=source_identity(ROOT,binary) if not args.oracle_only else None
    runner_hash=file_hash(Path(__file__));contract_hash=file_hash(Path(contract.__file__));helpers=contract.helpers()
    bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='userpass-batch-',dir=parent))
    prior=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};failures={};scans={}
    try:
        oracle=start_oracle(free_port());oracle_root=Path(oracle['root'])
        root_token=private_read(oracle['token_file']).decode().strip()
        def restart_reference():stop_oracle(oracle);restart_oracle(oracle)
        targets=[('oracle',Client(oracle['address'],oracle['ca_file'],root_token),restart_reference,oracle_root,
            [root_token,private_read(oracle_root/'unseal.key').decode().strip()])]
        if not args.oracle_only:
            from remote_jwks_live import Instance
            instance=Instance(binary,work/'candidate')
            path=instance.root/'server.json';config=json.loads(path.read_text())
            config.update(lifecycle_interval_seconds=0,outbound_endpoints=[]);private_write(path,config,replace=True)
            instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise ValueError('initialization_failed')
            instance.token,key=init['root_token'],init['keys_base64'][0]
            if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ValueError('unseal_failed')
            def restart_candidate():
                instance.stop();instance.start()
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ValueError('restart_failed')
            targets.append(('candidate',Client(instance.address,str(instance.root/'ca.crt'),instance.token),
                restart_candidate,instance.root,[instance.token,key]))
        for side,client,restart,data_root,sensitive in targets:
            trace=contract.Trace(client);trace.sensitive.extend(sensitive);cases[side]=trace.rows
            try:
                contract.run(trace,restart)
                scans[side]=safe_files(data_root,trace.sensitive)
                if not scans[side]:failures[side]='secret_scan_failed'
            except Exception as error:failures[side]='fixture_'+type(error).__name__
    except Exception as error:failures['setup']='fixture_'+type(error).__name__
    finally:
        try:
            if instance is not None:instance.stop()
        finally:
            if oracle is not None:stop_oracle(oracle)
            if prior is None:os.environ.pop('HB_ORACLE_WORK_ROOT',None)
            else:os.environ['HB_ORACLE_WORK_ROOT']=prior
    after=source_identity(ROOT,binary) if before else None
    runner_ok=runner_hash==file_hash(Path(__file__)) and contract_hash==file_hash(Path(contract.__file__))
    helpers_ok=helpers==contract.helpers();bao_ok=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    passed=(not failures and runner_ok and helpers_ok and bao_ok and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
        and all(complete(rows) for rows in cases.values()) and set(scans)==set(cases) and all(scans.values())
        and (args.oracle_only or equal and before==after and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.userpass-batch-comparison.v1','status':'passed' if passed else 'failed','cases':cases,
        'failures':failures,'cases_match':equal,'secrets_absent':scans,'candidate_source':before,'candidate_source_after':after,
        'source_and_binary_unchanged':before==after if before else None,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'contract_sha256':contract_hash,'helper_sha256':helpers,'runner_unchanged':runner_ok,
        'helpers_unchanged':helpers_ok,'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':bao_ok,
        'target_version':'2.6.2','oracle_only':args.oracle_only,'retained_failure_work_dir':None if passed else str(work),
        'dynamic_leases_covered':False,'historical_upgrade_covered':False,'HA_covered':False,'snapshot_key_history_covered':False,
        'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
