#!/usr/bin/env python3
"""Compare batch lifecycle and real SSH OTP owner behavior with OpenBao2.6.2."""
from __future__ import annotations
import json, os, re, shutil, tempfile
from pathlib import Path
from bao_http import SafeArgumentParser, private_read, private_write
from radius_cidrs_live import SourceClient
import sys
from core_isolation import ROOT, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files
import batch_lifecycle_contract as contract

def helpers():
    names=('bao_http','core_isolation','official_openbao_launcher','online_evidence',
           'userpass_password_live','radius_cidrs_live','remote_jwks_live','heptabao','heptabao.transport')
    return {name:file_hash(Path(sys.modules[name].__file__)) for name in names}

complete=contract.complete

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
    runner_hash=file_hash(Path(__file__));contract_hash=file_hash(Path(contract.__file__));helper_before=helpers()
    bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='batch-lifecycle-',dir=parent))
    prior=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};failures={};scans={};all_sensitive=[]
    try:
        oracle=start_oracle(free_port());oracle_root=Path(oracle['root'])
        root_token=private_read(oracle['token_file']).decode().strip()
        def restart_reference():stop_oracle(oracle);restart_oracle(oracle)
        targets=[('oracle',SourceClient(oracle['address'],oracle['ca_file'],root_token),restart_reference,oracle_root,
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
            targets.append(('candidate',SourceClient(instance.address,str(instance.root/'ca.crt'),instance.token),
                restart_candidate,instance.root,[instance.token,key]))
        for side,client,restart,data_root,sensitive in targets:
            trace=contract.Trace(client);trace.sensitive.extend(sensitive);cases[side]=trace.rows
            all_sensitive.append(trace.sensitive)
            try:
                contract.run(trace,restart)
                scans[side]=safe_files(data_root,trace.sensitive)
                if not scans[side]:failures[side]='secret_scan_failed'
            except Exception as error:failures[side]=next((row['case'] for row in reversed(trace.rows) if row.get('passed') is not True),'fixture_'+type(error).__name__)
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
    helpers_ok=helper_before==helpers();bao_ok=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    passed=(not failures and runner_ok and helpers_ok and bao_ok and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
        and all(complete(rows) for rows in cases.values()) and set(scans)==set(cases) and all(scans.values())
        and (args.oracle_only or equal and before==after and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.batch-lifecycle-comparison.v1','status':'passed' if passed else 'failed','cases':cases,
        'failures':failures,'cases_match':equal,'secrets_absent':scans,'candidate_source':before,'candidate_source_after':after,
        'source_and_binary_unchanged':before==after if before else None,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'contract_sha256':contract_hash,'helper_sha256':helper_before,'runner_unchanged':runner_ok,
        'helpers_unchanged':helpers_ok,'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':bao_ok,
        'target_version':'2.6.2','oracle_only':args.oracle_only,'retained_failure_work_dir':None if passed else str(work),
        'dynamic_leases_covered':bool(cases) and all(contract.complete(rows) for rows in cases.values()),'dynamic_backend':'ssh-otp','renewable_provider_cap_covered':False,'real_ssh_host_authentication':False,
        'actual_socket_origin':any('source_family' in row for rows in cases.values() for row in rows),'calibrated_oracle_receipt_sha256':contract.CALIBRATED_RECEIPT_SHA256,
        'scoped_extensions':['identity','cidr'],'mutating_requests_retried':False,'historical_upgrade_covered':False,'HA_covered':False,'snapshot_key_history_covered':False,
        'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if any(secret in json.dumps(report) for values in all_sensitive for secret in values):raise ValueError('sensitive_report_rejected')
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
