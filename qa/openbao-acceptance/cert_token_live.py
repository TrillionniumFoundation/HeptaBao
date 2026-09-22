#!/usr/bin/env python3
"""Compare the pinned cert batch and lifetime traces over real TLS, without response adapters."""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
import time

from bao_http import SafeArgumentParser, private_read, private_write
from cert_auth_live import Fixture
from cert_renewal_live import tls_client
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files
import cert_batch_probe as batch
import cert_native_ttl_probe as lifetime

PROFILES = {
    'batch': (batch, 'cert-batch-official-30aa128.json',
        '476fe1be97077458fd4d6e305b602dc458f7b9addd65a3dc42477c4def8c5688',
        '2fe9b641298c9e34b8f56c6cdff151042916fca6ce85be28ab1781f64ea5f4b8',
        'heptabao.cert-batch-probe.v1'),
    'ttl': (lifetime, 'cert-native-ttl-official-4e97aa7.json',
        'f3e3220485a76cab4c54fef3c882d6a836e20dbb72d2801a45b4645b7733343a',
        '12f54f12f3c2158d0c0753e8b26a42c4b8351943262a147efa9f92e7c3e49b23',
        'heptabao.cert-native-ttl-probe.v1'),
}
AGES = ('explicit.snapshot.age', 'ordinary.currentmax.age',
        'period.transition.cap0.age', 'period.transition.cap120.age')
POLL = re.compile(r'('+'|'.join(re.escape(x) for x in AGES)+r')\.poll([1-9][0-9]*)(\.lease)?\Z')
BOOLS = set('accessor accessor_absent accessor_endpoint_not_called auth accessor_no_bearer cert_name_matches certificate_metadata_keys_exact common_name_matches data default_matches distinct_bearer echo_target empty_result entity errors exact_role_readback_preserved known_issue_age_at_least_one_second live lookup_period_present max_matches orphan renewable role_exactly_unchanged same_entity warnings_present warnings_valid wrap'.split())
NUMBERS = set('status auth_num_uses creation_time creation_ttl explicit_max_ttl lease_duration lookup_explicit_max_ttl lookup_num_uses lookup_period max_ttl period read_only_polls token_explicit_max_ttl token_max_ttl token_num_uses token_period token_ttl ttl'.split())
BOOLS |= {x+'_present' for x in ('token_ttl','token_max_ttl','token_period','token_explicit_max_ttl','ttl','max_ttl','period','token_num_uses')}
TYPES = {'token_type','role_type','lookup_type'}


def remaining_cap(case):
    if re.fullmatch(r'explicit\.snapshot\.old(1|600)\.renew(_self|_accessor)?', case): return 120
    if re.fullmatch(r'children\.(child|orphan)\.(renew\.renew(_self|_accessor)?|no_leaf)', case): return 40
    return None


def safe_rows(rows):
    if not isinstance(rows,list) or not rows:return False
    seen=set()
    for row in rows:
        if not isinstance(row,dict):return False
        name=row.get('case')
        if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or name in seen:return False
        seen.add(name)
        for key,value in row.items():
            if key=='case':continue
            if key in BOOLS:
                if type(value) is not bool:return False
            elif key in NUMBERS:
                if type(value) is not int or value<0:return False
                if key=='status' and not 100<=value<=599:return False
            elif key in TYPES:
                if value not in ('default','service','batch','other'):return False
            else:return False
    return True


def shape(row):
    """Only volatile fields with separately required timing evidence become relation labels."""
    result=dict(row)
    if 'creation_time' in result:
        result['creation_time']='issued_clock_window'
        if 'ttl' in result:result['ttl']='last_grant_expiry_window'
    if 'read_only_polls' in result:result['read_only_polls']='all_polls_accounted'
    if remaining_cap(row['case']) and 'lease_duration' in result:
        result['lease_duration']='issued_explicit_cap_remaining'
    return result


def skeleton(rows, profile):
    if not safe_rows(rows):raise ValueError('unsafe_or_duplicate_rows')
    if profile=='batch':return rows
    result=[];polls={};last=None
    for row in rows:
        match=POLL.fullmatch(row['case'])
        if match:
            group,index,suffix=match.group(1),int(match.group(2)),match.group(3) or ''
            seq=polls.setdefault(group,[]);expected_index=len(seq)//2+1
            if index!=expected_index or suffix!=('.lease' if len(seq)%2 else ''):
                raise ValueError('poll_sequence_incomplete')
            normalized=shape(row);normalized['case']=group+'.poll'+suffix
            if len(seq)>=2 and normalized!=seq[len(seq)%2]:raise ValueError('poll_shape_changed')
            if not seq:result.append({'case':group+'.poll_sequence'})
            seq.append(normalized);last=group
        else:
            if row['case'] in {x+'.ready' for x in AGES}:
                group=row['case'][:-6];seq=polls.get(group,[])
                if last!=group or not seq or len(seq)%2 or row.get('read_only_polls')!=len(seq)//2:
                    raise ValueError('poll_count_not_accounted')
                # Both raw HTTP and lease projections are mandatory, even when poll count differs.
                result.extend(seq[:2])
            result.append(shape(row));last=None
    if set(polls)!=set(AGES):raise ValueError('age_phase_missing')
    return result


def complete(rows, finished, expected, profile, timing):
    module=PROFILES[profile][0]
    try:
        if (not isinstance(finished,list) or len(finished)!=len(set(finished))
                or set(finished)!=module.SCENARIOS or skeleton(rows,profile)!=skeleton(expected,profile)):
            return False
        needed=set()
        for row in rows:
            if 'creation_time' in row:needed.add(row['case'][:-6])
            if remaining_cap(row['case']) and 'lease_duration' in row:needed.add(row['case'])
        return (isinstance(timing,dict) and needed<=timing.keys()
                and all(value.get('passed') is True for value in timing.values()))
    except (ValueError,TypeError,KeyError):return False


def calibration(profile):
    module,name,digest,runner_digest,schema=PROFILES[profile]
    path=Path(__file__).parent/'evidence'/name
    if file_hash(path)!=digest or file_hash(Path(module.__file__))!=runner_digest:
        raise ValueError('calibration_or_probe_changed')
    value=json.loads(path.read_text())
    rows=value.get('cases');finished=value.get('completed_scenarios')
    scans=value.get('secrets_absent')
    if profile=='batch':rows=rows.get('oracle');finished=finished.get('oracle');scans=scans.get('oracle')
    if (value.get('schema')!=schema or value.get('status')!='observed'
        or value.get('target_version')!='2.6.2' or value.get('oracle_only') is not True
        or value.get('candidate_executed') is not False or value.get('failure') is not None
        or value.get('failures',{})!={} or scans is not True
        or any(value.get(k) is not True for k in ('inputs_unchanged','processes_stopped'))
        or value.get('runner_sha256')!=runner_digest
        or len(finished)!=len(set(finished)) or set(finished)!=module.SCENARIOS):
        raise ValueError('invalid_calibration')
    skeleton(rows,profile)
    return value,rows


def inputs():
    return {'runner':file_hash(Path(__file__)), 'helpers':lifetime.helpers(),
        'profiles':{name:{'probe':file_hash(Path(v[0].__file__)),
            'receipt':file_hash(Path(__file__).parent/'evidence'/v[1])} for name,v in PROFILES.items()}}


class Timing:
    """Private bearer-indexed windows; only timestamps and booleans leave this object."""
    def __init__(self):self.tokens={};self.accessors={};self.rows={}
    def observe(self,case,path,payload,token,result,before,after):
        auth=result.get('auth') or {};data=result.get('data') or {};checks=[]
        if after<before:checks.append(False)
        grant=auth.get('lease_duration');raw=auth.get('client_token')
        renew=path.startswith('auth/token/renew')
        target=(payload or {}).get('token') if renew else None
        if renew and path.endswith('renew-self'):target=token
        if renew and path.endswith('renew-accessor'):target=self.accessors.get((payload or {}).get('accessor'))
        if isinstance(grant,int) and not isinstance(grant,bool) and auth:
            cap=remaining_cap(case)
            if cap:
                prior=self.tokens.get(target)
                checks.append(prior is not None and cap_window(prior['issued'],cap,before,after,grant))
            if renew:
                prior=self.tokens.get(target)
                if prior is not None:prior['expiry']=(before+grant,after+grant)
            elif isinstance(raw,str) and raw:
                self.tokens[raw]={'issued':(before,after),'expiry':(before+grant,after+grant),'binding_probe':case=='fresh.omitted.login'}
                if auth.get('accessor'):self.accessors[auth['accessor']]=raw
        if type(data.get('creation_time')) is int:
            target=(payload or {}).get('token') or data.get('id') or token
            prior=self.tokens.get(target);created=data['creation_time'];ttl=data.get('ttl')
            checks.append(prior is not None and math.floor(prior['issued'][0])-1<=created<=math.ceil(prior['issued'][1]))
            checks.append(prior is not None and type(ttl) is int and expiry_window(prior['expiry'],before,after,ttl))
        if checks:self.rows[case]={'before':before,'after':after,'passed':all(checks)}


def cap_window(issued,cap,before,after,value):
    return (type(value) is int and 0<value<=cap
        and max(1,math.floor(issued[0]+cap-after)-1)<=value<=math.floor(issued[1]+cap-before)+1)


def expiry_window(expiry,before,after,value):
    # Integer API clocks have one-second resolution; requests bracket actual computation.
    return (type(value) is int and value>=0
        and max(0,math.floor(expiry[0]-after)-1)<=value<=max(0,math.floor(expiry[1]-before)+1))


def measured_trace(module,client):
    class Measured(module.Trace):
        def __init__(self,client):super().__init__(client);self.timing=Timing()
        def call(self,case,method,path,body=None,**kwargs):
            before=time.time();status,result=super().call(case,method,path,body,**kwargs);after=time.time()
            self.timing.observe(case,path,body,kwargs.get('token'),result,before,after)
            return status,result
    return Measured(client)


def verify_optional_tls(fixture,trace):
    """Exercise absence, valid chain, wrong trusted leaf, and invalid chain independently."""
    import ssl
    import urllib.error
    direct=next((raw for raw,item in trace.timing.tokens.items() if item.get('binding_probe')),None)
    if direct is None:raise ScenarioFailure('optional_tls_direct_token_missing')
    path='/v1/auth/token/renew-self';payload={'increment':75}
    good=trace.client.request('POST',path,payload,token=direct)
    plain=tls_client(fixture.address,fixture.root/'root.crt',fixture.token)
    absent=plain.request('POST',path,payload,token=direct)
    wrong=tls_client(fixture.address,fixture.root/'root.crt',fixture.token,
        (fixture.root/'wrong-client-chain.pem',fixture.root/'wrong-client.key'))
    wrong_result=wrong.request('POST',path,payload,token=direct)
    untrusted=tls_client(fixture.address,fixture.root/'root.crt',fixture.token,
        (fixture.root/'untrusted-client-chain.pem',fixture.root/'untrusted-client.key'))
    rejected=False
    try:untrusted.request('GET','/v1/sys/health',token='')
    except (ssl.SSLError,urllib.error.URLError,ConnectionError,OSError):rejected=True
    result={'real_leaf_renew_status':good.status,'absent_leaf_renew_status':absent.status,
        'wrong_trusted_leaf_renew_status':wrong_result.status,'untrusted_chain_tls_rejected':rejected}
    if result!={'real_leaf_renew_status':200,'absent_leaf_renew_status':400,
        'wrong_trusted_leaf_renew_status':403,'untrusted_chain_tls_rejected':True}:
        raise ScenarioFailure('optional_tls_verification_failed')
    return result


def main():
    p=SafeArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path);p.add_argument('--build-source-commit')
    p.add_argument('--expected-binary-sha256');p.add_argument('--oracle-only',action='store_true')
    p.add_argument('--work-parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if not args.oracle_only and (not args.binary or not re.fullmatch('[0-9a-f]{40}',args.build_source_commit or '')
        or not re.fullmatch('[0-9a-f]{64}',args.expected_binary_sha256 or '')):
        p.error('candidate_binary_build_and_sha256_required')
    binary=args.binary.resolve(strict=True) if args.binary else None
    if binary and file_hash(binary)!=args.expected_binary_sha256:p.error('candidate_binary_sha256_mismatch')
    calibrations={name:calibration(name) for name in PROFILES}
    before_inputs=inputs();bao=verify_inputs();archive=Path(os.environ['HB_ORACLE_ARCHIVE'])
    bao_hash,archive_hash=file_hash(bao),file_hash(archive)
    if any(v[0]['oracle_binary_sha256']!=bao_hash or v[0]['oracle_archive_sha256']!=archive_hash for v in calibrations.values()):
        raise ValueError('official_binary_not_calibrated')
    before=source_identity(ROOT,binary) if not args.oracle_only else None
    if before and before['source_dirty']:raise ValueError('candidate_source_dirty')
    output=args.output.absolute();admitted=admit_output(output)
    work=Path(tempfile.mkdtemp(prefix='cert-token-dual-',dir=private_parent(args.work_parent)))
    previous=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    cases,finished,clocks,scans,failures,adaptations={},{},{},{},{},{}
    processes=[];sensitive=[];oracle=fixture=None;observation='setup'
    def interrupted(signum,frame):raise ScenarioFailure('interrupted')
    handlers={sig:signal.signal(sig,interrupted) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        for profile,(module,*_) in PROFILES.items():
            # One certificate set per profile is shared byte-for-byte across both fresh stores.
            fixture=Fixture(binary or bao,work/(profile+'-candidate-and-tls'))
            certificate=(fixture.root/'client.crt').read_text()
            config_path=fixture.root/'server.json';config=json.loads(config_path.read_text())
            config.update(lifecycle_interval_seconds=0,tls_client_auth_optional=True)
            private_write(config_path,config,replace=True)
            for side in (('oracle',) if args.oracle_only else ('oracle','candidate')):
                observation=profile+'.'+side
                if side=='oracle':
                    oracle=start_oracle(free_port());processes.append(oracle['process'])
                    data_root=Path(oracle['root']);token=private_read(oracle['token_file']).decode().strip()
                    key=private_read(data_root/'unseal.key').decode().strip()
                    address,ca=oracle['address'],oracle['ca_file']
                    def restart():
                        stop_oracle(oracle);restart_oracle(oracle);processes.append(oracle['process'])
                else:
                    fixture.start();processes.append(fixture.process)
                    status,value=fixture.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
                    if status!=200:raise ScenarioFailure('candidate_initialization_failed')
                    fixture.token,fixture.unseal_key=value['root_token'],value['keys_base64'][0]
                    token,key=fixture.token,fixture.unseal_key
                    if fixture.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_unseal_failed')
                    data_root=fixture.root;address,ca=fixture.address,fixture.root/'root.crt'
                    def restart():
                        fixture.stop();fixture.start();processes.append(fixture.process)
                        if fixture.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_restart_failed')
                client=tls_client(address,ca,token,(fixture.root/'client-chain.pem',fixture.root/'client.key'))
                trace=measured_trace(module,client);trace.sensitive.extend([token,key])
                trace.sensitive.extend(private_read(path).decode() for path in fixture.root.glob('*.key'))
                cases[observation],finished[observation],clocks[observation]=trace.rows,trace.finished,trace.timing.rows
                sensitive.append(trace.sensitive);adaptations[observation]=[]
                if profile=='ttl':
                    plain=tls_client(address,ca,token)
                    module.run(trace,certificate,restart,plain)
                    if side=='candidate':adaptations[observation].append(verify_optional_tls(fixture,trace))
                else:module.run(trace,certificate,restart)
                if side=='oracle':stop_oracle(oracle);oracle=None
                else:fixture.stop()
                scans[observation]=all(safe_files(path,trace.sensitive) for path in {data_root,fixture.root})
                if not scans[observation]:raise ScenarioFailure('secret_scan_failed')
            fixture=None
    except Exception as error:
        # Only our static phase names may be emitted, never raw HTTP bodies or process logs.
        failures[observation]='fixture_'+type(error).__name__
        if isinstance(error,ScenarioFailure) and re.fullmatch(r'[a-z0-9_.]{1,140}',str(error)):
            failures[observation]+=':'+str(error)
    finally:
        for name,stop in (('candidate',lambda:fixture.stop() if fixture else None),
                          ('oracle',lambda:stop_oracle(oracle) if oracle else None)):
            try:stop()
            except Exception as error:failures.setdefault(name,'cleanup_'+type(error).__name__)
        if previous is None:os.environ.pop('HB_ORACLE_WORK_ROOT',None)
        else:os.environ['HB_ORACLE_WORK_ROOT']=previous
        for sig,handler in handlers.items():signal.signal(sig,handler)
    after=None;unchanged=False;oracle_unchanged=False
    try:
        after=source_identity(ROOT,binary) if before else None
        unchanged=before_inputs==inputs()
        oracle_unchanged=bao_hash==file_hash(bao) and archive_hash==file_hash(archive)
    except Exception as error:failures['postcheck']='fixture_'+type(error).__name__
    expected_sides={profile+'.'+side for profile in PROFILES for side in (('oracle',) if args.oracle_only else ('oracle','candidate'))}
    matches={key:complete(rows,finished.get(key),calibrations[key.split('.')[0]][1],key.split('.')[0],clocks.get(key))
             for key,rows in cases.items()}
    equal={profile:None if args.oracle_only else matches.get(profile+'.oracle') is True and matches.get(profile+'.candidate') is True
           for profile in PROFILES}
    stopped=all(process.poll() is not None for process in processes)
    adapted=(args.oracle_only or len(adaptations.get('ttl.candidate',[]))==1)
    passed=(not failures and stopped and unchanged and oracle_unchanged and adapted
        and set(cases)==expected_sides and set(scans)==expected_sides and all(scans.values()) and all(matches.values())
        and (args.oracle_only or before==after and not after['source_dirty'] and all(equal.values())))
    report={'schema':'heptabao.cert-token-comparison.v1','status':'passed' if passed else 'failed',
        'target_version':'2.6.2','oracle_only':args.oracle_only,'cases':cases,'completed_scenarios':finished,
        'calibrated_cases_match':matches,'cases_match':equal,'timing_evidence':clocks,
        'listener_adaptation_checks':adaptations,'failures':failures,'secrets_absent':scans,'processes_stopped':stopped,
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':before==after if before else None,
        'build_source_commit':args.build_source_commit,'expected_binary_sha256':args.expected_binary_sha256,
        'inputs_sha256':before_inputs,'inputs_unchanged':unchanged,'oracle_binary_sha256':bao_hash,
        'oracle_archive_sha256':archive_hash,'oracle_inputs_unchanged':oracle_unchanged,
        'profiles_use_independent_fresh_stores':True,'same_leaf_bytes_on_both_sides':True,
        'configuration_adaptation':'candidate tls_client_auth_optional=true with configured trusted CA; absent certificate allowed at transport only, supplied chains verified; oracle optional certificate listener; no mid-trace configuration changes',
        'timing_contract':'all raw polls retained and accounted; creation time tied to actual issue window; remaining TTL tied to last successful grant; explicit cap renewal tied to original issue window; integer rounding allowance at most one second per endpoint',
        'mutating_requests_retried':False,'retained_failure_work_dir':None if passed else str(work),
        'full_openbao_compatibility':False,'HA_covered':False,'historical_upgrade_covered':False,
        'not_covered':['CRL/OCSP','CA roles','CIDRs','MFA','listener configuration parity','historical upgrade','HA']}
    if any(secret in json.dumps(report) for values in sensitive for secret in values):raise ValueError('sensitive_report')
    if admit_output(output)!=admitted:raise ValueError('output_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{key:len(value) for key,value in cases.items()},'failures':failures}))
    return int(not passed)


if __name__=='__main__':raise SystemExit(main())
