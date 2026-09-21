#!/usr/bin/env python3
"""Official-only SecretID metadata parsing and immutable credential observations."""
from __future__ import annotations
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import tempfile
from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from approle_token_cidrs_probe import Trace as BaseTrace
from radius_cidrs_live import SourceClient
from userpass_password_live import free_port, private_parent, safe_files

import approle_secretid_metadata_probe as contract
MOUNT = contract.MOUNT
SCENARIOS = frozenset({'denial.service','denial.batch','restart'})

class Trace(contract.Trace):
 def finish(self,name):
  if name not in SCENARIOS or name in self.finished:raise ValueError('invalid_scenario')
  self.finished.append(name)

def run(t,restart):
 t.require('setup.mount','POST','sys/auth/'+MOUNT,{'type':'approle'},status=204)
 held=[]
 for kind in ('service','batch'):
  name='denial.'+kind
  path,rid=contract.role(t,name,'random',kind,True)
  first=contract.issue_sid(t,name+'.first',path,'random',{'metadata':'{"env":"one"}'})
  if first is None:raise ScenarioFailure('missing_first_sid')
  auth=contract.login(t,name+'.first_login',rid,first[0])
  entity=auth['entity_id']
  t.sensitive.append(entity)
  alias=contract.alias(t,name+'.initial',entity,rid)
  aid=alias['id'];t.sensitive.append(aid)
  t.require(name+'.custom','POST','identity/entity-alias/id/'+aid,
    {'name':rid,'canonical_id':entity,'mount_accessor':alias['mount_accessor'],'custom_metadata':{'owner':'control'}})
  t.require(name+'.finite_role','POST',path,{'secret_id_num_uses':2},status=204)
  second=contract.issue_sid(t,name+'.second',path,'random',{'metadata':'{"env":"two"}'})
  if second is None:raise ScenarioFailure('missing_second_sid')
  contract.lookup_sid(t,name+'.before_sid',path,*second)
  t.require(name+'.disable','POST','identity/entity/id/'+entity,{'disabled':True},status=204)
  status,body=t.call(name+'.rejected_login','POST','auth/'+MOUNT+'/login',{'role_id':rid,'secret_id':second[0]},token='')
  t.observe(name+'.rejection',permission_denied=status==403,no_credential=not bool(body.get('auth')),no_wrapper=not bool(body.get('wrap_info')))
  t.call(name+'.after_alias','GET','identity/entity-alias/id/'+aid)
  contract.lookup_sid(t,name+'.after_sid',path,*second)
  held.append((name,aid,path,second))
  t.finish(name)
 restart()
 for name,aid,path,second in held:
  t.call('restart.'+name+'.alias','GET','identity/entity-alias/id/'+aid)
  contract.lookup_sid(t,'restart.'+name+'.sid',path,*second)
 t.finish('restart')

def complete(t):
 return bool(t and t.rows and set(t.finished)==SCENARIOS and len(t.finished)==len(SCENARIOS)
   and len({x['case'] for x in t.rows})==len(t.rows))

def helpers():return {'contract':file_hash(Path(contract.__file__)),**contract.helpers()}

def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); binary, runner, helper = file_hash(bao), file_hash(Path(__file__)), helpers()
    before = source_identity(ROOT, bao)
    work = Path(tempfile.mkdtemp(prefix='approle-metadata-denial-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = trace = None; failure = None; scan = False; stopped = False; unchanged = False; after = None
    def failed(error):
        nonlocal failure
        failure = failure or 'fixture_'+type(error).__name__
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        oracle = start_oracle(free_port()); root = Path(oracle['root'])
        admin = private_read(oracle['token_file']).decode().strip()
        trace = Trace(SourceClient(oracle['address'], oracle['ca_file'], admin))
        trace.sensitive.extend((admin, private_read(root/'unseal.key').decode().strip()))
        def restart(): stop_oracle(oracle); restart_oracle(oracle)
        run(trace, restart)
    except Exception as error: failed(error)
    finally:
        try:
            if oracle is not None: stop_oracle(oracle)
        except Exception as error: failed(error)
        finally:
            if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
            else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
            for sig, handler in handlers.items(): signal.signal(sig, handler)
    try:
        if trace is not None and oracle is not None: scan = safe_files(Path(oracle['root']), trace.sensitive)
        stopped = oracle is None or oracle['process'].poll() is not None
        after = source_identity(ROOT, bao)
        unchanged = binary == file_hash(bao) and runner == file_hash(Path(__file__)) and helper == helpers() and before == after
    except Exception as error: failed(error)
    status = 'observed' if failure is None and complete(trace) and scan and unchanged and stopped and not before['source_dirty'] else 'failed'
    report = {'schema': 'heptabao.approle-metadata-denial-probe.v1', 'status': status,
        'failure': failure, 'failure_at': trace.rows[-1]['case'] if failure and trace and trace.rows else None,
        'cases': trace.rows if trace else [], 'completed_scenarios': trace.finished if trace else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': binary, 'runner_sha256': runner, 'helper_sha256': helper,
        'frozen_helpers_source': before, 'frozen_helpers_source_after': after,
        'runner_is_separately_hashed_staged_file': True, 'target_version': '2.6.2', 'oracle_only': True,
        'candidate_executed': False, 'source_qualified': False, 'full_openbao_compatibility': False,
        'mutating_requests_retried': False, 'not_covered': ['wrapping request', 'source denial', 'fresh alias limits', 'HA', 'candidate execution'],
        'retained_work_dir': str(work)}
    if trace and any(secret in json.dumps(report) for secret in trace.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': status, 'cases': len(report['cases']), 'scenarios': len(report['completed_scenarios']), 'failure': failure}))
    return int(status != 'observed')


if __name__ == '__main__': raise SystemExit(main())
