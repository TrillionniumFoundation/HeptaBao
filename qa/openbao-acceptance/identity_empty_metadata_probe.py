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
MOUNT=contract.MOUNT
SCENARIOS=frozenset({'entity','alias','group','restart'})
class Trace(contract.Trace):
 def finish(self,name):
  if name not in SCENARIOS or name in self.finished:raise ValueError('invalid_scenario')
  self.finished.append(name)
def run(t,restart):
 t.require('setup.mount','POST','sys/auth/'+MOUNT,{'type':'approle'},status=204)
 path,rid=contract.role(t,'setup','random','service')
 sid=contract.issue_sid(t,'setup.sid',path,'random',{})
 if sid is None:raise ScenarioFailure('missing_sid')
 auth=contract.login(t,'setup.login',rid,sid[0]);entity=auth['entity_id'];t.sensitive.append(entity)
 alias=contract.alias(t,'setup.identity',entity,rid)
 aid=alias['id'];t.sensitive.append(aid)
 t.call('entity.initial','GET','identity/entity/id/'+entity)
 t.call('alias.initial','GET','identity/entity-alias/id/'+aid)
 group=t.require('group.create','POST','identity/group',{'name':'empty-metadata-probe','type':'internal'})['data']['id']
 t.sensitive.append(group)
 t.call('group.initial','GET','identity/group/id/'+group)
 for label,value in (('empty',{}),('null',None),('nonempty',{'owner':'control'}),('clear_empty',{}),('again_nonempty',{'owner':'control'}),('clear_null',None)):
  t.call('entity.'+label+'.write','POST','identity/entity/id/'+entity,{'metadata':value})
  t.call('entity.'+label+'.read','GET','identity/entity/id/'+entity)
  t.call('alias.'+label+'.write','POST','identity/entity-alias/id/'+aid,
   {'canonical_id':entity,'mount_accessor':alias['mount_accessor'],'name':rid,'custom_metadata':value})
  t.call('alias.'+label+'.read','GET','identity/entity-alias/id/'+aid)
  t.call('group.'+label+'.write','POST','identity/group/id/'+group,{'metadata':value})
  t.call('group.'+label+'.read','GET','identity/group/id/'+group)
 # Admin-created alias has no backend map, unlike the AppRole-created alias.
 other=t.require('entity.admin_create','POST','identity/entity',{'name':'empty-backend-entity'})['data']['id']
 t.sensitive.append(other)
 extra=t.require('alias.admin_create','POST','identity/entity-alias',
  {'canonical_id':other,'mount_accessor':alias['mount_accessor'],'name':'empty-backend-alias','custom_metadata':{}})['data']['id']
 t.sensitive.append(extra);t.call('alias.admin_read','GET','identity/entity-alias/id/'+extra)
 for phase in ('entity','alias','group'):t.finish(phase)
 t.call('entity.pre_restart_empty.write','POST','identity/entity/id/'+entity,{'metadata':{}})
 t.call('group.pre_restart_empty.write','POST','identity/group/id/'+group,{'metadata':{}})
 t.call('alias.pre_restart_nonempty.write','POST','identity/entity-alias/id/'+aid,{'canonical_id':entity,'mount_accessor':alias['mount_accessor'],'name':rid,'custom_metadata':{'owner':'control'}})
 t.call('alias.pre_restart_empty.write','POST','identity/entity-alias/id/'+aid,{'canonical_id':entity,'mount_accessor':alias['mount_accessor'],'name':rid,'custom_metadata':{}})
 t.call('alias.empty_to_null.write','POST','identity/entity-alias/id/'+aid,{'canonical_id':entity,'mount_accessor':alias['mount_accessor'],'name':rid,'custom_metadata':None})
 t.call('alias.empty_to_null.read','GET','identity/entity-alias/id/'+aid)
 t.call('entity.pre_restart_empty.read','GET','identity/entity/id/'+entity)
 t.call('group.pre_restart_empty.read','GET','identity/group/id/'+group)

 restart()
 for name,route in (('entity','identity/entity/id/'+entity),('alias','identity/entity-alias/id/'+aid),
  ('group','identity/group/id/'+group),('admin_alias','identity/entity-alias/id/'+extra)):
  t.call('restart.'+name,'GET',route)
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
    work = Path(tempfile.mkdtemp(prefix='identity-empty-metadata-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.identity-empty-metadata-probe.v1', 'status': status,
        'failure': failure, 'failure_at': trace.rows[-1]['case'] if failure and trace and trace.rows else None,
        'cases': trace.rows if trace else [], 'completed_scenarios': trace.finished if trace else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': binary, 'runner_sha256': runner, 'helper_sha256': helper,
        'frozen_helpers_source': before, 'frozen_helpers_source_after': after,
        'runner_is_separately_hashed_staged_file': True, 'target_version': '2.6.2', 'oracle_only': True,
        'candidate_executed': False, 'source_qualified': False, 'full_openbao_compatibility': False,
        'mutating_requests_retried': False, 'not_covered': ['other Identity fields', 'HA', 'candidate execution'],
        'retained_work_dir': str(work)}
    if trace and any(secret in json.dumps(report) for secret in trace.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': status, 'cases': len(report['cases']), 'scenarios': len(report['completed_scenarios']), 'failure': failure}))
    return int(status != 'observed')


if __name__ == '__main__': raise SystemExit(main())
