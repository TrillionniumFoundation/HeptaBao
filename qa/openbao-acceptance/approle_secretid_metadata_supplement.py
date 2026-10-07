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

import base64
import approle_secretid_metadata_probe as contract
MOUNT = contract.MOUNT
KV = contract.KV
POLICY = contract.POLICY

def b64(value): return base64.b64encode(value.encode()).decode()
INPUTS = (
 ('base64_json',b64('{"env":"prod"}')),('base64_csv',b64('Env=Prod,Team=OPS')),
 ('base64_unpadded',b64('{"env":"prod"}').rstrip('=')),('base64_empty',b64('')),
 ('csv_reverse_duplicate','env=last,env=first'),('csv_case','Env=Prod,Team=OPS'),
 ('csv_leading',',env=prod'),('csv_trailing','env=prod,'),('csv_empty_segments',',env=prod,,team=ops,'),
 ('json_case','{"Env":"Prod"}'),('json_empty_key','{"":"prod"}'),('json_empty_both','{"":""}'),
 ('json_empty_value','{"env":""}'),('json_space_value','{"env":" "}'),
 ('json_unicode',json.dumps({'env':'汉字','键':'值'},ensure_ascii=False)),
 ('json_control',json.dumps({'env':'one\ntwo','tab':'a\tb'})),
 ('json_comma',json.dumps({'env':'one,two','note':'a=b'})),
 ('spaced_json_null',' null '),('base64_json_null',b64('null')),('whitespace','   '),
 ('json_long_key',json.dumps({'k'*129:'prod'})),('json_long_value',json.dumps({'env':'v'*1025})),
 ('json_65_keys',json.dumps({f'key{i}':'prod' for i in range(65)})),
)
SCENARIOS=frozenset('parser.'+name for name,_ in INPUTS)

class Trace(contract.Trace):
 def finish(self,name):
  if name not in SCENARIOS or name in self.finished:raise ValueError('invalid_scenario')
  self.finished.append(name)

def run(t,restart):
 t.require('setup.mount','POST','sys/auth/'+MOUNT,{'type':'approle'},status=204)
 t.require('setup.kv','POST','sys/mounts/approle-metadata-kv',{'type':'kv','options':{'version':'1'}},status=204)
 t.require('setup.value','POST',KV,{'value':'synthetic'},status=204)
 t.require('setup.policy','PUT','sys/policies/acl/'+POLICY,{'policy':'path "approle-metadata-kv/*" { capabilities=["read"] }'},status=204)
 path,rid=contract.role(t,'setup','random','service')
 for label,value in INPUTS:
  name='parser.'+label
  issued=contract.issue_sid(t,name,path,'random',{'metadata':value})
  if issued:
   contract.lookup_sid(t,name+'.stored',path,*issued)
   status,body=t.call(name+'.login','POST','auth/'+MOUNT+'/login',{'role_id':rid,'secret_id':issued[0]},token='')
   if status==200:
    raw=contract.credential(body)
    t.call(name+'.bearer','GET',KV,token=raw)
    t.call(name+'.lookup','POST','auth/token/lookup',{'token':raw})
   else:t.observe(name+'.no_issued_bearer',credential_issued=False)
  t.finish(name)

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
    work = Path(tempfile.mkdtemp(prefix='approle-sid-metadata-supplement-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.approle-secretid-metadata-supplement.v1', 'status': status,
        'failure': failure, 'failure_at': trace.rows[-1]['case'] if failure and trace and trace.rows else None,
        'cases': trace.rows if trace else [], 'completed_scenarios': trace.finished if trace else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': binary, 'runner_sha256': runner, 'helper_sha256': helper,
        'frozen_helpers_source': before, 'frozen_helpers_source_after': after,
        'runner_is_separately_hashed_staged_file': True, 'target_version': '2.6.2', 'oracle_only': True,
        'candidate_executed': False, 'source_qualified': False, 'full_openbao_compatibility': False,
        'mutating_requests_retried': False, 'not_covered': ['maximum metadata size limits', 'local-only SecretIDs', 'MFA', 'HA', 'custom SID or batch repetition of supplemental cases'],
        'retained_work_dir': str(work)}
    if trace and any(secret in json.dumps(report) for secret in trace.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': status, 'cases': len(report['cases']), 'scenarios': len(report['completed_scenarios']), 'failure': failure}))
    return int(status != 'observed')


if __name__ == '__main__': raise SystemExit(main())
