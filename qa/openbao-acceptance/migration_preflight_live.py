#!/usr/bin/env python3
"""Test real metadata preflight against pinned OpenBao and a new HeptaBao process.

All mutations belong to fresh synthetic fixture setup, never the preflight.
Only sanitized case results leave the disposable private fixture directory.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import start_oracle, stop_oracle, BINARY_SHA256
import migration_preflight as preflight


def main() -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    preflight.require_private_new_output(output)
    binary = Path(args.binary).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='heptabao-preflight-live-'))
    root.chmod(0o700)
    instance = oracle = None
    report = {'schema':'heptabao.migration-preflight-live.v1', 'status':'failed', 'cases':[],
              'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
              'source_worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
              'candidate_binary_sha256':file_hash(binary), 'oracle_binary_sha256':BINARY_SHA256,
              'runner_sha256':file_hash(Path(__file__)), 'synthetic_only':True,
              'full_format_migration':False, 'migration_authority':False, 'independent_admission':False}

    def check(name, condition):
        report['cases'].append({'case':name, 'passed':bool(condition)})
        if not condition: raise ScenarioFailure(name)

    try:
        spec = importlib.util.spec_from_file_location('preflight_smoke',ROOT/'qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        instance = smoke.Instance(binary, root/'candidate'); instance.start()
        status, init = instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        check('init',status==200)
        instance.token = init['root_token']
        check('unseal',instance.call('POST','sys/unseal',{'key':init['keys_base64'][0]})[0]==200)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        oracle = start_oracle(port)
        reference = Client(oracle['address'],oracle['ca_file'],private_read(oracle['token_file']).decode().strip())
        check('synthetic_transit_mount',reference.request('POST','/v1/sys/mounts/preflight-transit',{'type':'transit'}).status==204)
        # Only the fixture registers this mount; the collector cannot create it.
        before_mounts = reference.request('GET','/v1/sys/mounts').body['data']
        before = instance.call('GET','sys/internal/capacity')[1]['data']
        for source, dest in ((Path(oracle['ca_file']), root/'source-ca.pem'),
                             (instance.root/'ca.crt',root/'target-ca.pem')):
            dest.write_bytes(source.read_bytes()); dest.chmod(0o600)
        (root/'target.token').write_text(instance.token); (root/'target.token').chmod(0o600)
        config = {
            'source': {'address':oracle['address'],'namespace':'','ca_file':str(root/'source-ca.pem'),'token_file':oracle['token_file']},
            'target': {'address':instance.address,'namespace':'','ca_file':str(root/'target-ca.pem'),'token_file':str(root/'target.token')},
            'planned_additional_bytes':before['state_remaining_bytes']+1,
        }
        private_write(root/'config.json',config,replace=False)
        output_text=io.StringIO()
        with contextlib.redirect_stdout(output_text):
            code=preflight.main(['--config',str(root/'config.json'),'--output',str(root/'preflight.json'),'--allow-read'])
        check('cli_reports_blocked_not_migrated',code==3)
        result=json.loads(private_read(root/'preflight.json'))
        check('real_source_mounts_observed',result['source_catalogs']['mounts']['status']=='observed')
        check('real_source_transit_detected',result['source_catalogs']['mounts']['types'].get('transit')==1)
        check('transit_adapter_stays_blocked','asset_adapter_not_qualified:transit' in result['blockers'])
        check('real_target_capacity_observed',result['target_capacity']['status']=='observed')
        check('oversize_plan_is_blocked','target_state_estimate_exceeds_current_capacity' in result['blockers'])
        check('no_inventory_or_cutover_claim',not result['inventory_complete'] and not result['atomic_cutover_proven'])
        check('no_consumer_pin_authority',not result['hepta_consumer_requalified'] and not result['migration_authority'])
        encoded=json.dumps(result)
        check('metadata_names_redacted','preflight-transit' not in encoded and instance.token not in encoded)
        after=instance.call('GET','sys/internal/capacity')[1]['data']
        check('target_generation_unchanged',after['generation']==before['generation'])
        check('target_operations_unchanged',after['retained_operations']==before['retained_operations'])
        check('source_mounts_unchanged',reference.request('GET','/v1/sys/mounts').body['data']==before_mounts)
        # Using root fixture credentials avoids normal finite-token consumption;
        # the operator tool explicitly does not generalize that fact to all reads.
        config['source']['token_file']=str(root/'denied.token')
        (root/'denied.token').write_text('synthetic-invalid-token');(root/'denied.token').chmod(0o600)
        private_write(root/'denied-config.json',config,replace=False)
        with contextlib.redirect_stdout(io.StringIO()):
            code=preflight.main(['--config',str(root/'denied-config.json'),'--output',str(root/'denied.json'),'--allow-read'])
        check('denied_catalogs_are_not_empty_success',code in (2,3))
        if code==3:
            denied=json.loads(private_read(root/'denied.json'))
            check('denied_mount_catalog_unobserved',denied['source_catalogs']['mounts']['status']=='unobserved')
        check('binary_unchanged',file_hash(binary)==report['candidate_binary_sha256'])
        report['status']='passed_scoped_preflight_fixture'
    except (BaoError,ScenarioFailure) as exc:
        report['failure']=str(exc)
    except Exception as exc:
        report['failure']='unexpected_'+type(exc).__name__
    finally:
        if instance is not None: instance.stop()
        if oracle is not None:
            stop_oracle(oracle);shutil.rmtree(oracle['root'],ignore_errors=True)
        shutil.rmtree(root,ignore_errors=True)
    private_write(output,report,replace=False)
    print(json.dumps({'status':report['status'],'cases':len(report['cases']),'failure':report.get('failure')}))
    return int(report['status']!='passed_scoped_preflight_fixture')


if __name__=='__main__':
    raise SystemExit(main())
