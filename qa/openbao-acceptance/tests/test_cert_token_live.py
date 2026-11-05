import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import cert_token_live as f


class CertTokenComparisonTests(unittest.TestCase):
    def sample(self,profile):
        value,rows=f.calibration(profile)
        phases=value['completed_scenarios']
        if profile=='batch':phases=phases['oracle']
        # Only used to exercise comparison independently of the measured transport.
        timing={r['case'][:-6] if 'creation_time' in r else r['case']:{'passed':True}
                for r in rows if 'creation_time' in r or f.remaining_cap(r['case'])}
        return rows,phases,timing

    def test_both_immutable_complete_calibrations(self):
        for profile in f.PROFILES:
            rows,phases,timing=self.sample(profile)
            self.assertTrue(f.complete(rows,phases,rows,profile,timing))
            self.assertTrue(any(row.get('status',0)>=400 for row in rows))
            self.assertFalse(f.complete(rows,phases[:-1],rows,profile,timing))
            for bad in (rows[:-1],rows+rows[:1],list(reversed(rows))):
                self.assertFalse(f.complete(bad,phases,rows,profile,timing))

    def test_equal_wrong_sides_do_not_override_oracle_contract(self):
        for profile,case,update in (
            ('batch','matrix.default_service.default.login',{'status':500}),
            ('ttl','partial.null.login',{'orphan':False}),
            ('ttl','explicit.snapshot.old1.renew_self',{'auth_num_uses':2}),
            ('ttl','restart.original_cap.lookup.lease',{'creation_ttl':1}),
            ('ttl','aliases.validation_order.mixed.write',{'status':204}),
            ('ttl','aliases.validation_order.create.response_shape',{'warnings_present':False}),
            ('ttl','ordinary.currentmax.past.renew_self',{'status':200}),
            ('ttl','children.child.no_leaf',{'certificate_metadata_keys_exact':False})):
            rows,phases,timing=self.sample(profile);bad=copy.deepcopy(rows)
            target=next((r for r in bad if r['case']==case),None)
            if target is None and profile=='batch':target=next(r for r in bad if r.get('auth') is True)
            self.assertIsNotNone(target,case);target.update(update)
            self.assertFalse(f.complete(bad,phases,rows,profile,timing),case)

    def test_dynamic_fields_require_actual_timing_evidence(self):
        rows,phases,timing=self.sample('ttl')
        self.assertFalse(f.complete(rows,phases,rows,'ttl',{}))
        next(iter(timing.values()))['passed']=False
        self.assertFalse(f.complete(rows,phases,rows,'ttl',timing))
        self.assertFalse(f.cap_window((100.1,100.2),120,102.1,102.3,120))
        self.assertTrue(f.cap_window((100.1,100.2),120,102.1,102.3,118))
        self.assertFalse(f.cap_window((100.1,100.2),120,102.1,102.3,1))
        self.assertTrue(f.expiry_window((160.1,160.2),103,103.1,57))
        self.assertFalse(f.expiry_window((160.1,160.2),103,103.1,60))

    def test_poll_count_changes_are_accounted_not_filtered(self):
        rows,phases,timing=self.sample('ttl');bad=copy.deepcopy(rows)
        group=f.AGES[0]
        bad=[r for r in bad if not (f.POLL.fullmatch(r['case']) and r['case'].startswith(group+'.poll')
                                  and int(f.POLL.fullmatch(r['case']).group(2))>1)]
        next(r for r in bad if r['case']==group+'.ready')['read_only_polls']=1
        self.assertTrue(f.complete(bad,phases,rows,'ttl',timing))
        next(r for r in bad if r['case']==group+'.ready')['read_only_polls']=2
        self.assertFalse(f.complete(bad,phases,rows,'ttl',timing))
        bad=copy.deepcopy(rows)
        next(r for r in bad if r['case']==group+'.poll2')['status']=503
        self.assertFalse(f.complete(bad,phases,rows,'ttl',timing))
        bad=[r for r in rows if r['case']!=group+'.poll1.lease']
        self.assertFalse(f.complete(bad,phases,rows,'ttl',timing))

    def test_clock_measurement_tracks_failed_renew_and_original_issue(self):
        t=f.Timing();token='synthetic-token-never-executed'
        t.observe('explicit.snapshot.login','auth/cert/login',{},'',
            {'auth':{'client_token':token,'accessor':'synthetic-accessor','lease_duration':60}},100.1,100.2)
        t.observe('explicit.snapshot.old1.renew_self','auth/token/renew-self',{},token,
            {'auth':{'client_token':token,'lease_duration':118}},102.1,102.2)
        self.assertTrue(t.rows['explicit.snapshot.old1.renew_self']['passed'])
        t.observe('ordinary.currentmax.past.renew_self','auth/token/renew-self',{},token,
                  {'errors':['static']},103.1,103.2)
        t.observe('lookup','auth/token/lookup',{'token':token},None,
            {'data':{'creation_time':100,'ttl':116}},104.1,104.2)
        self.assertTrue(t.rows['lookup']['passed'])
        t.observe('wrong','auth/token/lookup',{'token':token},None,
            {'data':{'creation_time':104,'ttl':300}},104.1,104.2)
        self.assertFalse(t.rows['wrong']['passed'])
        self.assertNotIn(token,json.dumps(t.rows))

    def test_only_safe_projections_and_exact_shape_are_allowed(self):
        rows,phases,timing=self.sample('batch')
        for change in ({'token':'private'}, {'errors':['private']}, {'status':True}, {'certificate_metadata_keys_exact':1}):
            bad=copy.deepcopy(rows);bad[0].update(change)
            self.assertFalse(f.safe_rows(bad))
            self.assertFalse(f.complete(bad,phases,rows,'batch',timing))
        self.assertFalse(f.safe_rows([{'case':'fiction','passed':True}]))

    def test_calibration_rejects_unsafe_or_unfinished_receipt(self):
        profile='ttl';values=f.PROFILES[profile];original,_=f.calibration(profile)
        def digest(path):return values[3] if Path(path)==Path(values[0].__file__) else values[2]
        for key,value in [('status','passed'),('candidate_executed',True),('inputs_unchanged',False),
                          ('secrets_absent',False),('processes_stopped',False),('completed_scenarios',[])]:
            bad=copy.deepcopy(original);bad[key]=value
            with patch.object(f,'file_hash',digest),patch.object(Path,'read_text',return_value=json.dumps(bad)):
                with self.assertRaises(ValueError,msg=key):f.calibration(profile)
        with patch.object(f,'file_hash',return_value='0'*64):
            with self.assertRaises(ValueError):f.calibration(profile)

    def test_optional_listener_still_checks_leaf_binding_and_chain(self):
        from types import SimpleNamespace
        fixture=SimpleNamespace(root=Path('/not-executed'),address='https://127.0.0.1:1',token='root')
        trace=SimpleNamespace(timing=SimpleNamespace(tokens={'synthetic':{'binding_probe':True}}),
            client=SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=200)))
        plain=SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=400))
        wrong=SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=403))
        with patch.object(f,'tls_client',side_effect=[plain,wrong]):
            with patch.object(f,'peer_rejected_client_chain',return_value=True):
                self.assertTrue(f.verify_optional_tls(fixture,trace)['untrusted_chain_tls_rejected'])
        with patch.object(f,'tls_client',side_effect=[plain,wrong]):
            with patch.object(f,'peer_rejected_client_chain',return_value=False):
                with self.assertRaises(f.ScenarioFailure):f.verify_optional_tls(fixture,trace)
        accepted=SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=200))
        with patch.object(f,'tls_client',side_effect=[accepted,wrong]):
            with patch.object(f,'peer_rejected_client_chain',return_value=True):
                with self.assertRaises(f.ScenarioFailure):f.verify_optional_tls(fixture,trace)

    def test_oracle_only_never_starts_candidate_and_failure_is_retained(self):
        import tempfile
        import sys
        import os
        from types import SimpleNamespace
        expected={name:self.sample(name) for name in f.PROFILES}
        for failed in (False,True):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);parent.chmod(0o700)
                binary=parent/'bao';binary.write_bytes(b'not-executed')
                archive=parent/'oracle.tar.gz';archive.write_bytes(b'not-executed')
                output=parent/'report.json';created=[];stopped=[]
                original_hash=f.file_hash
                calibration,_=f.calibration('batch')
                def digest(path):
                    if Path(path)==binary:return calibration['oracle_binary_sha256']
                    if Path(path)==archive:return calibration['oracle_archive_sha256']
                    return original_hash(path)
                class Fixture:
                    def __init__(self,binary,root):
                        self.root=root;root.mkdir(mode=0o700)
                        for name,value in [('server.json','{}'),('client.crt','PUBLIC TEST CERT')]:
                            (root/name).write_text(value);(root/name).chmod(0o600)
                    def start(self):raise AssertionError('oracle-only started candidate')
                    def stop(self):pass
                def start(port):
                    root=parent/('oracle-'+str(len(created)));root.mkdir(mode=0o700)
                    for name,value in [('root.token','synthetic-root-0123456789'),('unseal.key','synthetic-key-0123456789')]:
                        (root/name).write_text(value);(root/name).chmod(0o600)
                    process=SimpleNamespace(exit=None);process.poll=lambda:process.exit
                    result=dict(root=str(root),token_file=str(root/'root.token'),process=process,
                        address='https://127.0.0.1:1',ca_file=str(root/'ca.crt'))
                    created.append(result);return result
                def stop(instance):instance['process'].exit=0;stopped.append(instance)
                def run(profile):
                    def execute(trace,*args):
                        if failed:raise f.ScenarioFailure('synthetic_failure')
                        rows,phases,timing=expected[profile]
                        trace.rows.extend(copy.deepcopy(rows));trace.finished.extend(phases)
                        trace.timing.rows.update(copy.deepcopy(timing))
                    return execute
                argv=['runner','--oracle-only','--work-parent',str(parent),'--output',str(output)]
                with (patch.object(sys,'argv',argv),patch.dict(os.environ,{'HB_ORACLE_ARCHIVE':str(archive)}),
                    patch.object(f,'verify_inputs',return_value=binary),patch.object(f,'file_hash',side_effect=digest),
                    patch.object(f,'Fixture',Fixture),patch.object(f,'start_oracle',side_effect=start),
                    patch.object(f,'stop_oracle',side_effect=stop),patch.object(f,'tls_client'),
                    patch.object(f,'safe_files',return_value=True),patch('builtins.print'),
                    patch.object(f.batch,'run',side_effect=run('batch')),
                    patch.object(f.lifetime,'run',side_effect=run('ttl'))):
                    self.assertEqual(f.main(),int(failed))
                report=json.loads(output.read_text())
                self.assertTrue(report['processes_stopped'])
                self.assertEqual(len(created),1 if failed else 2)
                self.assertTrue(all(item['process'].poll()==0 for item in created))
                self.assertEqual(report['status'],'failed' if failed else 'passed')
                self.assertFalse(report['mutating_requests_retried'])
                if failed:self.assertTrue(Path(report['retained_failure_work_dir']).exists())
                else:self.assertIsNone(report['retained_failure_work_dir'])
                self.assertFalse(any(key.endswith('.candidate') for key in report['cases']))


if __name__=='__main__':unittest.main()
