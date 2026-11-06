#!/usr/bin/env python3
"""New create-only revision; preserves staged, unexecuted r1 original bytes."""
import ast,difflib,hashlib,json
from pathlib import Path
WORK=Path('/workspace/scratch/c9fe536787d9/main3-authbus-work');OUT=WORK/'source-api-r2'
old=json.loads((WORK/'staging-api-r1.public.json').read_text())
manifest=json.loads((WORK/'manifest-api-r1.public.json').read_text())
def sha(raw):return hashlib.sha256(raw).hexdigest()
def once(s,old,new):
    assert s.count(old)==1,old[:100]
    return s.replace(old,new)
def revise(s):
    for stem in ('mac-authbus-main3-api','mac-authbus-main3-api-preparation','mac-authbus-main3-api-journal'):
        s=s.replace(stem+'-20261106-r1',stem+'-20261106-r2')
    for schema in ('heptabao.mac-main3-api-preparation-terminal','heptabao.mac-main3-api-preparation',
                   'heptabao.mac-main3-api-journal','heptabao.mac-main3-current-api-qualification'):
        s=s.replace(schema+'.r1',schema+'.r2')
    return s
sources={}
for name,s in old['sources'].items():
    assert sha(s.encode())==manifest['sourcePins'][name]['sha256'],name
    sources[name]=revise(s)
s=sources['main3_api_cycle.py']
s=once(s,"/v1/sys/internal/native-v6/activate","/v1/sys/storage/native-v6/activate")
s=once(s,"        need(not readiness or (method=='GET' and route=='/v1/sys/health' and body is None and token==''),'health_only_tcp_refusal_wait')",
 "        if category=='activate':need(method=='POST' and route=='/v1/sys/storage/native-v6/activate','normal_configured_storage_activation_only')\n        need(not readiness or (method=='GET' and route=='/v1/sys/health' and body is None and token==''),'health_only_tcp_refusal_wait')")
s=once(s,"api.check('initial.native_format_two',capacity.get('data',{}).get('native_kv2_reader_format')==2)",
 "api.check('initial.native_format_two',capacity.get('data',{}).get('native_kv2_reader_format')==2\n+              and capacity['data'].get('state_storage_format')=='heptabao-state-records-v6')".replace('\n+','\n'))
s=once(s,"api.check('cold.native_format_two_preserved',capacity.get('data',{}).get('native_kv2_reader_format')==2)",
 "api.check('cold.native_format_two_preserved',capacity.get('data',{}).get('native_kv2_reader_format')==2\n+              and capacity['data'].get('state_storage_format')=='heptabao-state-records-v6')".replace('\n+','\n'))
sources['main3_api_cycle.py']=s
s=sources['main3_source_fence.py']
s=once(s,'import time\n','import time\nfrom main3_source_authority import validate_authority,SOURCE_SELECTION_AUTHORITY,SDK_SOURCE_PINS\n')
s=once(s,"CAPSULE=CAPSULE_ROOT/'output/selected-owner-credentials.private.json'",
 "CAPSULE=CAPSULE_ROOT/'output/selected-owner-credentials.private.json'\nPREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-preparation-20261106-r2')\nBINDING=PREP/'capsule-admission-binding.private.json'")
s=once(s,'def __init__(self,phase_until,*,capsule_path=CAPSULE,clock=time.monotonic):',
 'def __init__(self,phase_until,*,capsule_path=CAPSULE,clock=time.monotonic,admit_mode="run"):')
s=once(s,'        self.validate(self.doc)\n        self.remaining()',
 '        self.validate(self.doc)\n        self.bind_admission(admit_mode)\n        self.remaining()')
s=once(s,"        metadata=doc.get('registeredMetadataFileBindings')",
 "        validate_authority(doc,need)\n        metadata=doc.get('registeredMetadataFileBindings')")
at='    def namespace(self,bundle,scope):'
body='''    @staticmethod
    def expected_binding(identity):
        return {'schema':'heptabao.main3-capsule-admission-binding.private.r1',
            'capsulePath':str(CAPSULE),'capsuleIdentity':list(typed_identity(identity)),
            'sourceCaptureJob':CAPTURE_JOB,'sourceCaptureWorkerSha256':CAPTURE_WORKER_SHA}
    @classmethod
    def validate_binding(cls,value,identity):
        need(value==cls.expected_binding(identity),'same_authoritatively_qualified_capsule_generation')
    def bind_admission(self,mode):
        self.remaining();need(mode in ('qualify','run'),'fixed_private_capsule_admission_mode')
        parent=os.open(PREP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.opened+=1
        try:
            p=os.fstat(parent)
            need(stat.S_ISDIR(p.st_mode) and p.st_uid==501 and stat.S_IMODE(p.st_mode)==0o700,
                 'admission_fixed_private_parent')
            if mode=='qualify':
                raw=(json.dumps(self.expected_binding(self.capsule_identity),sort_keys=True,separators=(',',':'))+'\\n').encode()
                fd=os.open(BINDING.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent);self.opened+=1
                try:
                    before=os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
                         and stat.S_IMODE(before.st_mode)==0o600,'new_private_capsule_binding')
                    offset=0
                    while offset<len(raw):
                        self.remaining();count=os.write(fd,raw[offset:]);need(count>0,'private_admission_write_progress');offset+=count
                    os.fsync(fd);os.fsync(parent);after=os.fstat(fd)
                    need(ident(before)[:6]==ident(after)[:6] and after.st_size==len(raw)
                         and ident(after)==ident(os.stat(BINDING.name,dir_fd=parent,follow_symlinks=False)),
                         'private_admission_binding_durable_identity')
                finally:os.close(fd);self.closed+=1
            else:
                raw,_=self.read(BINDING,8192,private=True)
                self.validate_binding(json.loads(raw),self.capsule_identity)
        finally:os.close(parent);self.closed+=1
        need(self.opened==self.closed,'capsule_admission_all_descriptors_closed')
        self.remaining()
'''
s=once(s,at,body+at)
s=once(s,"return {'captureJob':CAPTURE_JOB,'captureWorkerSourceSha256':CAPTURE_WORKER_SHA,",
 "return {'captureJob':CAPTURE_JOB,'captureWorkerSourceSha256':CAPTURE_WORKER_SHA,\n                'sourceSelectionAuthority':SOURCE_SELECTION_AUTHORITY,\n                'publicSdkCodePinCount':len(SDK_SOURCE_PINS),'qualificationCapsuleIdentityBound':True,")
sources['main3_source_fence.py']=s
sources['main3_source_authority.py']=(OUT/'main3_source_authority.py').read_text()
s=sources['main3_api_controller.py']
s=once(s,"'main3_source_fence.py','main3_api_cycle.py','test_main3_api_guards.py')",
 "'main3_source_fence.py','main3_source_authority.py','main3_api_cycle.py','test_main3_api_guards.py')")
s=once(s,"    need(Path(__file__).resolve()==QA/'main3_api_controller.py','only_pinned_remote_controller')",
 """    config=json.loads(stable_read(ROOT/'server/server.json',131072))
    need(set(config)=={'listen','data_dir','audit_file','tls_cert_file','tls_key_file','storage'}
         and config['storage']=={'native_v6_file':{'path':str(ROOT/'server/data')}}
         and config['data_dir']==str(ROOT/'server/data') and config['listen']=='127.0.0.1:'+str(plan['port'])
         and config['tls_cert_file']==str(ROOT/'server/tls/server.crt')
         and config['tls_key_file']==str(ROOT/'server/tls/server.key')
         and config['audit_file']==str(ROOT/'server/audit.jsonl'), 'exact_normal_native_file_configuration_without_fixture_options')
    need(Path(__file__).resolve()==QA/'main3_api_controller.py','only_pinned_remote_controller')""")
s=once(s,'active_fence=CapsuleFence(min(until,time.monotonic()+45.0))',
 'active_fence=CapsuleFence(min(until,time.monotonic()+45.0),admit_mode="qualify")')
s=once(s,"'actualPluginSdkPhaseExecuted':False,'productionClientRollbackQualified':False,",
 "'actualPluginSdkPhaseExecuted':False,'productionClientRollbackQualified':False,\n        'normalNativeStorageConfigurationVerified':True,'fixtureOptionsEnabled':False,\n        'normalActivationPath':'sys/storage/native-v6/activate',")
sources['main3_api_controller.py']=s
s=sources['test_main3_api_guards.py']
s=once(s,"'configurationIdentity':IDENT,'configurationSha256':'a'*64,",
 "'configurationIdentity':IDENT,'configurationSha256':'a'*64,\n        'sourceSelectionAuthority':dict(f.SOURCE_SELECTION_AUTHORITY),'sdkSourcePins':dict(f.SDK_SOURCE_PINS),")
at='    def test_phase_deadline_cannot_be_replenished(self):'
tests='''    def test_other_source_selection_job_rejected(self):
        value=capsule();value['sourceSelectionAuthority']['jobId']='other'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_other_public_order_receipt_rejected(self):
        value=capsule();value['sourceSelectionAuthority']['originalResultSha256']='f'*64
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_missing_public_sdk_pin_rejected(self):
        value=capsule();value['sdkSourcePins'].pop(next(iter(value['sdkSourcePins'])))
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_exact_qualification_identity_allowed(self):
        value=f.CapsuleFence.expected_binding(IDENT);f.CapsuleFence.validate_binding(value,IDENT)
    def test_changed_qualification_identity_rejected(self):
        value=f.CapsuleFence.expected_binding(IDENT);value['capsuleIdentity'][1]='999'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate_binding(value,IDENT)
    def test_wrong_qualification_path_rejected(self):
        value=f.CapsuleFence.expected_binding(IDENT);value['capsulePath']='/another/private.json'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate_binding(value,IDENT)
'''
s=once(s,at,tests+at)
at='    def test_fixed_request_bound_prevents_dispatch(self):'
tests='''    def test_normal_storage_activation_route_accepted(self):
        self.response.body=b'';self.response.length='0';self.response.status=204
        self.api.call('normal.activate','POST','/v1/sys/storage/native-v6/activate',{},expected=204,category='activate')
        self.assertEqual(self.connect.call_count,1)
    def test_fixture_only_activation_route_rejected_before_dispatch(self):
        with self.assertRaises(f.Refused):self.api.call('fixture.refused','POST','/v1/sys/internal/native-v6/activate',{},category='activate')
        self.connect.assert_not_called()
'''
s=once(s,at,tests+at);sources['test_main3_api_guards.py']=s
for name,source in sources.items():ast.parse(source);(OUT/name).write_text(source)
pins={name:{'bytes':len(source.encode()),'sha256':sha(source.encode())} for name,source in sources.items()}
preparer=revise(old['preparerSource']);lines=preparer.splitlines(True)
indices=[i for i,l in enumerate(lines) if l.startswith('EXPECTED_PINS=')];assert len(indices)==1
lines[indices[0]]='EXPECTED_PINS='+repr(pins)+'\n';preparer=''.join(lines);ast.parse(preparer)
(WORK/'prepare_main3_api_r2.bound.py').write_text(preparer)
(WORK/'staging-api-r2.public.json').write_text(json.dumps({'sources':sources,'preparerSource':preparer},separators=(',',':')))
diff=''.join(''.join(difflib.unified_diff(old['sources'].get(n,'').splitlines(True),s.splitlines(True),fromfile='retained-unexecuted-r1/'+n,tofile='normal-main3-api-r2/'+n)) for n,s in sources.items())
(WORK/'main3-api-r2.diff').write_text(diff)
manifest.update(schema='heptabao.mac-main3-api-source-derivation.r2',sourcePins=pins,
    preparer={'bytes':len(preparer.encode()),'sha256':sha(preparer.encode())},
    retainedR1Status={'stagingJob':'1a1b1cc2471-fc05-7adb','stagingSucceeded':True,'qualificationAttempted':False,'serviceActions':0,'apiRequests':0},
    normalNativeStorageProfile='native_v6_file',normalActivationPath='sys/storage/native-v6/activate',
    fixtureOptionsEnabled=False,sourceAuthorityIntegratedIntoPinnedFence=True,
    privateCapsuleQualificationIdentityBoundWithoutHash=True)
(WORK/'manifest-api-r2.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
