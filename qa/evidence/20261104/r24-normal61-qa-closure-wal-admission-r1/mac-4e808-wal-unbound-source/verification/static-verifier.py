#!/usr/bin/env python3
"""Static-only verification. Parse/compile source without import or execution."""
import ast, hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
parts=sorted(root.glob('input-part-*.json.txt'))
raw=''.join(path.read_text(encoding='utf-8') for path in parts)
x=json.loads(raw)
checks=[]
def ck(name,value):
    if value is not True:raise AssertionError(name)
    checks.append({'case':name,'passed':True})
def sha(v):return hashlib.sha256(v).hexdigest()
def blob(v):return hashlib.sha1(b'blob '+str(len(v)).encode()+b'\0'+v).hexdigest()
def assigns(tree):return {n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
def exact_guard(node):
    return ast.dump(node,include_attributes=False)==ast.dump(ast.parse("need(BINDING_READY is True,'mac_normal61_binding_not_admitted')").body[0],include_attributes=False)
expected_product={'mac_current_outer_inputs_r2.py','mac_current_outer_wal_r1.py','mac_owned_launchd_r3.py','mac_current_server_owner_r1.py'}
expected_rootonly={'mac_auth_rows_cas_r1.mjs','mac_current_capture_entry_wal_r1.py','mac_current_cycle_r2.mjs','mac_current_fixture_materializer_r1.py','mac_current_phase_owner_r2.py','mac_single_native_r2.mjs','mac_t5_volume_guard_r1.py'}
ck('22 exact baseline/candidate/pin/transform keys',set(x['baseline'])==set(x['candidate'])==set(x['pins'])==set(x['transforms']) and len(x['candidate'])==22)
python_count=0
for path,new in sorted(x['candidate'].items()):
    old=x['baseline'][path];pin=x['pins'][path];b=new.encode()
    ck(path+': full SHA256/Git/bytes',pin=={'bytes':len(b),'sha256':sha(b),'blob':blob(b)})
    inverse=new
    for change in reversed(x['transforms'][path]):
        ck(path+': inverse unique '+str(len(checks)),inverse.count(change['after'])==1)
        inverse=inverse.replace(change['after'],change['before'])
    ck(path+': whole inverse byte-exact baseline',inverse==old)
    name=path.split('/')[-1]
    if name in expected_rootonly:
        ck(path+': one root literal only',x['transforms'][path]==[{'before':'mac-authbus-df026-current-registry-wal-r1','after':'mac-authbus-4e808-current-registry-wal-r1'}])
    elif name not in expected_product:
        ck(path+': retained whole bytes',new==old and x['transforms'][path]==[])
    if path.endswith('.py'):
        t=ast.parse(new,filename=path);compile(t,path,'exec');python_count+=1
        a=assigns(t)
        if name in expected_product:
            ck(path+': explicit unbound flag',ast.literal_eval(a['BINDING_READY']) is False)
            if name=='mac_current_outer_inputs_r2.py':
                cls=next(n for n in t.body if isinstance(n,ast.ClassDef) and n.name=='Inputs')
                entry=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
                for var in ('NORMAL_ROOT','BINARY','BINARY_SHA','BINARY_BYTES'):
                    ck(path+': '+var+' not provisionally bound',ast.literal_eval(a[var]) is None)
                public=a['PUBLIC_INPUTS']
                pairs={ast.literal_eval(k):v for k,v in zip(public.keys,public.values)}
                ck(path+': actual receipts not bound',all(ast.literal_eval(pairs[k])==(None,None,65536) for k in ('normal','native_build')))
            elif name=='mac_owned_launchd_r3.py':
                cls=next(n for n in t.body if isinstance(n,ast.ClassDef) and n.name=='OwnedLaunchd')
                entry=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
                ck(path+': actual server not bound',ast.literal_eval(a['SERVER']) is None and ast.literal_eval(a['SERVER_SHA']) is None)
                ck(path+': exact fresh labels',ast.literal_eval(a['LABELS'])=={'server':'org.heptabao.qa.mac-authbus-4e808-wal-r1.server','consumer':'org.heptabao.qa.mac-authbus-4e808-wal-r1.consumer'})
            else:
                entry=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=='main')
                ck(path+': actual binary slots not bound',all(ast.literal_eval(a[k]) is None for k in ('BINARY','BINARY_SHA','BINARY_BYTES')))
            ck(path+': refusal is first actual entry statement',exact_guard(entry.body[0]))
        if name in ('mac_current_outer_inputs_r2.py','mac_current_outer_wal_r1.py'):
            ck(path+': exact known source',ast.literal_eval(a['COMMIT'])=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and ast.literal_eval(a['TREE'])=='eba5e650bd080b8ad41ea52a2bc68867f541d255')
        if name=='mac_current_outer_wal_r1.py':
            ck(path+': exact source inventory',set(ast.literal_eval(a['NAMES']))=={n.split('/')[-1] for n in x['candidate']} and len(ast.literal_eval(a['NAMES']))==22)
            for k,v in [('SYNTHETIC','syntheticBinding'),('NATIVE_BINDING','nativeBinding'),('WAL_BINDING','walBinding')]:
                ck(path+': '+k+' original exact',ast.literal_eval(a[k])==x['baselineCandidate'][v]==x['candidateDocument'][v])
        ck(path+': AST/compile only',True)
ck('18 Python AST compiled, no module imported',python_count==18)
ck('candidate exact22 source hashes',x['candidateDocument']['sourcePins']=={p.split('/')[-1]:v['sha256'] for p,v in x['pins'].items()})
for k in ('syntheticBinding','nativeBinding','walBinding','utilityPins','publicVolumeAnchorSha256','budgets'):
    ck('candidate preserves '+k,x['candidateDocument'][k]==x['baselineCandidate'][k])
ck('future actual slots all null',all(v is None for v in x['template']['futureActual'].values()))
ck('binding readiness false',x['template']['bindingReady'] is False and x['plan']['bindingReady'] is False)
ck('no executable requests',x['plan']['runtimeRequests']==[] and x['plan']['inertRequests']==[] and x['plan']['hostCalls']==0)
b=x['plan']['budgets'];bounds=x['plan']['bounds']
ck('all original temporal budgets',b=={'inertSeconds':45,'inertVolumeSeconds':30,'inertSupervisorSeconds':60,'controllerSeconds':900,'supervisorSeconds':1080,'managerSeconds':600,'managerFailureCleanupSeconds':60,'phaseSeconds':120,'captureSeconds':45,'registryQueryThroughClosureSeconds':3,'nativeSeconds':[15,8,3],'httpSeconds':10,'readySeconds':30,'tlsCommandSeconds':30})
ck('all original byte bounds',bounds=={'registryWalBytes':5969912,'rowBytes':1048576,'aggregateReadAndReturnedBytes':8388608,'privateCapsuleBytes':4194304,'entryPublicReportBytes':262144,'captureLibraryEnvelopeBytes':196608})
print(json.dumps({'schema':'heptabao.mac-current-4e808-static-source-result.r1','ok':True,'inputBytes':len(raw.encode()),'inputSha256':sha(raw.encode()),'sourceFiles':22,'pythonCompileOnly':18,'checkCount':len(checks),'checks':checks,'modulesImported':0,'candidateFunctionsExecuted':0,'hostCalls':0,'networkCalls':0,'privateInputsRead':0,'runtimeQualification':False},sort_keys=True,indent=2))
