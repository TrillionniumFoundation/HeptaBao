#!/usr/bin/env python3
"""Only source parse/compile and public-original binding; no candidate execution."""
import ast, hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
raw=''.join(p.read_text() for p in sorted(root.glob('input-part-*.json.txt')))
x=json.loads(raw);checks=[]
def ck(name,value):
    if value is not True:raise AssertionError(name)
    checks.append({'case':name,'passed':True})
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def assigns(tree):return {n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
def pvalue(node,context):
    if isinstance(node,ast.Constant) and isinstance(node.value,str):return node.value
    if isinstance(node,ast.Name):return context[node.id]
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='Path' and len(node.args)==1 and not node.keywords:return pvalue(node.args[0],context)
    if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Div):return pvalue(node.left,context)+'/'+pvalue(node.right,context)
    raise AssertionError('nonliteral path expression')
known={'mac_current_outer_inputs_r2.py','mac_current_outer_wal_r1.py','mac_owned_launchd_r3.py','mac_current_server_owner_r1.py'}
actual={k:json.loads(v) for k,v in x['actualRaw'].items() if k!='terminal'}
for k,v in x['actualRaw'].items():ck('original.'+k+'.wholepin',pin(v.encode())==x['actualPins'][k])
normal=actual['normal'];native=actual['native'];info=actual['serverInfo'];core=actual['combined'];authority=actual['authority']
artifact=normal['artifacts']['heptabao-server'];commit='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec';tree='eba5e650bd080b8ad41ea52a2bc68867f541d255'
for label,obj in [('normal',normal),('native',native),('core',core),('source',actual['sourceResult'])]:
    ck(label+'.exactsource',obj['source_commit']==commit and obj['source_tree']==tree)
ck('normal.real successful release',normal['schema']=='heptabao.native-default-build-result.v1' and normal['normal_default_candidate'] is True and normal['source_freeze_verified'] is True and normal['build_exit_code']==0 and normal['build_finished_success'] is True and normal['timed_out'] is False and normal['native_abi']=='aarch64-apple-darwin')
ck('native.provenance',native['schema']=='heptabao.native-build.v1' and native['binary_sha256']==artifact['sha256'] and native['provenance']['result_sha256']==x['actualPins']['normal']['sha256'] and native['features']==['default','native-v6-ha','native-v6-storage'] and native['native_abi']=='aarch64-apple-darwin')
ck('core.whole61 scope',core['schema']=='heptabao.mac-normal-same-root-publication-exact-tests.v1' and core['status']=='passed' and core['test_count']==44 and core['additional_test_counts']=={'ingress_observer':7,'cold_h2':9,'same_root_publication':1} and core['selected_test_total']==61 and core['original_60_status']=='passed' and core['source_unchanged'] is True and core['release_artifacts_unchanged'] is True)
ck('normal.native.core.same retained server',core['release_artifacts']['heptabao-server']==artifact and info['path']==artifact['path'] and info['size']==artifact['bytes']==92398928 and info['sha256']==artifact['sha256']=='c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63')
ck('artifact.profile exact',artifact['features']==native['features'] and artifact['profile']=={'debug_assertions':True,'debuginfo':0,'opt_level':'3','overflow_checks':True,'test':False})
ck('artifact.independent metadata',info['mode']==0o500 and info['metadata']['uid']==501 and info['metadata']['gid']==20 and info['metadata']['link_count']==1 and info['version']=='16777244:72626763:92398928:1793876826299674364:1793876826322472740')
for label,job in [('authority','1a1ab60127b-fc05-4d18'),('sourceAuthority','1a1ab595aa2-fc05-4ce1')]:
    v=actual[label];ck(label+'.actual terminal',v['job_id']==job and v['exit_code']==0 and v['state']=='succeeded' and v['output_complete'] is True and v['output_durable'] is True and v['timed_out'] is False and v['cancelled'] is False and v['terminal_publication_confirmed'] is True)
ck('source.actual prepared independent',actual['sourceResult']['status']=='prepared' and actual['sourceResult']['source_clean'] is True and actual['sourceResult']['full_strict_fsck_passed'] is True and actual['sourceResult']['production_changed'] is False)
ck('root.core accepted specific61',actual['rootReview']['status']=='PASS_61_ACTUAL_CORE_AND_NEW_TEST_ORIGINALS' and actual['rootReview']['core_blob']==x['actualPins']['combined']['blob'] and actual['rootReview']['core_sha256']==x['actualPins']['combined']['sha256'] and actual['rootReview']['normal_tests_passed']==61 and actual['rootReview']['owned_children_closed']==48)
ck('root.artifact acceptance onlysource',actual['artifactRootReview']['status']=='PASS_THREE_INDEPENDENT_WHOLE_RETAINED_ARTIFACT_INFOS' and actual['artifactRootReview']['source_only_binding_ready'] is True and actual['artifactRootReview']['WAL_runtime_GO'] is False and actual['artifactRootReview']['core_blob']==x['actualPins']['combined']['blob'] and actual['artifactRootReview']['infos']['server']==info)
changed=0;unchanged=0;compile_count=0
for path,new in sorted(x['candidate'].items()):
    old=x['baseline'][path];transforms=x['transforms'][path];name=path.split('/')[-1]
    ck(path+'.wholepin',pin(new.encode())==x['pins'][path])
    inverse=new
    for change in reversed(transforms):
        if inverse.count(change['after'])!=1:raise AssertionError('nonunique reverse '+path)
        inverse=inverse.replace(change['after'],change['before'])
    ck(path+'.strict replacement inverse',inverse==old)
    if not transforms:
        ck(path+'.unchanged',new==old and name not in known);unchanged+=1;continue
    ck(path+'.only four declared callers',name in known);changed+=1
    node=ast.parse(new,filename=path);compile(node,path,'exec');compile_count+=1;a=assigns(node)
    ck(path+'.ready literal bound',ast.literal_eval(a['BINDING_READY']) is True)
    if name=='mac_current_outer_inputs_r2.py':
        cls=next(n for n in node.body if isinstance(n,ast.ClassDef) and n.name=='Inputs');entry=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
        nr=pvalue(a['NORMAL_ROOT'],{});binary=pvalue(a['BINARY'],{'NORMAL_ROOT':nr})
        public={ast.literal_eval(k):v for k,v in zip(a['PUBLIC_INPUTS'].keys,a['PUBLIC_INPUTS'].values)}
        for k,norm in [('normal',x['actualPins']['normal']),('native_build',x['actualPins']['native'])]:
            tup=public[k];ck(path+'.'+k+'.actual receipt',pvalue(tup.elts[0],{'NORMAL_ROOT':nr})==(native['provenance']['result_path'] if k=='normal' else nr+'/native-build.public.json') and ast.literal_eval(tup.elts[1])==norm['sha256'] and ast.literal_eval(tup.elts[2])==65536)
        ck(path+'.known source',ast.literal_eval(a['COMMIT'])==commit and ast.literal_eval(a['TREE'])==tree)
    elif name=='mac_owned_launchd_r3.py':
        cls=next(n for n in node.body if isinstance(n,ast.ClassDef) and n.name=='OwnedLaunchd');entry=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
        binary=pvalue(a['SERVER'],{});ck(path+'.actual SHA',ast.literal_eval(a['SERVER_SHA'])==artifact['sha256'])
    else:
        entry=next(n for n in node.body if isinstance(n,ast.FunctionDef) and n.name=='main');binary=pvalue(a['BINARY'],{})
        if name=='mac_current_outer_wal_r1.py':ck(path+'.known source',ast.literal_eval(a['COMMIT'])==commit and ast.literal_eval(a['TREE'])==tree)
    ck(path+'.first guard unchanged',ast.dump(entry.body[0],include_attributes=False)==ast.dump(ast.parse("need(BINDING_READY is True,'mac_normal61_binding_not_admitted')").body[0],include_attributes=False))
    ck(path+'.actual binary path',binary==artifact['path'])
    if name!='mac_owned_launchd_r3.py':ck(path+'.actual bytes+SHA',ast.literal_eval(a['BINARY_SHA'])==artifact['sha256'] and ast.literal_eval(a['BINARY_BYTES'])==artifact['bytes'])
ck('exact4changed18whole retained',changed==4 and unchanged==18 and compile_count==4 and len(x['candidate'])==22)
ck('candidate22 actual source pins',x['candidateDocument']['sourcePins']=={p.split('/')[-1]:v['sha256'] for p,v in x['pins'].items()})
for k in ('syntheticBinding','nativeBinding','walBinding','utilityPins','publicVolumeAnchorSha256','budgets'):ck('candidate unchanged '+k,x['candidateDocument'][k]==x['baselineCandidate'][k])
ck('original scopes not granted',x['plan']['hostCalls']==0 and x['plan']['runtimeRequests']==[] and x['plan']['inertRequests']==[] and x['binding']['authority']['newRuntime'] is False and x['binding']['authority']['newInert'] is False)
ck('original budgets',x['plan']['budgets']=={'inertSeconds':45,'inertVolumeSeconds':30,'inertSupervisorSeconds':60,'controllerSeconds':900,'supervisorSeconds':1080,'managerSeconds':600,'managerFailureCleanupSeconds':60,'phaseSeconds':120,'captureSeconds':45,'registryQueryThroughClosureSeconds':3,'nativeSeconds':[15,8,3],'httpSeconds':10,'readySeconds':30,'tlsCommandSeconds':30})
ck('originalbytebounds',x['plan']['bounds']=={'registryWalBytes':5969912,'rowBytes':1048576,'aggregateReadAndReturnedBytes':8388608,'privateCapsuleBytes':4194304,'entryPublicReportBytes':262144,'captureLibraryEnvelopeBytes':196608})
print(json.dumps({'schema':'heptabao.mac-current-4e808-actual-source-static-result.r1','ok':True,'checkCount':len(checks),'checks':checks,'inputBytes':len(raw.encode()),'inputSha256':hashlib.sha256(raw.encode()).hexdigest(),'newPythonCompileOnly':compile_count,'wholeUnchanged':unchanged,'candidateFunctionsExecuted':0,'modulesImported':0,'hostCalls':0,'privateInputsRead':0,'runtimeQualified':False},sort_keys=True,indent=2))
