import ast
import copy
import hashlib
import json
import re
from pathlib import Path

BASE=Path('/workspace/scratch/f86faac821c4')
OUT=BASE/'full34_mac4e808_source_r1'
I=json.loads((BASE/'full34_mac_source_inputs.json').read_text())
S=json.loads((BASE/'full34_local_assessment_input.json').read_text())
checks=[]
def check(name,condition):
    if not condition:raise AssertionError(name)
    checks.append({'name':name,'passed':True})
def sha(raw):return hashlib.sha256(raw.encode()).hexdigest()
def blob(raw):
    b=raw.encode();return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def text(path):return (OUT/path).read_text()
def sources(raw):
    t=ast.parse(raw)
    return {n.name:ast.get_source_segment(raw,n) for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}

candidate=text('candidate/run_current_mac_full34_r1.py')
original=text('reference/x230-current-unbound-wrapper.py')
check('source_ast_compiles_without_execution',isinstance(compile(candidate,'<candidate>','exec'),type(compile('','','exec'))))
before=sources(original);after=sources(candidate)
for name in ('need','sha','save','enc'):
    check('original_'+name+'_byte_equal',before[name]==after[name])
check('no_x230_transfer_admission_in_candidate','TRANSFER_SHA' not in candidate and 'transfer.result.public.json' not in candidate)
check('ready_false',next(n.value.value for n in ast.parse(candidate).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BINDING_READY' for t in n.targets)) is False)
check('single_original_product_run_call',candidate.count('p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)')==1)
check('original_product_run_expression_exact','p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)' in original)
check('readonly_prepare_has_no_product_calls',not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ('Popen','run') for n in ast.walk(ast.parse(after['readonly_prepare']))))
check('readonly_prepare_has_no_creation_calls',not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ('mkdir','write_bytes','write_text','touch','chmod','unlink') for n in ast.walk(ast.parse(after['readonly_prepare']))))
check('prepare_output_precedes_runtime_mkdir',candidate.index("if sys.argv[1]=='--prepare-only':")<candidate.index('OUT.parent.mkdir'))
check('actual_prepare_digest_guard_precedes_runtime_mkdir',candidate.index("'actual_prepare_binding_changed'")<candidate.index('OUT.parent.mkdir'))

# Strict unified hunk application, without invoking a patch process.
def apply(old,diff):
    lines=old.splitlines(keepends=True);patch=diff.splitlines(keepends=True);out=[];pos=0;i=2;hunks=0
    while i<len(patch):
        m=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n',patch[i])
        check('diff_hunk_header_'+str(i),m is not None)
        a=int(m.group(1));oc=int(m.group(2) or 1);nc=int(m.group(4) or 1)
        index=a-1 if oc else a
        check('diff_forward_order_'+str(i),index>=pos)
        out.extend(lines[pos:index]);pos=index;i+=1;used=added=0
        while i<len(patch) and not patch[i].startswith('@@ '):
            row=patch[i];tag=row[0];body=row[1:]
            check('diff_marker_'+str(i),tag in ' +-')
            if tag in ' -':
                check('diff_context_'+str(i),pos<len(lines) and lines[pos]==body)
                pos+=1;used+=1
            if tag in ' +':out.append(body);added+=1
            i+=1
        check('diff_counts_'+str(hunks),(used,added)==(oc,nc));hunks+=1
    out.extend(lines[pos:]);return ''.join(out),hunks
rebuilt,hunks=apply(original,text('diff/current-wrapper-to-mac.diff'))
check('whole_strict_diff_target',rebuilt==candidate)

trees={k:json.loads(S[k]) for k in ('root_tree','qa_tree','acceptance_tree','single_tree','tools_tree','migration_tree')}
def member(parent,name,oid):
    check('member_'+name,any(e['path']==name and e['sha']==oid for e in parent['tree']))
member(trees['root_tree'],'qa',trees['qa_tree']['sha'])
member(trees['qa_tree'],'openbao-acceptance',trees['acceptance_tree']['sha'])
member(trees['qa_tree'],'single-node',trees['single_tree']['sha'])
member(trees['root_tree'],'tools',trees['tools_tree']['sha'])
member(trees['tools_tree'],'migration',trees['migration_tree']['sha'])
mapping={'driver':('acceptance_tree','kv2_271_lossless_native_live.py'),
         'official_launcher':('acceptance_tree','official_openbao_launcher.py'),
         'owned_process':('acceptance_tree','owned_process.py'),
         'online_evidence':('acceptance_tree','online_evidence.py'),
         'smoke':('single_tree','smoke.py'),
         'native_large':('migration_tree','openbao271_kv2_native_large_migrate.py')}
for name,(owner,filename) in mapping.items():
    raw=text('canonical/'+name+'.py');m=I['current'][name]['meta']
    check(name+'_whole_bytes_hash',len(raw.encode())==m['bytes'] and sha(raw)==m['sha256'] and blob(raw)==m['blob'])
    member(trees[owner],filename,m['blob'])
driver=text('canonical/driver.py');dt=ast.parse(driver)
constants={n.targets[0].id:ast.literal_eval(n.value) for n in dt.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('HTTP_SECONDS','MIGRATION_SECONDS','CHECKS')}
check('original_http_15_and_migration_360',(constants['HTTP_SECONDS'],constants['MIGRATION_SECONDS'])==(15,360))
check('original_31_unique_cases',len(constants['CHECKS'])==len(set(constants['CHECKS']))==31)
check('full34_17_times_2mib_original','"full34": (17, 2 * MIB, True)' in driver)
check('actual_native_profile','config["storage"] = {"native_v6_file": {"path": config["data_dir"]}}' in driver)
check('official_version_explicit',driver.count('version="2.7.1"')>=3)
check('source_driver_unchanged',driver==I['current']['driver']['raw'])

# Execute only the pure receipt-admission function with a fake file surface.
# It reads the already archived public JSON in memory and never imports or
# executes the candidate module, subprocesses, filesystem, or fixtures.
nodes=ast.parse(candidate).body
selected=[n for n in nodes if isinstance(n,ast.FunctionDef) and n.name in ('need','normal61_admission')]
class FakePath:
    def __init__(self,name):self.name=name
    def __truediv__(self,other):return FakePath(self.name+'/'+other)
    def read_bytes(self):return current_raw.encode()
ns={'json':json,'BINDING_READY':True,'NORMAL61_SHA':I['current']['mac_combined']['meta']['sha256'],
    'NORMAL_NATIVE_SHA':I['current']['mac_native']['meta']['sha256'],
    'NORMAL_RELEASE_SHA':I['current']['mac_release']['meta']['sha256'],
    'HEAD':'4e808d0ecb1bcded22870a7ec960dfb2491cf6ec',
    'TREE':'eba5e650bd080b8ad41ea52a2bc68867f541d255','PRODUCT':FakePath('fixed'),
    'sha':lambda unused:I['current']['mac_combined']['meta']['sha256']}
exec(compile(ast.Module(body=selected,type_ignores=[]),'<receipt-admission-only>','exec'),ns)
current_raw=I['current']['mac_combined']['raw']
check('actual_mac61_receipt_admitted',ns['normal61_admission']()==ns['NORMAL61_SHA'])
base=json.loads(current_raw)
negative=[('old_linux_schema',lambda n:n.update(schema='heptabao.linux-normal-same-root-publication-exact-tests.v1')),
          ('old60',lambda n:n.update(selected_test_total=60)),
          ('wrong_source',lambda n:n.update(source_commit='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c')),
          ('wrong_runner',lambda n:n.update(controller_sha256='0'*64)),
          ('aba_missing',lambda n:n.pop('same_root_publication_regression')),
          ('aba_failed',lambda n:n['same_root_publication_regression'].update(status='failed')),
          ('aba_cap_changed',lambda n:n['same_root_publication_regression'].update(new_total_group_cap_seconds=601)),
          ('cleanup_survivor',lambda n:n['cleanup'][0].update(remaining=[{'pid':1}])),
          ('source_changed',lambda n:n.update(source_unchanged=False))]
for name,mutate in negative:
    n=copy.deepcopy(base);mutate(n);current_raw=json.dumps(n)
    refused=False
    try:ns['normal61_admission']()
    except RuntimeError:refused=True
    check('negative_'+name,refused)
current_raw=I['current']['mac_combined']['raw'];ns['BINDING_READY']=False
refused=False
try:ns['normal61_admission']()
except RuntimeError as e:refused=str(e)=='normal61_and_local_prerequisite_bindings_unresolved'
check('unresolved_binding_early_refused',refused)

plan=json.loads(text('PLAN.public.json'))
check('six_metadata_requests',len(plan['metadata_requests'])==6)
check('all_metadata_unsubmitted',all(r['submission_count']==0 and r['current_metadata'] is None for r in plan['metadata_requests']))
check('no_runtime_dispatch',plan['process_start_requests_in_packet']==0)
check('rog_unbound',plan['rog']['ready'] is False and plan['rog']['oracle_binary'] is None)
for req in plan['metadata_requests']:
    r=json.loads(text(req['request']))
    check('request_'+req['role'],r['operation']=={'tool':'file_info','arguments':{'host':'mac','path':req['path']}} and 1<=len(r['idempotency_key'].encode())<=128)

result={'schema':'heptabao.current-mac-full34-source-checks.v1','status':'passed','candidate_bytes':len(candidate.encode()),'candidate_sha256':sha(candidate),'candidate_blob':blob(candidate),'strict_diff_hunks':hunks,'checks':checks,'check_count':len(checks),'selected_receipt_components':1+len(negative)+1,'candidate_module_executed':False,'product_or_runtime_calls':0,'source_only':True}
(OUT/'review/source-checks.public.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='checks'},sort_keys=True))
