import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/f86faac821c4/x230_current_seven_prebind_r1')
data = json.loads((ROOT / 'input.original.json').read_text())
out = ROOT / 'packet'
out.mkdir(exist_ok=True)
checks = []
def check(name, ok):
    if not ok: raise AssertionError(name)
    checks.append(name)
def sha(b): return hashlib.sha256(b).hexdigest()
def gitblob(b): return hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest()
def write(path, raw):
    p = out / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw)
def assignment(source, name):
    ns = [n for n in ast.parse(source).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    check(name + ':single_assignment', len(ns) == 1)
    return ns[0]
def span(source, node):
    lines = source.splitlines(keepends=True)
    # All changed literals are ASCII. Python AST columns count UTF-8 bytes.
    start = sum(len(l) for l in lines[:node.lineno-1]) + len(lines[node.lineno-1].encode()[:node.col_offset].decode())
    end = sum(len(l) for l in lines[:node.end_lineno-1]) + len(lines[node.end_lineno-1].encode()[:node.end_col_offset].decode())
    return start, end
def edits_apply(source, edits):
    edits = sorted(edits, key=lambda x:x['start'])
    result = source
    for e in reversed(edits):
        check('literal_before:' + e['label'], result[e['start']:e['end']] == e['before'])
        result = result[:e['start']] + e['after'] + result[e['end']:]
    offset = 0
    inverse = []
    for e in edits:
        s=e['start']+offset
        inverse.append({'start':s,'end':s+len(e['after']),'before':e['after'],'after':e['before']})
        offset += len(e['after'])-len(e['before'])
    back = result
    for e in reversed(inverse):
        check('literal_inverse_at_offset', back[e['start']:e['end']] == e['before'])
        back = back[:e['start']] + e['after'] + back[e['end']:]
    check('whole_literal_inverse', back == source)
    return result
plan = json.loads(data['original_plan'])
api = json.loads(data['source_tree_original'])
check('source36_tree_exact', api['sha'] == data['source_tree'] and api['truncated'] is False)
table = json.loads(data['normal5_actual_table'])
check('actual_normal_current', table['source_commit'] == plan['canonical']['commit'] and table['source_tree'] == plan['canonical']['tree'] and table['metadata_complete'] is True)
check('five_actual_rows', len(table['files']) == 5)
by_path = {}
for f in table['files']:
    info = json.loads(data['actual_infos'][f['name']]['raw'])
    raw = data['actual_infos'][f['name']]['raw'].encode()
    meta = f['independent_info']
    check('actual_info_whole:' + f['name'], len(raw)==meta['bytes'] and sha(raw)==meta['sha256'] and gitblob(raw)==meta['blob'])
    md=info['metadata']; dev,ino,size,mt,ct=map(int,info['version'].split(':'))
    full9=[dev,ino,md['uid'],md['gid'],0o100000|md['mode'],md['link_count'],size,mt,ct]
    check('actual_info_table:' + f['name'], info['path']==f['path'] and info['size']==f['bytes']==size and info['sha256']==f['sha256'] and info['version']==f['version'] and md['mode']==f['mode'] and md['uid']==f['uid']==1000 and md['gid']==f['gid']==1000 and md['link_count']==f['nlink']==1)
    check('actual_receiver_full9:' + f['name'], full9==[int(x) for x in f['receiver_full9']] and f['matched_receiver_full9'] is True)
    by_path[f['path']]=f
    write('reference/actual-info/' + f['name'] + '.json', data['actual_infos'][f['name']]['raw'])
write('reference/normal5-actual-table.public.json',data['normal5_actual_table'])
write('reference/original-plan.public.json',data['original_plan'])
write('reference/source36-tree.original.json',data['source_tree_original'])
write('reference/rog-export-bundle-info.original.json',data['actual_infos']['rog_bundle_info']['raw'])
source2=data['source2_whole']
for name,r in source2.items():
    body=r['raw'].encode()
    check('source2_whole:'+name,len(body)==r['bytes'] and sha(body)==r['sha256'] and gitblob(body)==r['blob'])
    write('reference/source2/'+name+'.original.json',r['raw'])
s2table=json.loads(source2['source2-binding']['raw'])
s2core=json.loads(source2['source2-core']['raw'])
s2authority=json.loads(source2['source2-authority']['raw'])
check('source2_current',s2table['source_commit']==plan['canonical']['commit'] and s2table['source_tree']==plan['canonical']['tree'])
check('source2_authority',s2authority['exit_code']==0)
check('source2_transferred',s2core['status']=='transferred' and s2core['all_owned_stopped'] and s2core['all_local_owned_stopped'])
check('source2_remote_complete',s2core['remote_endpoint_completion_verified'] and not s2core['remote_cleanup_unknown'] and s2core['cleanup_errors']==[])
check('source2_three_owned_closed',len(s2core['cleanup'])==3 and all(r['exit_code']==0 and r['direct_child_reaped'] and r['remaining']==[] for r in s2core['cleanup']))
check('source2_exact_two',len(s2table['observed_files'])==2)
for i,(name,f) in enumerate(zip(('bundle-info','export-info'),s2table['observed_files'],strict=True)):
    r=source2[name];info=json.loads(r['raw'])
    md=info['metadata'];dev,ino,size,mt,ct=map(int,info['version'].split(':'))
    full9=[dev,ino,md['uid'],md['gid'],0o100000|md['mode'],md['link_count'],size,mt,ct]
    check('source2_info_fields:'+str(i),info['path']==f['path'] and info['size']==f['bytes']==size and info['sha256']==f['sha256'] and info['version']==f['version'] and info['mode']==md['mode']==f['mode']==0o400 and md['uid']==f['uid']==1000 and md['gid']==f['gid']==1000 and md['link_count']==f['nlink']==1)
    check('source2_full9:'+str(i),full9==[int(x) for x in f['receiver_full9']]==s2core['receiver']['files'][i]['identity'])
    check('source2_stream_content:'+str(i),f['same_fd_receiver_whole']==s2core['receiver']['files'][i]['same_fd_readback']=={'bytes':f['bytes'],'sha256':f['sha256']})
    check('source2_original_info_pin:'+str(i),r['blob']==f['independent_info_blob'] and r['bytes']==f['independent_info_bytes'] and r['sha256']==f['independent_info_sha256'])
    actual=dict(f)
    actual['independent_info']={k:r[k] for k in ('blob','bytes','sha256')}
    actual['receiver_full9']=full9
    check('source2_unique_desktop_path:'+str(i),f['path'] not in by_path)
    by_path[f['path']]=actual
check('seven_unique_actual_desktop_inputs',len(by_path)==7)
outputs={}; all_edits={}; after_tables={}
for role, before in data['before'].items():
    pin=plan['source_pins'][role]
    check(role+':before_whole',len(before.encode())==pin['bytes'] and sha(before.encode())==pin['sha256'] and gitblob(before.encode())==pin['blob'])
    check(role+':tree_member',sum(e.get('type')=='blob' and e.get('sha')==pin['blob'] and e.get('size')==pin['bytes'] for e in api['tree'])>=1)
    ass=assignment(before,'FILES'); old=ast.literal_eval(ass.value)
    check(role+':seven_slots',len(old)==7 and isinstance(ass.value,ast.List))
    edits=[]
    for i,row in enumerate(old):
        if row['path'] not in by_path: continue
        f=by_path[row['path']]
        check(role+':mode_and_empty_slot:'+str(i),row['source_mode']==f['mode'] and row['target_mode']==f['mode'] and all(row[k] is None for k in ('bytes','sha256','version')))
        nd=ass.value.elts[i]
        vals={k.value:v for k,v in zip(nd.keys,nd.values)}
        for key in ('bytes','sha256','version'):
            value=f[key]; start,end=span(before,vals[key])
            edits.append({'label':role+':slot'+str(i)+':'+key,'start':start,'end':end,'before':before[start:end],'after':json.dumps(value,ensure_ascii=False)})
    check(role+':only_twentyone_input_literals',len(edits)==21)
    after=edits_apply(before,edits)
    outputs[role]=after; all_edits[role]=[edits]
    after_tables[role]=ast.literal_eval(assignment(after,'FILES').value)
check('all_three_tables_identical', after_tables['sender']==after_tables['receiver']==after_tables['relay'])
base_relay=outputs['relay']; helper_node=assignment(base_relay,'HELPERS').value
helpers_before=ast.literal_eval(helper_node)
check('original_helper_pins',helpers_before=={'sender.py':plan['source_pins']['sender']['sha256'],'receiver.py':plan['source_pins']['receiver']['sha256']})
hedits=[]
for key,node in zip(helper_node.keys,helper_node.values):
    role=key.value.removesuffix('.py');start,end=span(base_relay,node)
    hedits.append({'label':'relay:derived_helper:'+role,'start':start,'end':end,'before':base_relay[start:end],'after':json.dumps(sha(outputs[role].encode()))})
outputs['relay']=edits_apply(base_relay,hedits);all_edits['relay'].append(hedits)
def strict_apply(source,patch):
    import re
    old=source.splitlines(True);lines=patch.splitlines(True);out=[];at=0;i=2
    while i<len(lines):
        m=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[i])
        check('strict_hunk_header',m is not None)
        start=int(m[1])-1
        check('strict_hunk_order',start>=at)
        out.extend(old[at:start]);at=start;i+=1;nc=np=0
        while i<len(lines) and not lines[i].startswith('@@ '):
            k=lines[i][0];body=lines[i][1:]
            check('strict_hunk_kind',k in ' +-')
            if k in ' -':
                check('strict_hunk_context',old[at]==body);at+=1;nc+=1
            if k in ' +':out.append(body);np+=1
            i+=1
        check('strict_hunk_counts',nc==int(m[2] or 1) and np==int(m[4] or 1))
    out.extend(old[at:])
    return ''.join(out)
defdefs={}
for role,after in outputs.items():
    before=data['before'][role]
    def defs(src):
        return {n.name:ast.get_source_segment(src,n) for n in ast.parse(src).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
    olddefs=defs(before);newdefs=defs(after)
    check(role+':all_original_definitions_byte_identical',olddefs==newdefs)
    defdefs[role]=list(olddefs)
    def without_bindings(src):
        tree=ast.parse(src)
        tree.body=[n for n in tree.body if not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('FILES','HELPERS') for t in n.targets))]
        return ast.dump(tree,include_attributes=False)
    check(role+':all_other_AST_identical',without_bindings(before)==without_bindings(after))
    check(role+':ready_remains_false',ast.literal_eval(assignment(after,'BINDING_READY').value) is False)
    compile(after,'<source-only '+role+'>','exec')
    check(role+':AST_compile_only',True)
    write('reference/'+role+'.py',before)
    write('candidate/'+role+'.py',after)
    patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='reference/'+role+'.py',tofile='candidate/'+role+'.py'))
    check(role+':strict_whole_diff',strict_apply(before,patch)==after)
    write('diff/'+role+'.diff',patch)
files=after_tables['receiver']
check('all_seven_inputs_bound',all(type(f['bytes']) is int and f['bytes']>0 and isinstance(f['sha256'],str) and len(f['sha256'])==64 and isinstance(f['version'],str) for f in files))
mapping=[]
for i,row in enumerate(files):
    actual=by_path.get(row['path'])
    mapping.append({'index':i,'role':row['name'],'desktop_source_path':row['path'],'x230_target_path':plan['x230_root']+'/artifacts/'+row['name'],'source_mode_octal':format(row['source_mode'],'04o'),'target_mode_octal':format(row['target_mode'],'04o'),'bytes':row['bytes'],'sha256':row['sha256'],'desktop_expected_version':row['version'],'bound_from_actual_independent_info':actual is not None,'independent_info':None if actual is None else actual['independent_info'],'uid':None if actual is None else actual['uid'],'gid':None if actual is None else actual['gid'],'nlink':None if actual is None else actual['nlink'],'full9_decimal_strings':None if actual is None else [str(v) for v in actual['receiver_full9']]})
write('binding/seven-actual-inputs.public.json',json.dumps({'schema':'heptabao.current-x230-seven-actual-inputs-binding.v1','source_only':True,'binding_ready':False,'normal5_bound_indices':[0,1,2,5,6],'source2_bound_indices':[3,4],'unbound_indices':[],'files':mapping},indent=2)+'\n')
write('verification/literal-edits.public.json',json.dumps(all_edits,indent=2)+'\n')
report={'schema':'heptabao.current-x230-seven-input-prebind-source-review.v1','status':'PASS_FULL_7_SOURCE_ONLY_NOT_EXECUTABLE','checks_passed':len(checks),'checks':checks,'original_definitions':defdefs,'original_definition_counts':{k:len(v) for k,v in defdefs.items()},'input_literal_edits':63,'derived_helper_pin_edits':2,'source_commit':plan['canonical']['commit'],'source_tree':plan['canonical']['tree'],'original_deadlines_unchanged':True,'original_effect_fence_unchanged':True,'old_relay_unknown_preserved':True,'effect_fence_does_not_prove_old_job_terminated':True,'binding_ready':False,'exact_runtime_request_created':False,'host_requests':0,'candidate_modules_executed':0,'AST_compile_only':True,'desktop_canonical_import_qualified':False,'X230_source_import_qualified':False,'X230_product_or_full34_qualified':False}
write('verification/source-review.public.json',json.dumps(report,indent=2)+'\n')
next_plan={
 'schema':'heptabao.current-x230-seven-actual-input-prebind-plan.v1','source_only':True,'binding_ready':False,
 'canonical_expected':plan['canonical'],'actual_source36':data['source_tree'],
 'normal5_actual_table_blob':'795c92856119c5a2f8c73130f5772d82f3dfc295','normal5_root_review':data['normal5_root_review'],
 'normal5_complete_packet':data['normal5_complete_packet'],'normal5_input_indices_bound':[0,1,2,5,6],
 'source2_actual_packet':data['source2_transport_status']['actual_tree'],'source2_root_review':data['source2_transport_status']['root_review'],
 'source2_input_indices_bound':[3,4],'remaining_unbound_input_indices':[],'remaining_inputs':[],
 'old_relay':plan['old_relay'],'effect_fence':plan['effect_fence'],'held_fence':plan['held_fence'],'budgets':plan['budgets'],
 'no_runtime_dispatch':True,'status':'SOURCE_ONLY_ALL_7_ACTUAL_BOUND_NOT_ADMITTED',
 'desktop_canonical_import_qualified':False,'x230_canonical_import_qualified':False,
 'X230_fresh_receiver_import_expected_only':{'root':plan['x230_root'],'source':plan['x230_root']+'/source',
 'role':'Receiver materializes this standalone bundle independently after all seven artifacts pass receipt checks. It does not consume an existing desktop checkout.'},
 'remaining_admission_steps':[
 'Root reviews this complete seven-input binding and unchanged fence/custody. The current ready flag intentionally remains false.',
 'Prepare only the final readiness literal, derived helper pins, create-only inert carrier and exact requests; obtain root authorization before each host phase.',
 'Actual receiver must complete the new local clone, zero-prerequisite bundle verification, full fsck, 3763-commit proof, all 3914 tracked-file/index bytes and fsync, source/artifact/fence closure under original budgets.',
 'Only actual X230 destination/source receipts can bind the existing current full34/comparison69 wrappers for separately authorized prepare/live.'],
 'scope_limits':[
 'The old relay remains UNKNOWN. Its R3 effect fence constrains effects under the retained stable-namespace condition; it does not establish old process termination.',
 'All seven desktop input identities are historical actual observations; no current stat or X230 delivery/import/restart/migration/full34 pass is claimed.',
 'ROG source versions remain provenance; desktop received versions alone populate the seven sender input slots.',
 'Desktop standalone import is separately proposed, not executed. This transport has no semantic dependency on that separate checkout.']}
write('PLAN.public.json',json.dumps(next_plan,indent=2)+'\n')
write('README.md','''# Current 4e808 X230 seven-input prebind

All seven desktop inputs now have accepted actual provenance: five normal61 artifacts and two standalone source-carrier files. This packet changes only their bytes/SHA/version literals and the two derived relay helper SHA values. BINDING_READY remains false, and there is no executable dispatch.

Each original transport definition, strict SSH configuration, owned-child handling, complete stream/EOF checks, create-only publication, source clone/fsck/history verification, full tracked-index validation, and deadline remains unchanged. The original R3 effect fence is retained verbatim. It limits effects under its stated namespace condition and does not prove that the old UNKNOWN relay terminated.

Source paths are existing desktop observations; X230 target paths are proposed fresh output locations. The release receipt maps to artifacts/result.public.json and combined normal61 receipt maps to artifacts/normal61-result.public.json. Source and target modes are separately preserved. Exact full9 values are reconstructed from original metadata using Python integers and emitted as decimal strings.

This is a complete input prebind, not delivery or source-import qualification. The receiver itself creates a fresh checkout from the standalone bundle. It does not consume the separately proposed desktop canonical checkout. Neither desktop nor X230 import is claimed here.

Next steps are root review, the separately reviewed readiness/carrier/request finalization, actual inert and relay, complete destination/source proofs, then the existing current full34/comparison69 wrappers' own prepare/live gates. No host or product operation was submitted by this packet.
''')
write('verification/generate-and-verify.py',Path(__file__).read_text())
write('verification/input.original.json',(ROOT/'input.original.json').read_text())
print(json.dumps({'status':report['status'],'checks_passed':len(checks),'counts':report['original_definition_counts'],'candidate_pins':{k:{'bytes':len(v.encode()),'sha256':sha(v.encode()),'blob':gitblob(v.encode())} for k,v in outputs.items()},'packet_files':len(list(out.rglob('*')))},sort_keys=True))

