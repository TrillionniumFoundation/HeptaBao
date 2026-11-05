#!/usr/bin/env python3
"""Offline literal binding; no execution of the full importer or host commands."""
import ast, copy, difflib, hashlib, json, re, stat, types
from pathlib import Path
HERE=Path(__file__).resolve().parent
refs=json.loads((HERE/'input.original.json').read_text())['references']
OUT=HERE/'packet';OUT.mkdir(exist_ok=True)
checks=[]
def check(name,ok):
    assert ok,name
    checks.append({'check':name,'passed':True})
def dumps(obj):return json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=False)+'\n'
def pin(raw):
    b=raw.encode()
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(path,raw):
    p=OUT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(raw)
def seg(s,n):return ast.get_source_segment(s,n)
for name,r in refs.items():check('whole-reference:'+name,all(pin(r['raw'])[k]==r[k] for k in ('bytes','sha256','blob')))
old=refs['importer-base']['raw'];module=ast.parse(old)
check('exact-unbound-base',pin(old)['blob']=='f162a3e7976ede50439526c8a806b2253e1e6dd3')
assigns={n.targets[0].id:n for n in module.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
def literal(name):return ast.literal_eval(assigns[name].value)
core=json.loads(refs['source2-core']['raw'])
export=json.loads(refs['source-export-original']['raw'])
authority=json.loads(refs['source2-authority']['raw'])
received=json.loads(refs['source2-binding']['raw'])
check('received-canonical',received['source_commit']==literal('CANONICAL') and received['source_tree']==literal('TREE'))
check('received-job',received['relay_job_id']=='1a1acb4e995-fc05-567a')
check('source2-authority-zero',authority['exit_code']==0)
check('source2-status',core['status']=='transferred')
check('source2-owned',core['all_owned_stopped'] and core['all_local_owned_stopped'] and core['remote_endpoint_completion_verified'])
check('source2-no-unknown',core['remote_cleanup_unknown'] is False and core['cleanup_errors']==[])
check('source2-three-cleanup',len(core['cleanup'])==3 and all(r['exit_code']==0 and r['direct_child_reaped'] and r['remaining']==[] for r in core['cleanup']))
check('base-ready-false',literal('ACTUAL_INPUTS_READY') is False)
def info(name):
    v=json.loads(refs[name]['raw']);tok=v['version'].split(':')
    check('version:'+name,len(tok)==5 and all(re.fullmatch('[0-9]+',x) for x in tok))
    dev,ino,size,mtime,ctime=map(int,tok);m=v['metadata']
    check('size:'+name,size==v['size'])
    check('mode:'+name,v['mode']==m['mode'])
    check('owner-link:'+name,m['uid']==m['gid']==1000 and m['link_count']==1)
    return v,[dev,ino,m['uid'],m['gid'],stat.S_IFREG|v['mode'],m['link_count'],size,mtime,ctime]
infos=[info('bundle-info'),info('export-info')]
transfer_info,transfer_ident=info('source2-core-info')
check('transfer-raw-whole',transfer_info['size']==pin(refs['source2-core']['raw'])['bytes'] and transfer_info['sha256']==pin(refs['source2-core']['raw'])['sha256'])
source_rows=copy.deepcopy(literal('SOURCE_FILES'));dest_rows=copy.deepcopy(literal('FILES'));held=[]
for i,(src,dst,(meta,ident),obs) in enumerate(zip(source_rows,dest_rows,infos,received['observed_files'],strict=True)):
    actual_src=core['files'][i]
    check(f'source-shape-{i}',set(src)==set(actual_src) and all(src[k]==actual_src[k] for k in src if k not in ('bytes','sha256','version')))
    for field in ('bytes','sha256','version'):
        check(f'unbound-source-{i}-{field}',src[field] is None);src[field]=actual_src[field]
        check(f'unbound-dest-{i}-{field}',dst[field] is None);dst[field]=meta['size' if field=='bytes' else field]
    check(f'dest-path-mode-{i}',dst['path']==meta['path'] and dst['mode']==meta['mode']==0o400)
    check(f'cross-source-content-{i}',src['bytes']==dst['bytes'] and src['sha256']==dst['sha256'])
    check(f'dest-table-{i}',all(obs[k]==dst[k] for k in ('name','path','bytes','sha256','version','mode')))
    check(f'full9-table-{i}',[int(v) for v in obs['receiver_full9']]==ident)
    check(f'full9-receiver-{i}',core['receiver']['files'][i]['identity']==ident)
    held.append({'name':dst['name'],'identity':ident,'same_fd_readback':{'bytes':dst['bytes'],'sha256':dst['sha256']}})
transfer=copy.deepcopy(literal('TRANSFER'))
check('transfer-path-mode',transfer['path']==transfer_info['path'] and transfer['mode']==transfer_info['mode']==0o600)
for field in ('bytes','sha256','version'):
    check('unbound-transfer:'+field,transfer[field] is None);transfer[field]=transfer_info['size' if field=='bytes' else field]
check('export-raw-dest',dest_rows[1]['bytes']==pin(refs['source-export-original']['raw'])['bytes'] and dest_rows[1]['sha256']==pin(refs['source-export-original']['raw'])['sha256'])
for role,info_name,source_name in [('sender.py','source2-sender-info','source2-sender'),('receiver.py','source2-receiver-info','source2-receiver'),('relay.py','source2-relay-info','source2-relay')]:
    meta,ident=info(info_name);target=core['controller'] if role=='relay.py' else core['helpers'][role]
    check('control-source:'+role,target['bytes']==pin(refs[source_name]['raw'])['bytes'] and target['sha256']==pin(refs[source_name]['raw'])['sha256'])
    check('control-info:'+role,meta['size']==target['bytes'] and meta['sha256']==target['sha256'])
    for field in ('identity_before','identity_after','identity'):
        if field in target:check('control-'+field+':'+role,target[field]==ident)
offsets=[0]
for line in old.splitlines(keepends=True):offsets.append(offsets[-1]+len(line))
edits=[]
def change(node,value,label):
    start=offsets[node.lineno-1]+node.col_offset;end=offsets[node.end_lineno-1]+node.end_col_offset
    previous=ast.literal_eval(node)
    check('literal-before:'+label,previous is None or label=='ACTUAL_INPUTS_READY' and previous is False)
    edits.append({'start':start,'end':end,'before':old[start:end],'after':repr(value),'label':label})
change(assigns['ACTUAL_INPUTS_READY'].value,True,'ACTUAL_INPUTS_READY')
for name,rows in [('SOURCE_FILES',source_rows),('FILES',dest_rows)]:
    for i,(item,values) in enumerate(zip(assigns[name].value.elts,rows,strict=True)):
        nodes={ast.literal_eval(k):v for k,v in zip(item.keys,item.values,strict=True)}
        for field in ('bytes','sha256','version'):change(nodes[field],values[field],f'{name}[{i}].{field}')
nodes={ast.literal_eval(k):v for k,v in zip(assigns['TRANSFER'].value.keys,assigns['TRANSFER'].value.values,strict=True)}
for field in ('bytes','sha256','version'):change(nodes[field],transfer[field],'TRANSFER.'+field)
verify=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verify_receipts')
expected_transport={
"transported['controller']['bytes']":core['controller']['bytes'],
"transported['controller']['sha256']":core['controller']['sha256'],
"transported['helpers']['sender.py']['sha256']":core['helpers']['sender.py']['sha256'],
"transported['helpers']['receiver.py']['sha256']":core['helpers']['receiver.py']['sha256']}
found=set()
for node in verify.body:
    if isinstance(node,ast.Assert) and isinstance(node.test,ast.Compare):
        left=seg(old,node.test.left)
        if left in expected_transport:
            check('equality:'+left,len(node.test.ops)==1 and isinstance(node.test.ops[0],ast.Eq))
            change(node.test.comparators[0],expected_transport[left],left);found.add(left)
check('four-pins',found==set(expected_transport));check('twenty-literals',len(edits)==20)
edits.sort(key=lambda e:e['start']);new=old
for e in reversed(edits):new=new[:e['start']]+e['after']+new[e['end']:]
delta=0
for e in edits:
    e['new_start']=e['start']+delta;e['new_end']=e['new_start']+len(e['after'])
    delta+=len(e['after'])-len(e['before'])
inverse=new
for e in reversed(edits):
    check('inverse:'+e['label'],inverse[e['new_start']:e['new_end']]==e['after'])
    inverse=inverse[:e['new_start']]+e['before']+inverse[e['new_end']:]
check('inverse-whole',inverse==old)
newmod=ast.parse(new);compile(new,'bound_importer.py','exec',dont_inherit=True);check('compile-only',True)
olddefs={n.name:n for n in module.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
newdefs={n.name:n for n in newmod.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
check('same-definitions',set(olddefs)==set(newdefs))
for name,node in olddefs.items():
    original=seg(old,node)
    if name=='verify_receipts':
        for left,value in expected_transport.items():original=original.replace(left+'==None',left+'=='+repr(value))
        check('receipt-only-four-literals',original==seg(new,newdefs[name]))
    else:check('definition-byte-identical:'+name,original==seg(new,newdefs[name]))
main_old=next(n for n in module.body if isinstance(n,ast.Try) and n.lineno==518)
main_new=next(n for n in newmod.body if isinstance(n,ast.Try) and n.lineno==518)
check('main-whole-byte-identical',seg(old,main_old)==seg(new,main_new))
source_pin=pin(new)
request={'host':'desktop','executable':'/usr/bin/python3','args':['-I','-S','-B','-c',new,source_pin['sha256']],
'cwd':'/home/qian-qi/heptabao-ha-closure-20261103-r1','timeout_seconds':330,
'idempotency_key':'heptabao-4e808-standalone-source-import-'+source_pin['sha256'][:8]+'-20261105-r1'}
request_raw=dumps(request)
guard_code=compile(ast.fix_missing_locations(ast.Module(body=copy.deepcopy(main_new.body[:5]),type_ignores=[])),'selected-original-main-argv-contract','exec')
def guard(args):
    ns={'sys':types.SimpleNamespace(argv=['-c']+args[5:],orig_argv=[request['executable']]+args),
        're':re,'digest':lambda b:hashlib.sha256(b).hexdigest()}
    exec(guard_code,ns,ns);return ns
check('exact-request-original-five-statements',guard(request['args'])['controller_raw']==new.encode())
for label,args in [('missing-tail',request['args'][:-1]),('wrong-tail',request['args'][:-1]+['0'*64])]:
    rejected=False
    try:guard(args)
    except AssertionError:rejected=True
    check('original-guard-rejects:'+label,rejected)
selected=compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(newdefs['verify_receipts'])],type_ignores=[])),'selected-public-receipt-predicate','exec')
ns={'json':json,'CANONICAL':literal('CANONICAL'),'TREE':literal('TREE'),'PARENT':literal('PARENT'),
'ROOT_COMMIT':literal('ROOT_COMMIT'),'CANONICAL_COUNT':literal('CANONICAL_COUNT'),'SOURCE_FILES':source_rows,'FILES':dest_rows,
'CARRIER':Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-carrier-r1'),'result':{}}
exec(selected,ns,ns)
ns['verify_receipts']({'source-export.result.public.json':refs['source-export-original']['raw'],'source-carrier.result.public.json':refs['source2-core']['raw']},held)
check('selected-actual-receipt-predicate',ns['result']=={'export_receipt_verified':True,'transport_receipt_verified':True,'raw_input_receipts_unchanged':True})
check('original-deadlines',all(x in new for x in ('UNTIL=START+300',"'git_command_seconds':60","'clone_seconds':90","'overall_seconds':300")))
diff=''.join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='a/import_source4e808_unbound.py',tofile='b/import_source4e808_bound.py',n=3))
def strict_apply(text,patch):
    original=text.splitlines(keepends=True);lines=patch.splitlines(keepends=True);out=[];at=0;i=2
    while i<len(lines):
        m=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[i]);assert m,lines[i]
        start=int(m[1])-1;assert start>=at
        out.extend(original[at:start]);at=start;i+=1;oldn=newn=0
        while i<len(lines) and not lines[i].startswith('@@ '):
            kind=lines[i][0];body=lines[i][1:];assert kind in ' +-'
            if kind in ' -':assert original[at]==body;at+=1;oldn+=1
            if kind in ' +':out.append(body);newn+=1
            i+=1
        assert oldn==int(m[2] or 1) and newn==int(m[4] or 1)
    out.extend(original[at:]);return ''.join(out)
check('strict-whole-diff',strict_apply(old,diff)==new)
binding={'schema':'heptabao.current4e808.standalone-import-actual-literal-binding.v1',
'candidate_commit':literal('CANONICAL'),'candidate_tree':literal('TREE'),'ready_in_source':True,'host_dispatch_submitted':False,'source_import_qualified':False,
'logical_slots':['SOURCE_FILES exact ROG sender inputs','FILES exact desktop received inputs','TRANSFER exact desktop core identity','controller bytes/SHA','sender and receiver source SHA'],
'ROG_source_files':source_rows,'desktop_received_files':dest_rows,'transfer':transfer,
'transport_controller':{'bytes':core['controller']['bytes'],'sha256':core['controller']['sha256']},
'transport_helpers':{n:{'sha256':core['helpers'][n]['sha256']} for n in ('sender.py','receiver.py')},
'destination_full9_decimal_strings':[[str(x) for x in p[1]] for p in infos],'transfer_full9_decimal_strings':[str(x) for x in transfer_ident],
'actual_source2_tree':'454524327d4477828b6b6d2940d60b31c546a50d','root_review':'89c073151239ed359cb2eb69ccb9b91fe4f1898d',
'export_raw_blob':refs['source-export-original']['blob'],
'future_admission':'Original hold_fixed_inputs and receipt guards recheck these historical actual pins before create-only import.'}
review={'schema':'heptabao.current4e808.standalone-import-source-review.v1','scope':'offline literal binding and selected original predicates only',
'passed':True,'checks':checks,'check_count':len(checks),'base':pin(old),'candidate':source_pin,'diff':pin(diff),
'hunks':sum(x.startswith('@@ ') for x in diff.splitlines()),'literal_changes':len(edits),'definitions':len(olddefs),
'byte_identical_definitions':len(olddefs)-1,'four_literal_only_definition':'verify_receipts','main_body_byte_identical':True,'request':pin(request_raw),
'original_five_argv_statements_selected_executed':True,'selected_actual_receipt_predicate_executed':True,
'whole_module_executed':False,'host_io':False,'Runtime_calls':0,'Git_commands_executed_by_candidate':0,'product_started':False,
'nanoseconds':'Original raw texts use Python integers; proof full9 arrays are decimal strings.',
'budgets':{'outer':330,'controller':300,'Git':60,'clone':90,'TERM':5,'KILL':5},
'not_claimed':['current filesystem stat after archived observation','fresh roots absent now','source import executed','desktop checkout qualified','product qualification']}
write('reference/importer.unbound.py',old);write('candidate/importer.bound.py',new)
write('diff/importer.binding.diff',diff);write('dispatch/import.exact-request.json',request_raw)
write('binding/actual-five-slots.public.json',dumps(binding))
write('verification/literal-edits.public.json',dumps(edits));write('verification/source-review.public.json',dumps(review))
for name,ref in refs.items():
    if name in ('importer-base','importer-dispatch-contract'):continue
    extension='.py' if name in ('source2-sender','source2-receiver','source2-relay') else '.json'
    write('reference/'+name+'.original'+extension,ref['raw'])
write('reference/original-unbound-dispatch-contract.json',refs['importer-dispatch-contract']['raw'])
plan={'schema':'heptabao.current4e808.standalone-import-bound-plan.v1','status':'source-only-awaiting-root-review-and-runtime-line',
'candidate':source_pin,'exact_request':pin(request_raw),'idempotency_key':request['idempotency_key'],
'host':'desktop','executable':'/usr/bin/python3','argument_count':len(request['args']),
'argument_shape':['-I','-S','-B','-c','exact full candidate text','SHA256(exact full candidate text)'],'cwd':request['cwd'],
'new_source':'/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-validation-source-r1',
'new_owned_root':'/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-import-r1',
'root_and_source_create_only':True,'new_inert_or_prepare_layer':False,'product_tests':0,'budgets':review['budgets'],
'requires_before_submit':['root acceptance of this exact candidate and request','explicit Runtime line handoff','durable external execution intent in a separate completed call'],
'after_authorized_submit':['unique process_start','save original ACK before parse','observe only original job and immutable results','preserve unknown without replay'],
'planned_not_actual':{'source_import_qualified':False,'X230_import_qualified':False,'product_run':False}}
write('PLAN.public.json',dumps(plan))
write('README.md','''# Current 4e808 standalone desktop source import: exact bound proposal

This packet binds the accepted two-file transport to the reviewed importer. It changes 20 literal values in five logical slots plus the ready flag. The original module main, owned Git execution, input custody, create-only roots, source validation, cleanup, and deadlines remain byte identical. The receipt predicate has only four exact actual source pins changed.

The request uses the original inline invocation: /usr/bin/python3 -I -S -B -c <whole source> <SHA256 of whole source>, cwd at the fixed BASE and outer 330 seconds. There is no added inert or prepare layer. The five original argument guards require both sys.argv and sys.orig_argv shapes and recompute the exact inline body hash.

Actual provenance is source2 job 1a1acb4e995-fc05-567a, its completed authority, public core, independent destination metadata, previously observed control identities, and original source export receipt. Unsafe integers remain Python integers or raw text; proof arrays use decimal strings. These are historical observations, rechecked by the original input custody code at execution.

The offline verifier compiled but did not execute the full module. Only the original five argument guards and receipt predicate ran against archived public inputs. Strict diff application, literal inverse, unchanged definitions and complete main body were verified. No host or product action occurred.

The inherited source docstring is unchanged to preserve the literal-only delta. ACTUAL_INPUTS_READY=True means the proposal has fixed actual metadata. Import execution, new checkout identity, X230 import, H2, CLI, and other product qualifications remain false. Root approval and explicit Runtime handoff are required before the unique proposed request.
''')
write('verification/generate-and-verify.py',Path(__file__).read_text())
write('verification/input.original.json',(HERE/'input.original.json').read_text())
files={str(p.relative_to(OUT)):p.read_text() for p in sorted(OUT.rglob('*')) if p.is_file()}
(HERE/'generated-files.json').write_text(dumps(files))
print(dumps({'passed':True,'checks':len(checks),'literal_changes':len(edits),'hunks':review['hunks'],'definitions':len(olddefs),
'unchanged_definitions':len(olddefs)-1,'candidate':source_pin,'request':pin(request_raw),'key':request['idempotency_key'],'files_before_executor_manifest':len(files)}),end='')

