#!/usr/bin/env python3
"""Source-only readiness successor and original X230 publisher interface binding."""
import ast,base64,copy,difflib,hashlib,json,re,shlex,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
data=json.loads((HERE/'input.original.json').read_text())
OUT=HERE/'packet';OUT.mkdir(exist_ok=True);checks=[]
def check(label,ok):
    assert ok,label
    checks.append({'check':label,'passed':True})
def dump(o):return json.dumps(o,indent=2,sort_keys=True,ensure_ascii=False)+'\n'
def pin(raw):
    b=raw.encode();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(name,raw):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(raw)
def assignment(src,name):
    nodes=[n for n in ast.parse(src).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    check('single-assignment:'+name,len(nodes)==1);return nodes[0]
def val(src,name):return ast.literal_eval(assignment(src,name).value)
def definitions(src):return {n.name:ast.get_source_segment(src,n) for n in ast.parse(src).body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef))}
def spans(src,n):
    ls=src.splitlines(True)
    start=sum(map(len,ls[:n.lineno-1]))+len(ls[n.lineno-1].encode()[:n.col_offset].decode())
    end=sum(map(len,ls[:n.end_lineno-1]))+len(ls[n.end_lineno-1].encode()[:n.end_col_offset].decode())
    return start,end
def literal_edit(src,node,value,label):
    start,end=spans(src,node);before=src[start:end]
    after=json.dumps(value) if isinstance(value,str) and before.startswith('"') else repr(value)
    return {'label':label,'start':start,'end':end,'before':before,'after':after}
def apply(src,edits):
    edits=sorted(edits,key=lambda e:e['start']);out=src
    for e in reversed(edits):
        check('literal-exact:'+e['label'],out[e['start']:e['end']]==e['before'])
        out=out[:e['start']]+e['after']+out[e['end']:]
    shift=0
    for e in edits:
        e['new_start']=e['start']+shift;e['new_end']=e['new_start']+len(e['after'])
        shift+=len(e['after'])-len(e['before'])
    inverse=out
    for e in reversed(edits):
        check('inverse-literal:'+e['label'],inverse[e['new_start']:e['new_end']]==e['after'])
        inverse=inverse[:e['new_start']]+e['before']+inverse[e['new_end']:]
    check('whole-inverse:'+str(len(edits)),inverse==src);return out
def strict_apply(src,patch):
    source=src.splitlines(True);lines=patch.splitlines(True);out=[];at=0;i=2
    while i<len(lines):
        m=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[i]);assert m,lines[i]
        start=int(m[1])-1;assert start>=at;out.extend(source[at:start]);at=start;i+=1;a=b=0
        while i<len(lines) and not lines[i].startswith('@@ '):
            k=lines[i][0];body=lines[i][1:];assert k in ' +-'
            if k in ' -':assert source[at]==body;at+=1;a+=1
            if k in ' +':out.append(body);b+=1
            i+=1
        assert a==int(m[2] or 1) and b==int(m[4] or 1)
    out.extend(source[at:]);return ''.join(out)
outputs={};all_edits={};hunks={}
for role in ('sender','receiver','relay'):
    before=data['prebind_sources'][role]
    check(role+':prebind-ready-false',val(before,'BINDING_READY') is False)
    edits=[literal_edit(before,assignment(before,'BINDING_READY').value,True,role+'.BINDING_READY')]
    if role=='relay':
        helpers=assignment(before,'HELPERS').value
        for k,n in zip(helpers.keys,helpers.values,strict=True):
            endpoint=ast.literal_eval(k).removesuffix('.py')
            check('old-helper:'+endpoint,ast.literal_eval(n)==pin(data['prebind_sources'][endpoint])['sha256'])
            edits.append(literal_edit(before,n,pin(outputs[endpoint])['sha256'],'relay.HELPERS.'+endpoint))
    after=apply(before,edits);outputs[role]=after;all_edits[role]=edits
    check(role+':all-definitions-byte-identical',definitions(before)==definitions(after))
    check(role+':seven-actual-rows-identical',val(before,'FILES')==val(after,'FILES'))
    check(role+':ready-true',val(after,'BINDING_READY') is True)
    compile(after,'<'+role+' compile-only>','exec')
    tree=ast.parse(after);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='binding_ready')
    ns={'BINDING_READY':True,'FILES':val(after,'FILES')}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(function)],type_ignores=[])),'selected-binding-ready','exec'),ns,ns)
    ns['binding_ready']();check(role+':selected-ready-guard-passes',True)
    ns['BINDING_READY']=False;rejected=False
    try:ns['binding_ready']()
    except AssertionError:rejected=True
    check(role+':selected-unready-rejected',rejected)
    patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+role+'.prebind.py',tofile='b/'+role+'.ready.py'))
    check(role+':strict-whole-diff',strict_apply(before,patch)==after)
    hunks[role]=sum(x.startswith('@@ ') for x in patch.splitlines())
    write('reference/'+role+'.prebind.py',before);write('candidate/'+role+'.py',after);write('diff/'+role+'.ready.diff',patch)
check('exact-five-control-literals',sum(map(len,all_edits.values()))==5)
check('exact-seven-rows-all-roles',val(outputs['sender'],'FILES')==val(outputs['receiver'],'FILES')==val(outputs['relay'],'FILES'))
prior=data['prior_interface']
for name,r in prior.items():
    check('prior-whole:'+name,all(pin(r['raw'])[k]==r[k] for k in ('bytes','sha256','blob')))
old_pub=prior['inert-base']['raw'];old_req=json.loads(prior['inert-request-base']['raw']);old_payload=json.loads(prior['payload-base']['raw'])
check('old-inert-request-exact-source',old_req['args']==['-I','-S','-B','-c',old_pub])
check('old-inert-request-exact-stdin',old_req['stdin']==prior['payload-base']['raw'])
for name,(length,sha) in val(old_pub,'PINS').items():
    b=base64.b64decode(old_payload['files'][name],validate=True)
    check('prior-carried-pin:'+name,len(b)==length and hashlib.sha256(b).hexdigest()==sha)
pubtree=ast.parse(old_pub);pub_edits=[]
base_node=assignment(old_pub,'BASE').value
check('publisher-base-expression',isinstance(base_node,ast.BinOp) and isinstance(base_node.op,ast.Div))
pub_edits.append(literal_edit(old_pub,base_node.right,'normal-same-root-publication-x230-transfer-controls-r1','publisher.BASE'))
pins_node=assignment(old_pub,'PINS').value
for k,n in zip(pins_node.keys,pins_node.values,strict=True):
    name=ast.literal_eval(k);actual=pin(outputs[name.removesuffix('.py')])
    pub_edits.append(literal_edit(old_pub,n.elts[0],actual['bytes'],'publisher.PINS.'+name+'.bytes'))
    pub_edits.append(literal_edit(old_pub,n.elts[1],actual['sha256'],'publisher.PINS.'+name+'.sha256'))
schemas={
'heptabao.df026-x230-normal7-inert-carrier.v1':'heptabao.4e808-x230-normal7-inert-carrier.v1',
'heptabao.df026-x230-normal7-inputs.v1':'heptabao.4e808-x230-normal7-inputs.v1'}
found=[]
for n in ast.walk(pubtree):
    if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in schemas:
        found.append(n.value);pub_edits.append(literal_edit(old_pub,n,schemas[n.value],'publisher.schema.'+n.value))
check('two-publisher-schema-literals',set(found)==set(schemas) and len(found)==2)
check('publisher-nine-literals',len(pub_edits)==9)
publisher=apply(old_pub,pub_edits);all_edits['publisher']=pub_edits
check('publisher-five-definitions-identical',definitions(old_pub)==definitions(publisher) and len(definitions(publisher))==5)
compile(publisher,'<publisher compile-only>','exec')
pubpatch=''.join(difflib.unified_diff(old_pub.splitlines(True),publisher.splitlines(True),fromfile='a/inert.previous.py',tofile='b/inert.current.py'))
check('publisher-strict-whole',strict_apply(old_pub,pubpatch)==publisher);hunks['publisher']=sum(x.startswith('@@ ') for x in pubpatch.splitlines())
payload={'schema':schemas['heptabao.df026-x230-normal7-inputs.v1'],'files':{role+'.py':base64.b64encode(outputs[role].encode()).decode() for role in ('sender','receiver','relay')}}
payload_raw=dump(payload)
check('same-input-cap',0<len(payload_raw.encode())<=262144 and 'read(262145)' in publisher and '<= 262144' in publisher)
for name,(length,sha) in val(publisher,'PINS').items():
    b=base64.b64decode(payload['files'][name],validate=True)
    check('new-exact-carried:'+name,b==outputs[name.removesuffix('.py')].encode() and len(b)==length and hashlib.sha256(b).hexdigest()==sha)
# Select only the original pure serializer and the receiver's five original argument statements.
relaytree=ast.parse(outputs['relay']);remote=next(n for n in relaytree.body if isinstance(n,ast.FunctionDef) and n.name=='remote_command')
ns={'hashlib':hashlib,'shlex':shlex};exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(remote)],type_ignores=[])),'selected-remote-command','exec'),ns,ns)
remote_argv=shlex.split(ns['remote_command']('/usr/bin/python3',outputs['receiver']))
check('receiver-exact-inline-shape',remote_argv==['/usr/bin/python3','-I','-S','-B','-c',outputs['receiver'],pin(outputs['receiver'])['sha256']])
receivertree=ast.parse(outputs['receiver'])
main=next(n for n in receivertree.body if isinstance(n,ast.Try) and any(isinstance(s,ast.Assert) and 'len(sys.argv)' in ast.get_source_segment(outputs['receiver'],s) for s in n.body))
entry_start=next(i for i,s in enumerate(main.body) if isinstance(s,ast.Assert) and 'len(sys.argv)' in ast.get_source_segment(outputs['receiver'],s))
entry=main.body[entry_start:entry_start+5]
check('receiver-entry-five-selected-nodes',len(entry)==5 and sum(isinstance(n,ast.Assert) for n in entry)==4 and isinstance(entry[3],ast.Assign))
guard=compile(ast.fix_missing_locations(ast.Module(body=copy.deepcopy(entry),type_ignores=[])),'selected-receiver-entry','exec')
def invoke(argv):
    env={'sys':types.SimpleNamespace(argv=['-c']+argv[6:],orig_argv=argv),'re':re,'digest':lambda b:hashlib.sha256(b).hexdigest()}
    exec(guard,env,env);return env
check('receiver-original-entry-accepts',invoke(remote_argv)['controller_raw']==outputs['receiver'].encode())
for label,argv in [('missing',remote_argv[:-1]),('wrong',remote_argv[:-1]+['0'*64]),('extra',remote_argv+['extra'])]:
    rejected=False
    try:invoke(argv)
    except AssertionError:rejected=True
    check('receiver-original-entry-rejects:'+label,rejected)
inert_req=copy.deepcopy(old_req)
inert_req['args']=['-I','-S','-B','-c',publisher]
inert_req['stdin']=payload_raw
inert_req['idempotency_key']='heptabao-4e808-x230-controls-inert-r1-'+pin(publisher)['sha256'][:8]
check('inert-original-request-fields',set(inert_req)==set(old_req))
for k in ('host','executable','cwd','timeout_seconds'):check('inert-unchanged:'+k,inert_req[k]==old_req[k])
check('inert-exact-original-shape',inert_req['host']=='desktop' and inert_req['executable']=='/usr/bin/python3' and inert_req['timeout_seconds']==60 and len(inert_req['args'])==5)
relay_req=copy.deepcopy(json.loads(prior['relay-request-base']['raw']))
relay_req['args']=['-I','-S','-B','/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-x230-transfer-controls-r1/relay.py']
relay_req['idempotency_key']='heptabao-4e808-x230-source-artifacts-relay-r1-'+pin(outputs['relay'])['sha256'][:8]
check('relay-original-fields',set(relay_req)==set(json.loads(prior['relay-request-base']['raw'])))
for k in ('host','executable','cwd','timeout_seconds'):check('relay-unchanged:'+k,relay_req[k]==json.loads(prior['relay-request-base']['raw'])[k])
check('relay-fresh-key',relay_req['idempotency_key']!=json.loads(prior['relay-request-base']['raw'])['idempotency_key'])
check('relay-original-360',relay_req['timeout_seconds']==360)
inert_request_raw=dump(inert_req);relay_request_raw=dump(relay_req)
write('candidate/inert.py',publisher);write('reference/inert.previous.py',old_pub);write('diff/inert.binding.diff',pubpatch)
write('dispatch/inert.stdin.json',payload_raw);write('dispatch/inert.exact-request.json',inert_request_raw);write('dispatch/relay.exact-request.json',relay_request_raw)
for name,r in prior.items():
    if name=='inert-base':continue
    write('reference/'+name+'.original.json',r['raw'])
write('reference/prebind-PLAN.public.json',data['prebind_plan']);write('reference/seven-actual-inputs.public.json',data['prebind_binding'])
contract={'schema':'heptabao.current4e808.x230-ready-exact-dispatch-contract.v1',
'inert':{'request':pin(inert_request_raw),'publisher':pin(publisher),'stdin':pin(payload_raw),'host':'desktop','argv_shape':['/usr/bin/python3','-I','-S','-B','-c','exact publisher text'],'outer_seconds':60,'stdin_maximum':262144,'only_three_public_controls':True,'no_source_import_or_execution':True},
'relay':{'request':pin(relay_request_raw),'exact':relay_req,'argv_guard_added':False,'file_self_path':relay_req['args'][3],'original_parent_seconds':300},
'sender':{'source':pin(outputs['sender']),'local_argv_shape':['/usr/bin/python3','-I','-S','-B','-c','exact sender text'],'trailing_self_sha_required':False,'seconds':90},
'receiver':{'source':pin(outputs['receiver']),'remote_argv_shape':['/usr/bin/python3','-I','-S','-B','-c','exact receiver text','SHA256(exact receiver text)'],'original_five_statements_selected_executed':True,'missing_wrong_extra_rejected':True,'seconds':300,'Git_seconds':60,'clone_seconds':90},
'readiness_scope':'All seven historical actual input pins present; code binding is ready, but neither request is authorized or submitted by this packet.',
'Runtime_calls':0,'inert_executed':False,'relay_executed':False,'old_relay_state':'UNKNOWN','old_relay_termination_proven':False}
write('CALLER_CONTRACT.public.json',dump(contract))
plan=json.loads(data['prebind_plan'])
plan.update(schema='heptabao.current4e808.x230-ready-source-plan.v1',status='SOURCE_READY_REQUESTS_FROZEN_NOT_SUBMITTED',
binding_ready=True,no_runtime_dispatch=False,executable_dispatch_present=True,dispatch_authorized=False,Runtime_calls=0,
prebind_tree=data['prebind_tree'],candidate_pins={r:pin(v) for r,v in outputs.items()},publisher_pin=pin(publisher),
requests={'inert':pin(inert_request_raw),'relay':pin(relay_request_raw)},
remaining_admission_steps=['Root accepts these exact ready sources, publisher, payload and requests.',
'Authorized unique create-only inert; authority, complete original streams, three controls and receipt independently observed.',
'Separate root relay authorization under the original held effect fence and exact historical input pins.',
'Actual X230 receiver clone/fsck/history/tracked files, destination proofs and owned closure before full34/comparison69 binding.'])
write('PLAN.public.json',dump(plan))
review={'schema':'heptabao.current-x230-ready-source-review.v1','status':'PASS_SOURCE_ONLY','checks':checks,'check_count':len(checks),
'prebind_control_literal_changes':5,'publisher_literal_changes':9,'strict_diff_hunks':hunks,
'original_definition_counts':{r:len(definitions(v)) for r,v in outputs.items()},'publisher_definitions':5,
'original_function_definitions_all_byte_identical':True,'all_seven_actual_input_rows_unchanged':True,
'whole_source_modules_executed':0,'Runtime_calls':0,'selected_pure_functions':['binding_ready','remote_command'],
'selected_receiver_entry_statements':5,'old_UNKNOWN_preserved':True,'effect_fence_byte_identical':True,
'candidate_pins':{r:pin(v) for r,v in outputs.items()},'publisher':pin(publisher),'payload':pin(payload_raw),'requests':{'inert':pin(inert_request_raw),'relay':pin(relay_request_raw)}}
write('verification/literal-edits.public.json',dump(all_edits));write('verification/source-review.public.json',dump(review))
write('README.md','''# Current 4e808 X230 ready source and exact original interfaces

This successor preserves the complete seven-input prebind and changes only the three readiness literals and the two derived relay helper hashes. All original transport functions, input tables, strict SSH, held old-effect fence, deadlines, cleanup, remote receiver argv and source validation remain unchanged.

The prior X230 inert publisher is reused. Only its new controls namespace, two schema literals and the three carried source byte/hash pins change. Its five functions are byte identical. The new request uses the original inline publisher plus base64 stdin form, 262144-byte carrier ceiling and 60-second outer supervision. It only publishes three public source controls and one receipt; it does not import or execute those modules.

The relay request uses the original file invocation and 360-second outer supervision. Its original 300-second controller and receiver, 90-second sender and clone, 60-second Git commands, and 5/5 cleanup remain. The receiver's original exact self-SHA contract is derived from the actual unchanged remote_command function and tested with the final source. Missing, incorrect or extra trailing arguments are refused by the same original entry statements.

Both requests are proposals awaiting explicit root authorization and line ownership. Ready source is not proof of inert, transport, X230 import, restart, full34, comparison69, HA or full replacement. The original relay remains UNKNOWN; the unchanged held marker restricts effects under its namespace assumptions and does not prove termination. No candidate source or product was executed while generating this packet.
''')
write('verification/generate-and-verify.py',Path(__file__).read_text());write('verification/input.original.json',(HERE/'input.original.json').read_text())
print(dump({'passed':True,'checks':len(checks),'hunks':hunks,'candidate_pins':review['candidate_pins'],'publisher':pin(publisher),'payload':pin(payload_raw),'requests':review['requests'],'keys':{'inert':inert_req['idempotency_key'],'relay':relay_req['idempotency_key']}}),end='')

