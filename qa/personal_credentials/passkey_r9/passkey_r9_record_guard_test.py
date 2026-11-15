#!/usr/bin/env python3
"""Finite host tests of the actual Runtime binding/argument functions; no ADB."""
import copy,hashlib,importlib.util,json,sys
from pathlib import Path
from types import SimpleNamespace
BASE=Path(__file__).parent
attempted=[]
def audit(event,args):
 if event.startswith(('socket.','subprocess.')) or event in ('os.system','os.posix_spawn','os.spawn'):
  attempted.append(event);raise RuntimeError('external_operation_forbidden')
sys.addaudithook(audit)
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
dispatch=module('actual_dispatch',BASE/'execute-workflow.py')
capture=module('actual_capture',BASE/'capture-runtime.py')
observer=module('actual_observer',BASE/'runtime-sources/reset-input-observer-r9.py')
def raw(x):return json.dumps(x,sort_keys=True).encode()
request={'host':'pocket4','executable':'/usr/bin/python3','args':['-I','-B',str(capture.BASE/'execute-workflow.py'),'--stage','M04'],'idempotency_key':'hb-passkey-r9-M04-test'}
launch={'audit_recorded':False,'job':{'id':'synthetic-test-job','host':'pocket4','execution_mode':'operator','executable':request['executable'],'args':request['args'],'idempotency_key':request['idempotency_key'],'request_digest':'0'*64}}
terminal={'job_id':launch['job']['id'],'state':'succeeded','exit_code':0,'output_durable':True,'output_complete':True,'log_bytes':{'stdout':{'stored':3},'stderr':{'stored':0}}}
def data(q=request,l=launch,t=terminal):return {'request.public.json':raw(q),'launch.tool-original.json':raw({'content':[{'type':'text','text':raw(l).decode()}]}),'terminal.tool-original.json':raw(t),'stdout.original':b'ok\n','stderr.original':b''}
checks=[]
def check(name,fn,reject=False):
 try:fn()
 except AssertionError:
  assert reject,name
 else:assert not reject,name
 checks.append(name)
check('actual_capture_preserves_false_launch_audit',lambda: (_ for _ in ()).throw(AssertionError()) if capture.validate('M04',data())[0]['audit_recorded'] is not False else None)
q=copy.deepcopy(request);q['args'][-1]='M03'
check('capture_rejects_wrong_stage_argv',lambda:capture.validate('M04',data(q=q)),True)
t=copy.deepcopy(terminal);t['log_bytes']['stdout']['stored']=4
check('capture_rejects_incomplete_stdout',lambda:capture.validate('M04',data(t=t)),True)
l=copy.deepcopy(launch);l['job']['id']='different-job'
check('capture_rejects_launch_terminal_mismatch',lambda:capture.validate('M04',data(l=l)),True)
source=BASE/'runtime-sources/M04-ordinary-saf-backup-r9.py';source_raw=source.read_bytes();digest=hashlib.sha256(source_raw).hexdigest()
dispatcher_raw=(BASE/'execute-workflow.py').read_bytes();dispatcher_digest=hashlib.sha256(dispatcher_raw).hexdigest()
intent={'schema':1,'stage':'M04','source_sha256':digest,'dispatcher_sha256':dispatcher_digest,'argv':['/usr/bin/python3','-I','-B',str(source)],'unknown_result_must_not_be_reissued':True,'case_passed_by_dispatch':False}
def observed(records,dispatch_intent=intent,expected_dispatcher=dispatcher_digest):
 values=dict(records,**{'execute-workflow.py':dispatcher_raw,'M04.intent.public.json':raw(dispatch_intent)})
 live=SimpleNamespace(private_directory=lambda _:None,private_file=lambda p,n:source_raw if p==source else values[p.name])
 return observer.runtime_evidence(live,'M04',source,digest,expected_dispatcher)
check('observer_accepts_actual_bounded_export_records',lambda:observed(data()))
t=copy.deepcopy(terminal);t.update(state='failed',exit_code=1)
check('observer_rejects_failed_export_job',lambda:observed(data(t=t)),True)
q=copy.deepcopy(request);q['stdin']='unbound-inline-source'
check('observer_rejects_inline_unbound_export',lambda:observed(data(q=q)),True)
i=copy.deepcopy(intent);i['source_sha256']='f'*64
check('observer_rejects_wrong_dispatched_source',lambda:observed(data(),i),True)
check('observer_rejects_wrong_pinned_dispatcher',lambda:observed(data(),expected_dispatcher='f'*64),True)
check('dispatcher_requires_external_observer_dispatcher_pin',lambda:dispatch.arguments('M05_OBSERVE',None,None,None),True)
check('dispatcher_requires_exact_reset_checkpoint',lambda:dispatch.arguments('M05_RESET',None,None,None),True)
check('dispatcher_does_not_accept_restore_witness_for_reset',lambda:dispatch.arguments('G11_RESET','a'*64,'b'*64,'c'*64),True)
check('dispatcher_rejects_extra_digest_on_nonreset_stage',lambda:dispatch.arguments('M04','a'*64,None,None),True)
check('dispatcher_passes_current_restore_three_digest_arguments',lambda: (_ for _ in ()).throw(AssertionError()) if dispatch.arguments('M05_RESTORE','a'*64,'b'*64,'c'*64)!=['--checkpoint-sha256','a'*64,'--reset-result-sha256','b'*64,'--completion-sha256','c'*64] else None)
assert not attempted
print(json.dumps({'schema':1,'scope':'actual_runtime_binding_and_dispatch_functions_with_host_doubles','passed':len(checks),'expected':14,'checks':checks,'external_events_attempted':len(attempted),'adb_used':False,'network_used':False,'product_executed':False,'phone_qualified':False},sort_keys=True))
