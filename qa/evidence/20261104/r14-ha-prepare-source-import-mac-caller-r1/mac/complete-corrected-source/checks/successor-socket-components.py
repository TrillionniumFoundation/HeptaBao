#!/usr/bin/env python3
"""AST-selected source and fake-socket regression checks; no whole candidate import."""
import ast, contextlib, hashlib, json, types
from pathlib import Path
ROOT=Path(__file__).parent
PINS={"outer.before.py":{"bytes":58586,"sha256":"986194f0da2d278986589d5ec757fb50a040182db6f610addba9469ee97e1be5"},"outer.after.py":{"bytes":59477,"sha256":"5ecc57805f1fb2b162c38d28d28debe5e035ca3135db6b1b7df55daa6227df50"},"phase.before.py":{"bytes":25005,"sha256":"42520fe933e2c0106e6983a282421759b260a2bf48a08f86d0f404caa3f2eb86"},"phase.after.py":{"bytes":24971,"sha256":"bbf3636f4323e3e990204c8ea04c986f8740b3f34fa966a937f947b767ee15c4"},"materializer.before.py":{"bytes":23631,"sha256":"9ae14eccdec7742c31df92fede042acac68514b3713ef8cb751cb8f456fb1526"},"materializer.after.py":{"bytes":23643,"sha256":"f766ba33f22230d78e635477b35e527e7815452e591e7bc7a03fa2ae6c902b7f"}}
sources={}
for name,pin in PINS.items():
    raw=(ROOT/name).read_bytes()
    assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256']
    sources[name]=raw.decode()
    compile(ast.parse(sources[name],filename=name),name,'exec')
results=[]
def case(name,passed,**evidence):
    assert passed,name
    results.append(dict(case=name,passed=True,**evidence))
def definitions(source):
    lines=source.splitlines(keepends=True)
    return {x.name:''.join(lines[x.lineno-1:x.end_lineno]) for x in ast.parse(source).body
            if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
before=definitions(sources['outer.before.py']);after=definitions(sources['outer.after.py'])
assert before.keys()==after.keys()
unchanged=[k for k in before if k not in ('Context','reserve_port','main')]
assert all(before[k]==after[k] for k in unchanged)
old_aggregate="        socket_closed=(client is None or report['controlHttp']['allOwnedSocketsClosed'])"
new_aggregate="        socket_closed=(ctx.public()['allEphemeralPortReservationSocketsClosed']\n            and (client is None or report['controlHttp']['allOwnedSocketsClosed']))"
assert after['main'].replace(new_aggregate,old_aggregate)==before['main']
assert sources['phase.after.py'].replace(
    "        for name in ('mac_native_process_observer_r1.py',\n",
    "        for name in ('mac_native_process_observer_r1.py','authbus_native_login_custody.py',\n"
)==sources['phase.before.py']
assert sources['materializer.after.py'].replace(
    "and captured['declaredModelSha256']==sha(encoded(selected)+b'\\n'),'actual_per_agent_model_binding')",
    "and captured['declaredModelSha256']==digest(selected),'actual_per_agent_model_binding')"
)==sources['materializer.before.py']
def top_values(source):
    return [ast.dump(x,include_attributes=False) for x in ast.parse(source).body
            if isinstance(x,(ast.Assign,ast.AnnAssign))]
assert top_values(sources['outer.before.py'])==top_values(sources['outer.after.py'])
class Signals:
    def __init__(self):self.depth=0;self.pending=None
    @contextlib.contextmanager
    def critical(self):
        self.depth+=1
        try:yield
        finally:self.depth-=1
class FakeSocket:
    def __init__(self,mode,context):
        self.mode=mode;self.context=context;self.fd=41;self.close_calls=0
    def bind(self,address):
        assert address==('127.0.0.1',0)
        if self.mode=='bind-fail':raise OSError('synthetic bind failure')
    def getsockname(self):
        if self.mode=='getname-fail':raise OSError('synthetic name failure')
        return ('127.0.0.1',80 if self.mode=='invalid-port' else 24321)
    def close(self):
        self.close_calls+=1
        assert self.close_calls==1 and self.context.signals.depth>0
        row=getattr(self.context,'port_reservation',None)
        if row is not None:assert row['created'] and row['closeAttempted']
        if self.mode=='close-before-error':raise OSError('synthetic close failure')
        if self.mode=='close-interrupt':raise KeyboardInterrupt()
        if self.mode!='close-noop':self.fd=-1
        if self.mode=='close-after-error':raise OSError('synthetic uncertain close')
    def fileno(self):
        if self.mode=='fileno-error':raise OSError('synthetic fileno failure')
        return self.fd
class Factory:
    AF_INET='AF_INET';SOCK_STREAM='SOCK_STREAM'
    def __init__(self,mode):self.mode=mode;self.calls=0;self.created=[];self.context=None
    def socket(self,family,kind):
        self.calls+=1
        assert family==self.AF_INET and kind==self.SOCK_STREAM
        assert self.context.signals.depth>0
        if self.mode=='constructor-fail':raise OSError('synthetic constructor refusal')
        value=FakeSocket(self.mode,self.context);self.created.append(value);return value
def selected(source,mode):
    tree=ast.parse(source)
    keep=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef))
          and n.name in ('Refused','need','Context','reserve_port')]
    module=ast.fix_missing_locations(ast.Module(body=keep,type_ignores=[]))
    factory=Factory(mode)
    namespace={'START':0.0,'NEW_OUTER_SECONDS':900.0,'NEW_OUTER_FAILURE_CLEANUP_SECONDS':60.0,
               'time':types.SimpleNamespace(monotonic=lambda:0.0),'socket':factory}
    exec(compile(module,'<selected-real-context-and-reserve-port>','exec'),namespace)
    ctx=namespace['Context']();ctx.signals=Signals();factory.context=ctx
    assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign)
        and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='socket_closed')
    expression=compile(ast.fix_missing_locations(ast.Expression(body=assignment.value)),
                       '<actual-final-socket-closure-expression>','eval')
    return namespace,ctx,factory,expression
def observe(source,mode):
    ns,ctx,factory,expression=selected(source,mode)
    value=None;error=None
    try:value=ns['reserve_port'](ctx)
    except BaseException as exc:error=type(exc).__name__
    projection=ctx.public()
    aggregate=eval(expression,{'ctx':ctx,'client':None,'report':{}})
    return ns,ctx,factory,value,error,projection,aggregate
old=observe(sources['outer.before.py'],'close-before-error')
case('old_failure_reproduced',old[4]=='OSError' and old[1].unknown is False and old[6] is True,
     old_outcome_unknown=False,old_final_socket_aggregate=True)
success=observe(sources['outer.after.py'],'normal')
case('new_success_actual_close',success[3]==24321 and success[4] is None
     and not success[1].unknown and success[6] and success[2].created[0].close_calls==1,
     close_attempts=1)
for mode in ('close-before-error','close-after-error','close-noop','fileno-error','close-interrupt'):
    values=observe(sources['outer.after.py'],mode)
    ns,ctx,factory,value,error,projection,aggregate=values
    ctx.close_all()
    case(mode,error=='Refused' and ctx.unknown and not aggregate
         and projection['allEphemeralPortReservationSocketsClosed'] is False
         and projection['portReservation']['closeAttempted']
         and not projection['portReservation']['closed'] and factory.created[0].close_calls==1,
         outcome_unknown=True,final_socket_aggregate=False,close_attempts=1)
for mode,error_type in (('bind-fail','OSError'),('getname-fail','OSError'),('invalid-port','Refused')):
    ns,ctx,factory,value,error,projection,aggregate=observe(sources['outer.after.py'],mode)
    case(mode,error==error_type and not ctx.unknown and aggregate
         and factory.created[0].close_calls==1 and value is None,
         known_failure_with_socket_closed=True,product_success=False)
values=observe(sources['outer.after.py'],'constructor-fail')
case('constructor-refusal-no-owned-socket',values[4]=='OSError' and not values[1].unknown
     and values[6] and values[2].created==[] and not values[5]['portReservation']['created'])
for mode in ('normal','close-before-error'):
    ns,ctx,factory,value,error,projection,aggregate=observe(sources['outer.after.py'],mode)
    second=None
    try:ns['reserve_port'](ctx)
    except BaseException as exc:second=type(exc).__name__
    case('no_second_reservation_'+mode,second=='Refused' and factory.calls==1
         and factory.created[0].close_calls==1 and ctx.unknown==(mode!='normal'),
         factory_calls=1,close_attempts=1)
print(json.dumps({'schema':'heptabao.mac-complete-outer-successor-source-components.v1',
  'ok':True,'checks':results,'passed':len(results),'failed':0,
  'source_files':PINS,'compiled_full_source_count':len(sources),
  'unchanged_outer_definition_count':len(unchanged),'unchanged_outer_definitions':unchanged,
  'outer_top_level_constants_unchanged':True,'main_only_actual_socket_aggregate_changed':True,
  'phase_single_unused_name_change':True,'materializer_single_lf_comparison_change':True,
  'executed_candidate_definitions':['Refused','need','Context','reserve_port'],
  'full_candidate_modules_imported':0,'actual_sockets':0,'actual_descriptors':0,
  'child_processes':0,'network_requests':0,'sqlite_connections':0,'host_calls':0,
  'source_inputs':'Only six already-public source files in an owned local /tmp directory',
  'model_contract_components':'Independently executed by ha_validation; not re-counted here',
  'runtime_qualification':False},indent=2,sort_keys=True))
