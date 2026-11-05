#!/usr/bin/env python3
"""Selected pure functions only; no import or execution of the complete outer."""
import ast, copy, hashlib, json
from pathlib import Path
BASE=Path(__file__).parent
source=(BASE/'outer.proposed.py').read_text()
before=(BASE/'outer.before.py').read_text()
assert hashlib.sha256(source.encode()).hexdigest()=='72ecfcd586a4ab4c48fd95d2e15b4a44165a754570c699eae18dceaa02f3b262'
assert hashlib.sha256(before.encode()).hexdigest()=='bce47fd194be7ec1d1ec340e24d8e759dbf7611ef3c75eca2adeb62e9b4ccf01'
tree=ast.parse(source);old=ast.parse(before)
compile(tree,'outer.proposed.py','exec')
names={'token_lookup_snapshot','token_lifecycle_before','token_lifecycle'}
selected=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name in names]
assert len(selected)==3
class Refused(Exception):pass
def need(value,code):
    if not value:raise Refused(code)
def exact_data(value):
    need(isinstance(value,dict) and isinstance(value.get('data'),dict),'typed_data')
    return value['data']
g={'ROOT':Path('/synthetic-owned-root'),'need':need,'exact_data':exact_data,
   'exact_json':json.loads}
exec(compile(ast.Module(body=selected,type_ignores=[]),'selected-renewal','exec'),g)
TOKEN='synthetic-opaque-token';ACCESSOR='synthetic-opaque-accessor'
def lookup(ttl=170,expiry=1180,token=TOKEN,accessor=ACCESSOR,renewable=True):
    return {'data':{'id':token,'accessor':accessor,'type':'service','namespace':'',
                    'renewable':renewable,'ttl':ttl,'expire_time_unix':expiry,
                    'creation_time':1000}}
class FakeGuard:
    def __init__(self):self.reads=[]
    def read(self,path,cap):
        self.reads.append((str(path),cap))
        return json.dumps({'tokens':[TOKEN]}).encode()
class FakeClient:
    def __init__(self,delta=5):self.rows=[];self.delta=delta;self.override={}
    def call(self,label,method,route,body=None,*,token=None,expected=200,validate=None):
        self.rows.append({'label':label,'method':method,'route':route,'body':body,'expected':expected})
        assert token==TOKEN
        if label.startswith('lookup-self-before-'):value=lookup()
        elif label.startswith('lookup-self-after-'):value=lookup(ttl=175,expiry=1180+self.delta)
        elif label.startswith('renew-self-'):
            assert method=='POST' and body=={}
            value={'auth':{'client_token':TOKEN,'accessor':ACCESSOR,'renewable':True,'lease_duration':180}}
        else:value={}
        if route in self.override:value=copy.deepcopy(self.override[route])
        if validate is not None:validate(value)
        return value
checks=[]
def record(name,value):
    assert value,name
    checks.append({'case':name,'passed':True})
def run_chain(delta):
    client=FakeClient(delta);guard=FakeGuard();secrets=set()
    private=g['token_lifecycle_before'](client,guard,'initial',secrets)
    client.rows.append({'label':'existing-canonical-and-inbox-operation'})
    public=g['token_lifecycle'](client,'initial',private)
    return client,guard,secrets,public
client,guard,secrets,public=run_chain(5)
record('same_credential_chain_and_existing_kv_position',
    [x['label'] for x in client.rows]==[
      'lookup-self-before-initial','existing-canonical-and-inbox-operation',
      'unassigned-denied-initial','renew-self-initial','lookup-self-after-initial',
      'revoke-self-initial','revoked-denied-initial']
    and len(guard.reads)==1 and guard.reads[0][1]==65536
    and public['expiryDeltaSeconds']==5 and public['expiryExtensionObserved'] is True
    and public['sameCredentialAcrossLookupAndRenew'] is True
    and public['sameAccessorAcrossLookupAndRenew'] is True)
serial=json.dumps(public,sort_keys=True)
record('public_projection_has_no_token_or_accessor',
    TOKEN not in serial and ACCESSOR not in serial and set(secrets)=={TOKEN,ACCESSOR}
    and set(public['lookupBefore'])=={'ttlSeconds','expiresAtUnix','renewable'}
    and set(public['lookupAfter'])=={'ttlSeconds','expiresAtUnix','renewable'})
_,same_guard,_,same=run_chain(0)
record('same_second_legal_renew_is_not_extension',
    same['renewed'] is True and same['revoked'] is True
    and same['expiryExtensionObserved'] is False and same['expiryObservation']=='unchanged'
    and same['expiryDeltaSeconds']==0 and len(same_guard.reads)==1)
_,_,_,decreased=run_chain(-1)
record('decreased_expiry_is_observed_not_qualified',
    decreased['revoked'] is True and decreased['expiryExtensionObserved'] is False
    and decreased['expiryObservation']=='decreased' and decreased['expiryDeltaSeconds']==-1)
try:g['token_lookup_snapshot'](lookup(token='other'),TOKEN)
except Refused as error:record('wrong_lookup_credential_refused',str(error)=='lookup_self_echoes_same_presented_credential')
else:raise AssertionError('credential accepted')
expected=g['token_lookup_snapshot'](lookup(),TOKEN)
try:g['token_lookup_snapshot'](lookup(accessor='other'),TOKEN,expected)
except Refused as error:record('changed_accessor_refused',str(error)=='same_accessor_and_creation_across_self_lookups')
else:raise AssertionError('accessor accepted')
bad_client=FakeClient();bad_guard=FakeGuard()
private=g['token_lifecycle_before'](bad_client,bad_guard,'initial',set())
bad_client.override['auth/token/renew-self']={'auth':{'client_token':'other','accessor':ACCESSOR,
   'renewable':True,'lease_duration':180}}
try:g['token_lifecycle'](bad_client,'initial',private)
except Refused as error:
    record('wrong_renewed_credential_refused_without_continuation',
        str(error)=='actual_renewal_same_credential_accessor_and_ttl'
        and bad_client.rows[-1]['label']=='renew-self-initial')
else:raise AssertionError('renew credential accepted')
negative_values=[lookup(ttl=True),lookup(ttl=0),lookup(ttl=601),lookup(renewable=False)]
refused=0
for value in negative_values:
    try:g['token_lookup_snapshot'](value,TOKEN)
    except Refused:refused+=1
record('ttl_type_zero_bound_and_nonrenewable_refused',refused==len(negative_values))
old_functions={x.name:ast.get_source_segment(before,x) for x in old.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
new_functions={x.name:ast.get_source_segment(source,x) for x in tree.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
unchanged=[name for name in old_functions if old_functions[name]==new_functions.get(name)]
modified=[name for name in old_functions if old_functions[name]!=new_functions.get(name)]
assert sorted(modified)==['main','token_lifecycle']
assert 'LoopbackHTTP' in unchanged and 'Context' in unchanged
old_assign={x.targets[0].id:ast.get_source_segment(before,x.value) for x in old.body
  if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name)}
new_assign={x.targets[0].id:ast.get_source_segment(source,x.value) for x in tree.body
  if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name)}
changed_assign=[name for name in old_assign if old_assign[name]!=new_assign.get(name)]
assert changed_assign==['BINDING_READY'] and new_assign['BINDING_READY']=='False'
report={'schema':'heptabao.renewal-lookup-increment-pure-selected-checks.r1',
 'status':'passed','selectedFunctionCount':3,'caseCount':len(checks),'checks':checks,
 'topLevelFunctionsAndClassesUnchanged':unchanged,
 'modifiedExistingDefinitions':modified,'onlyChangedTopLevelAssignment':'BINDING_READY=False',
 'completeModuleCompiledOnly':True,'completeModuleImportedOrExecuted':False,
 'actualHostAccess':False,'actualNetwork':False,'actualSqlite':False,'actualChild':False,
 'actualCredential':False,'fakeTokenFileReadCountPerChain':1,
 'scope':'Eight selected pure/mock groups; not a service, expiry extension, SDK selector, or runtime qualification.',
 'increasedCase':public,'unchangedCase':same,'decreasedCase':decreased}
raw=json.dumps(report,indent=2,sort_keys=True)+'\n'
assert TOKEN not in raw and ACCESSOR not in raw
(BASE/'result.public.json').write_text(raw)
print(raw,end='')
