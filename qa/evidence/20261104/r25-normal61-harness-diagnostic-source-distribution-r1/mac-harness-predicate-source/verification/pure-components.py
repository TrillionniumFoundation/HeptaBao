import ast, copy, hashlib, io, json, os as real_os, posixpath, re, signal as real_signal, stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT=Path('/tmp/mac-captured-harness-predicate-r1')
SOURCE=(ROOT/'predicate_observer.py').read_text()
assert hashlib.sha256(SOURCE.encode()).hexdigest()=='2b999a66c6c3578673fd4611c4d89bf14fd7fd3605c3839ddb4379216d0b3805'
TREE=ast.parse(SOURCE)
compile(TREE,'predicate_observer.py','exec')
NODES=[n for n in TREE.body if isinstance(n,(ast.Assign,ast.ClassDef,ast.FunctionDef))]
SELECTED=compile(ast.Module(body=NODES,type_ignores=[]),'selected-predicate-definitions','exec')
checks=[]
def check(name,value):
    assert value,name
    checks.append({'case':name,'passed':True})
class Clock:
    def __init__(self):self.now=0.0
    def monotonic(self):return self.now
class FakeSignal:
    SIGTERM=15
    SIGINT=2
    def __init__(self):
        self.handlers={15:'default',2:'default'};self.calls=0;self.cancel_on_final_restore=False
    def getsignal(self,n):return self.handlers[n]
    def signal(self,n,h):
        self.calls+=1
        if self.cancel_on_final_restore and self.calls==4:
            prior=self.handlers[n]
            if callable(prior):prior(15,None)
        old=self.handlers[n];self.handlers[n]=h;return old
def namespace():
    clock=Clock();signals=FakeSignal();stdout=io.BytesIO()
    ns={'__name__':'selected_component_only','contextmanager':contextmanager,'Path':Path,
        'hashlib':hashlib,'json':json,'os':SimpleNamespace(path=posixpath),'re':re,
        'signal':signals,'stat':stat,'sys':SimpleNamespace(platform='darwin',stdout=SimpleNamespace(buffer=stdout)),
        'time':clock}
    exec(SELECTED,ns)
    return ns,clock,signals,stdout
def fixture(ns,plugin_id='codex',root=None):
    if root is None:root=ns['KNOWN_CODEX_ROOT']
    plugins=[{'pluginId':plugin_id,'rootDir':root,'enabled':True,'startup':{'agentHarnesses':[{'id':'codex'}]}}]
    columns=['plugins_json']+['col'+str(i) for i in range(12)]
    return {'schema':'heptabao.mac-guarded-current-inputs.private.r1',
        'sourceConfigSha256':ns['CONFIG_SHA256'],'agentIds':list(ns['AGENTS']),
        'models':{a:{'provider':'openai','id':'gpt-5.6-sol','sourceConfigSha256':ns['CONFIG_SHA256'],
                     'declaredModelSha256':'a'*64} for a in ns['AGENTS']},
        'registry':{'columns':columns,'row':[json.dumps(plugins)]+[None]*12},
        'authDocuments':[{'syntheticCredential':'DO-NOT-PUBLISH-CREDENTIAL-CANARY'}]}
def raw_doc(doc):return json.dumps(doc,separators=(',',':')).encode()
def refused(ns,func,code):
    try:func()
    except ns['Refused'] as e:return str(e)==code
    return False

ns,_,_,_=namespace()
out=ns['predicate_projection'](raw_doc(fixture(ns)))
check('01_exact_original_valid_root_and_selection_not_claimed',
      out['enabledHarnessOwners'][0]['originalCompositePredicate'] is True
      and out['actualSelectedHarnessSetKnown'] is False
      and out['enabledHarnessOwners'][0]['actualSelectedForCurrentAgents'] is None
      and out['unselectedHarnessClaimed'] is False)

out=ns['predicate_projection'](raw_doc(fixture(ns,'@synthetic/scoped')))
row=out['enabledHarnessOwners'][0]
check('02_scoped_identifier_is_exact_legacy_regex_rejection',
      row['identifierMatchesOriginalRegex'] is False and row['rootIsAbsolute']
      and row['rootIsNormalized'] and row['rootInOriginalNpmProjectsNamespace']
      and out['firstCompositeRejectionOrdinal']==0)

out=ns['predicate_projection'](raw_doc(fixture(ns,'bundled','/opt/homebrew/lib/node_modules/openclaw/extensions/synthetic')))
row=out['enabledHarnessOwners'][0]
check('03_bundled_enabled_not_falsely_selected_or_unused',
      row['identifierMatchesOriginalRegex'] and row['rootIsAbsolute'] and row['rootIsNormalized']
      and not row['rootInOriginalNpmProjectsNamespace']
      and row['actualSelectedForCurrentAgents'] is None and row['publicCodeRoot'] is None
      and out['unselectedHarnessClaimed'] is False)

out=ns['predicate_projection'](raw_doc(fixture(ns,'codex',ns['KNOWN_CODEX_ROOT']+'/../codex')))
check('04_nonnormalized_root_rejected_exact_original_expression',
      out['enabledHarnessOwners'][0]['rootIsNormalized'] is False
      and out['enabledHarnessOwners'][0]['originalCompositePredicate'] is False)

doc=fixture(ns,'DO-NOT-PUBLISH-ID-CANARY','/DO-NOT-PUBLISH-ROOT-CANARY')
projected=ns['encoded'](ns['predicate_projection'](raw_doc(doc)))
check('05_no_private_or_unknown_id_root_literals_published',
      all(x not in projected for x in [b'DO-NOT-PUBLISH-CREDENTIAL-CANARY',b'DO-NOT-PUBLISH-ID-CANARY',b'DO-NOT-PUBLISH-ROOT-CANARY']))

doc=fixture(ns)
one=json.loads(doc['registry']['row'][0])[0]
doc['registry']['row'][0]=json.dumps([one]*129)
a=refused(ns,lambda:ns['predicate_projection'](raw_doc(doc)),'bounded_actual_registry_plugins')
doc['registry']['row'][0]=json.dumps([one]*9)
b=refused(ns,lambda:ns['predicate_projection'](raw_doc(doc)),'finite_actual_enabled_harness_roots')
check('06_original_128_registry_and_8_enabled_caps',a and b)

class FakeOS:
    O_RDONLY=real_os.O_RDONLY
    O_DIRECTORY=real_os.O_DIRECTORY
    O_NOFOLLOW=real_os.O_NOFOLLOW
    O_NONBLOCK=real_os.O_NONBLOCK
    path=posixpath
    def __init__(self,ns,data,clock,signal_state):
        self.ns,self.data,self.clock,self.signal_state=ns,data,clock,signal_state
        self.info={};self.fds={};self.nextfd=100;self.position=0;self.close_calls=[]
        self.open_calls=0;self.cancel_open_at=None;self.drift_on_eof=False
        self.late_on_eof=False;self.fail_close_fd=None
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        anchors={a['path']:a['identity'] for a in ns['EXPECTED_ANCHORS']}
        for i,path in enumerate(ns['PARENT_PATHS']):
            values=anchors.get(path,['16777244',str(9900+i),'501','20','16832','2','64','1000000001','1000000001'])
            self.info[path]=dict(zip(fields,map(int,values)))
        self.info[ns['CAPSULE']['path']]=dict(zip(fields,map(int,ns['CAPSULE']['identity'])))
    def getuid(self):return 501
    def getinfo(self,path):return SimpleNamespace(**self.info[path])
    def lstat(self,path):return self.getinfo(path)
    def resolve(self,name,dir_fd):
        return name if dir_fd is None else posixpath.join(self.fds[dir_fd],name)
    def stat(self,name,*,dir_fd=None,follow_symlinks=False):
        assert follow_symlinks is False
        return self.getinfo(self.resolve(name,dir_fd))
    def fstat(self,fd):return self.getinfo(self.fds[fd])
    def open(self,name,flags,*,dir_fd=None):
        path=self.resolve(name,dir_fd)
        assert path in self.info
        fd=self.nextfd;self.nextfd+=1;self.fds[fd]=path;self.open_calls+=1
        if self.open_calls==self.cancel_open_at:self.signal_state.receive(15,None)
        return fd
    def read(self,fd,want):
        assert self.fds[fd]==self.ns['CAPSULE']['path']
        part=self.data[self.position:self.position+want];self.position+=len(part)
        if not part:
            if self.drift_on_eof:self.info[self.ns['PARENT_PATHS'][5]]['st_mtime_ns']+=1
            if self.late_on_eof:self.clock.now=5.01
        return part
    def close(self,fd):
        self.close_calls.append(fd)
        if fd==self.fail_close_fd:raise OSError(5,'synthetic close failure')
        del self.fds[fd]

def reader_fixture(extra=b''):
    ns,clock,fake_signal,stdout=namespace()
    body=raw_doc(fixture(ns))
    body=body+b' '*(195155-len(body))
    # Synthetic memory rebinding only; no real path, FD or captured private data is accessed.
    ns['CAPSULE']=dict(ns['CAPSULE'])
    ns['CAPSULE']['sha256']=hashlib.sha256(body).hexdigest()
    signal_state=ns['Signals']()
    fake=FakeOS(ns,body+extra,clock,signal_state)
    ns['os']=fake
    reader=ns['FixedReader'](signal_state,5.0)
    return ns,clock,fake_signal,stdout,signal_state,fake,reader,body
def read_and_close(reader,signal_state,after=None):
    failure=None;raw=None
    with signal_state.critical():
        try:
            raw=reader.read_exact_capsule()
            if after:after(raw)
            reader.verify_all()
        except BaseException as e:
            failure=e
        finally:reader.close()
    return raw,failure

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
raw,error=read_and_close(r,sig,lambda b:ns['predicate_projection'](b))
check('07_fake_complete_fullnine_72_metadata_9_fd_4_reads',
      error is None and raw==body and r.metadata_calls==72 and len(r.rows)==9
      and r.read_calls==4 and r.read_bytes==195155 and r.public()['allOwnedDescriptorsClosed']
      and len(fake.close_calls)==9 and len(set(fake.close_calls))==9)

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
fake.cancel_open_at=4
_,error=read_and_close(r,sig)
check('08_cancel_after_open_returns_still_registered_and_closed',
      isinstance(error,ns['Cancelled']) and len(r.rows)==4 and len(fake.close_calls)==4
      and r.public()['allOwnedDescriptorsClosed'] and not fake.fds)

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
fake.drift_on_eof=True
_,error=read_and_close(r,sig)
check('09_parent_fullnine_drift_refuses_after_whole_read',
      isinstance(error,ns['Refused']) and str(error)=='same_named_held_full_nine'
      and r.public()['allOwnedDescriptorsClosed'] and len(fake.close_calls)==9)

ns,clock,fs,out,sig,fake,r,body=reader_fixture(extra=b'X')
_,error=read_and_close(r,sig)
check('10_one_eof_byte_counts_no_extra_read',
      isinstance(error,ns['Refused']) and str(error)=='fixed_private_byte_bound' and r.read_bytes==195156 and r.read_calls==3
      and r.public()['allOwnedDescriptorsClosed'])

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
fake.fail_close_fd=104
_,error=read_and_close(r,sig)
before=list(fake.close_calls);r.close()
check('11_close_error_keeps_false_and_no_second_close',
      error is None and not r.public()['allOwnedDescriptorsClosed'] and len(r.close_errors)==1
      and fake.close_calls==before and len(before)==9 and len(set(before))==9)

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
fake.late_on_eof=True
_,error=read_and_close(r,sig)
check('12_same_absolute_deadline_refuses_late_read_but_closes',
      isinstance(error,ns['Refused']) and str(error)=='original_diagnostic_deadline'
      and r.public()['allOwnedDescriptorsClosed'] and clock.now>5)

ns,clock,fs,out,sig,fake,r,body=reader_fixture()
# Main constructs its own Signals; connect the fake OS to that exact object.
original_signals=ns['Signals']
def new_signals():
    value=original_signals();fake.signal_state=value;return value
ns['Signals']=new_signals
fs.cancel_on_final_restore=True
failed=None
try:
    result=ns['main']()
except BaseException as e:
    failed=e
printed=json.loads(out.getvalue())
check('13_actual_main_late_restore_cancellation_cannot_return_success',
      isinstance(failed,ns['Cancelled']) and printed['observationComplete'] is False
      and printed['pendingSignal']==15 and printed['closure']['allOwnedDescriptorsClosed']
      and len(fake.close_calls)==9 and len(set(fake.close_calls))==9
      and fs.handlers=={15:'default',2:'default'})

report={'schema':'heptabao.mac-captured-harness-predicate-pure-components.r1',
 'sourceSha256':hashlib.sha256(SOURCE.encode()).hexdigest(),'checksPassed':len(checks),
 'checks':checks,'actualHostCalls':0,'actualDescriptors':0,'actualSignalsSent':0,
 'actualSqlite':0,'actualNetwork':0,'actualSubprocess':0,
 'candidateFullModuleMainNotRunOnHost':True,
 'selectedSourceDefinitionsExecutedAgainstMemoryFakesOnly':True,
 'syntheticMemoryCapsuleHashRebindingNotHostQualification':True,
 'actualCapturedPrivateBodyLoaded':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'components.stdout.json').open('xb') as f:f.write(raw)
print(raw.decode(),end='')
