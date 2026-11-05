#!/usr/bin/env python3
"""Four selected pure ledger families; AST extraction, fake handles only."""
import ast, base64, hashlib, json, re, stat, sys, types
from contextlib import nullcontext
from pathlib import Path

payload=json.loads(sys.stdin.read())
sources=payload['sources']
for name,raw in sources.items():
    assert hashlib.sha256(raw.encode()).hexdigest()==payload['sha256'][name]

def prohibit(event,args):
    if event in ('open','sqlite3.connect','subprocess.Popen','socket.__new__','os.system',
                 'os.fork','os.posix_spawn','os.exec','os.kill','os.killpg'):
        raise RuntimeError('component_io_prohibited:'+event)
sys.addaudithook(prohibit)

class Clock:
    def __init__(self):self.now=0.0;self.samples=[]
    def monotonic(self):self.samples.append(self.now);return self.now
class FakeOS:
    O_RDONLY=0;O_NOFOLLOW=1;O_NONBLOCK=2
    def __init__(self,clock):self.clock=clock;self.closed=[];self.after_close=None;self.close_error=False;self.named={};self.held={};self.close_fail_fds=set();self.read_done=False
    def geteuid(self):return 501
    def getuid(self):return 501
    def close(self,fd):
        self.closed.append(fd)
        if self.after_close is not None:self.clock.now=self.after_close
        if self.close_error or fd in self.close_fail_fds:raise OSError(5,'synthetic')
    def open(self,path,flags):return 90
    def read(self,fd,n):
        assert fd==90
        if self.read_done:return b''
        self.read_done=True;return b'owned-code'
    def lstat(self,path):return self.named[(None,str(path))]
    def stat(self,name,*,dir_fd,follow_symlinks):
        assert follow_symlinks is False
        key=(dir_fd,name)
        if key not in self.named:raise FileNotFoundError(2,'synthetic')
        return self.named[key]
    def fstat(self,fd):return self.held[fd]
class FakeSqlError(Exception):pass
class FakeCursor:
    def __init__(self,db):self.db=db;self.description=None;self.rows=[];self.close_count=0
    def execute(self,sql,args=()):
        self.db.statements.append(sql)
        self.rows=[]
        if sql=='PRAGMA query_only':self.rows=[(1,)]
        elif sql=='SELECT sqlite_source_id()':self.rows=[(self.db.engine.source_id,)]
        elif sql=='PRAGMA database_list':self.rows=[(0,'main',self.db.engine.main_path)]
        if sql in self.db.engine.result_rows:self.rows=list(self.db.engine.result_rows[sql])
        self.description=('public',) if self.rows else None
        return self
    def fetchmany(self,n):return self.rows[:n]
    def fetchone(self):return self.rows.pop(0) if self.rows else None
    def close(self):self.close_count+=1
class FakeConnection:
    def __init__(self,engine):self.engine=engine;self.close_count=0;self.statements=[];self.cursors=[]
    def cursor(self):
        c=FakeCursor(self);self.cursors.append(c);return c
    def execute(self,sql,args=()):return self.cursor().execute(sql,args)
    def setlimit(self,*args):return 0
    def enable_load_extension(self,*args):pass
    def set_progress_handler(self,*args):pass
    def set_authorizer(self,*args):pass
    def close(self):
        self.close_count+=1
        if self.engine.close_time is not None:self.engine.clock.now=self.engine.close_time
        if self.engine.close_error:raise OSError(5,'synthetic')
class FakeSqlite:
    Connection=FakeConnection
    Error=FakeSqlError
    SQLITE_LIMIT_LENGTH=0;SQLITE_LIMIT_SQL_LENGTH=1
    SQLITE_SELECT=21;SQLITE_READ=20;SQLITE_PRAGMA=19;SQLITE_TRANSACTION=22;SQLITE_OK=0;SQLITE_DENY=1
    def __init__(self,clock):
        self.clock=clock;self.created=[];self.attempts=[];self.connect_error=False;self.close_error=False;self.close_time=None;self.result_rows={}
        self.source_id='2026-01-01 00:00:00 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc'
        self.main_path='/synthetic-owned/main.sqlite'
    def connect(self,database,**kwargs):
        self.attempts.append((database,kwargs))
        if self.connect_error:raise FakeSqlError('synthetic')
        c=FakeConnection(self);self.created.append(c);return c

BASE_NAMES={'CaptureRefused','need','encoded','sha','identity','parent_identity','FixedInputs','immutable_query'}
NEW_NAMES={'failure_record','CaptureAttemptFailure','WalInputs','_full_parent','verify_bundle',
           'readonly_wal_query','observed_runtime','attempt_registry','capture_current_with_wal','configure_connection',
           'read_registry'}
base_raw=sources['mac_guarded_current_capture_r3.py']
new_raw=sources['mac_registry_readonly_wal_r1.py']
def selected(raw,names):
    tree=ast.parse(raw)
    body=[x for x in tree.body if isinstance(x,(ast.ClassDef,ast.FunctionDef)) and x.name in names]
    assert {x.name for x in body}==names
    return compile(ast.Module(body=body,type_ignores=[]),'<selected-actual-source>','exec')
base_code=selected(base_raw,BASE_NAMES);new_code=selected(new_raw,NEW_NAMES)
runtime={'pythonExecutable':{'path':'public-synthetic','bytes':1,'sha256':'0'*64},
         'sqliteExtension':{'path':'public-synthetic-extension','bytes':1,'sha256':'1'*64},
         'pythonVersion':'synthetic','sqliteVersion':'3.53.4','sqliteVersionInfo':[3,53,4]}
actual_definition_hashes={}
for raw,names,prefix in ((base_raw,BASE_NAMES,'base'),(new_raw,NEW_NAMES,'new')):
    lines=raw.splitlines(keepends=True)
    for node in ast.parse(raw).body:
        if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name in names:
            actual_definition_hashes[prefix+'.'+node.name]=hashlib.sha256(''.join(lines[node.lineno-1:node.end_lineno]).encode()).hexdigest()

def environment():
    clock=Clock();fake_os=FakeOS(clock);sqlite=FakeSqlite(clock)
    common={'json':json,'hashlib':hashlib,'re':re,'stat':stat,'Path':Path,'base64':base64,
            'os':fake_os,'time':clock,'sqlite3':sqlite,'sys':types.SimpleNamespace(platform='darwin'),
            'LIVE':Path('/Users/qianqi/.openclaw'),'MIB':1024*1024,'MAX_ROW_BYTES':1024*1024,
            'MAX_RETURNED_AND_READ_BYTES':8*1024*1024,'MAX_QUERY_SECONDS':3.0,'NEW_CAPTURE_SECONDS':45.0}
    base_env=dict(common);exec(base_code,base_env)
    base=types.SimpleNamespace(**{k:v for k,v in base_env.items() if not k.startswith('__')})
    base.runtime_identity=lambda **kwargs:runtime
    base.validate_synthetic_proof=lambda *args,**kwargs:None
    base.current_models=lambda cfg:{}
    base.AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
    base.CACHE_NAMES=()
    base.CONFIG_SHA=hashlib.sha256(b'{}').hexdigest()
    env=dict(common,base=base,need=base.need,encoded=base.encoded,identity=base.identity,
        SYNTHETIC_ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-current-registry-readonly-wal-synthetic-r1'),
        CASES=tuple('W%02d'%i for i in range(1,11)),SCHEMA='selected-component',SOURCE_SCHEMA='selected-runtime',
        SQLITE_SOURCE_UUID=sqlite.source_id.split()[-1],URI_OPTIONS='mode=ro&cache=private&vfs=unix-posix&readonly_shm=1')
    exec(new_code,env)
    env['public_runtime_identity']=lambda inputs,until=None:runtime
    return env,base_env,base,clock,fake_os,sqlite

def make_inputs(env):
    obj=env['WalInputs'](until=45.0,critical=nullcontext,cancelled=lambda:False)
    obj.fds.append({'fd':81,'path':'/synthetic-owned/main.sqlite','closeAttempted':False,'closed':False})
    obj.verify=lambda:setattr(obj,'verified',True)
    return obj
def configure_query(env):
    env['observed_runtime']=lambda inputs:{'runtime':runtime,'sqliteSourceId':'public'}
    env['registry_wal_database']=lambda inputs:{'main':{'path':'/synthetic-owned/main.sqlite'}}
    env['verify_bundle']=lambda inputs,bundle,until:inputs.remaining(until)
    env['uri_for']=lambda bundle:'file:/synthetic-owned/main.sqlite?mode=ro&cache=private&vfs=unix-posix&readonly_shm=1'
    env['read_registry']=lambda inputs,connection,until:{'public':'fixed-row'}
def capture_old_failure(connect_error=False,close_error=False):
    env,base_env,base,clock,fake_os,sqlite=environment()
    sqlite.connect_error=connect_error;sqlite.close_error=close_error
    obj=make_inputs(env);obj.read=lambda *args,**kwargs:b'{}'
    env['WalInputs']=lambda **kwargs:obj
    env['observed_runtime']=lambda inputs:{'runtime':runtime,'sqliteSourceId':'public'}
    env['validate_wal_proof']=lambda *args:None
    env['validate_original_immutable_proof']=lambda *args:None
    base.auth_rows=lambda inputs,agent:base_env['immutable_query'](inputs,{'fd':81},lambda db,until:{})
    try:
        env['capture_current_with_wal'](critical=nullcontext,cancelled=lambda:False,synthetic_proof=b'x',
            synthetic_proof_sha='0'*64,wal_proof=b'y',wal_proof_sha='1'*64,until=45.0)
    except env['CaptureAttemptFailure'] as caught:public=caught.public
    else:raise AssertionError('old negative must have failure envelope')
    return public,obj,sqlite,fake_os

families=[]
# Family 1: original no-handle attempts are unobservable, new attempts explicit.
public,obj,sqlite,fake_os=capture_old_failure(connect_error=True)
assert len(sqlite.attempts)==1 and not sqlite.created, public
assert public['originalImmutableRouteInvoked'] is True and public['originalImmutableConnectAttemptCount'] is None
assert public['connections']==[] and public['connectAttempts']==[] and public['observationUnknown'] and not public['ok']
assert public['allOwnedDescriptorsClosed'] and fake_os.closed==[81]
env,be,base,clock,fo,sql=environment();sql.connect_error=True;obj=make_inputs(env)
value,public=env['attempt_registry'](obj)
assert value is None and not public['ok'] and public['observationUnknown']
assert len(public['connectAttempts'])==1 and public['connectAttempts'][0]['handleReturned'] is False
assert public['connectAttempts'][0]['error'] is not None and public['connections']==[] and fo.closed==[81]
families.append({'family':'L01-connect-unreturned','variants':2,'passed':True,
                 'oldAttemptCountIsNull':True,'newAttemptRecordedBeforeCall':True})

# Concrete root-review addendum: returned bytes are counted before refusal,
# and an exhausted aggregate refuses before another cursor/fetch is created.
accounting=[]
env,be,base,clock,fo,sql=environment();obj=make_inputs(env)
connection=obj.connect('public',until=45,label='accounting');sql.result_rows['public-row-count']=[('a',),('b',)]
try:obj.execute(connection,'public-row-count',until=45,limit=1,label='count-refusal')
except base.CaptureRefused as error:assert str(error)=='fixed_sql_result_count'
else:raise AssertionError('count refusal required')
assert len(obj.returned_rows)==2 and all(r['countedInAggregate'] for r in obj.returned_rows)
assert obj.byte_count==sum(r['bytes'] for r in obj.returned_rows)
obj.close();assert obj.public()['allOwnedDescriptorsClosed']
accounting.append('overflow-row-counted-before-count-refusal')
env,be,base,clock,fo,sql=environment();obj=make_inputs(env);connection=obj.connect('public',until=45,label='accounting')
names=['index_key']+['c_'+x for x in 'abcdefghijkl']
sql.result_rows["SELECT sql FROM sqlite_master WHERE type='table' AND name=? LIMIT 2"]=[('CREATE TABLE installed_plugin_index(index_key TEXT PRIMARY KEY)',)]
sql.result_rows['PRAGMA table_info(installed_plugin_index)']=[(i,n,'TEXT',0,None,1 if i==0 else 0) for i,n in enumerate(names)]
statement='SELECT '+','.join('"'+n+'"' for n in names)+' FROM installed_plugin_index WHERE index_key=? LIMIT 2'
sql.result_rows['EXPLAIN QUERY PLAN '+statement]=[(1,0,0,'SEARCH installed_plugin_index USING INDEX sqlite_autoindex_installed_plugin_index_1 (index_key=?)')]
sql.result_rows[statement]=[tuple(['installed-plugin-index','P'*(1024*1024+1)]+['public']*11)]
try:env['read_registry'](obj,connection,until=45)
except base.CaptureRefused as error:assert str(error)=='registry_returned_byte_cap'
else:raise AssertionError('oversize row refusal required')
assert obj.byte_count>1024*1024 and obj.byte_count<=8*1024*1024
assert {r['label'] for r in obj.returned_rows}=={'registry-schema','registry-columns','registry-key-plan','registry-fixed-row'}
assert all(r['countedInAggregate'] for r in obj.returned_rows)
obj.close();assert obj.public()['allOwnedDescriptorsClosed']
accounting.append('schema-info-plan-and-oversize-data-counted-before-row-cap')
env,be,base,clock,fo,sql=environment();obj=make_inputs(env);connection=obj.connect('public',until=45,label='accounting')
obj.byte_count=8*1024*1024-100
try:obj.execute(connection,'not-executed',until=45,label='remaining-admission')
except base.CaptureRefused as error:assert str(error)=='returned_budget_pre_execute_admission'
else:raise AssertionError('pre-admission refusal required')
assert not obj.cursors and not sql.created[0].statements and not obj.returned_rows
obj.close();families[0]['returnedAccountingAddendum']=accounting+['insufficient-remaining-refused-before-cursor']

# Family 2: old immutable and new runtime/registry all use the same final ledger.
variants=[]
public,obj,sql,fo=capture_old_failure(close_error=True)
for label in ('old-immutable','new-runtime','new-registry'):
    if label!='old-immutable':
        env,be,base,clock,fo,sql=environment();obj=make_inputs(env);sql.close_error=True
        if label=='new-registry':configure_query(env)
        value,public=env['attempt_registry'](obj);assert value is None
    assert not public['ok'] and public['observationUnknown'] and public['libraryFailureLedgerAvailable']
    assert not public['allReturnedConnectionsClosed'] and not public['allHeldDescriptorsClosed']
    assert not public['allOwnedDescriptorsClosed'] and not public['privateResultPublished']
    assert len(sql.created)==1 and sql.created[0].close_count==1 and fo.closed==[]
    assert public['connections'][0]['closeAttempted'] and not public['connections'][0]['closed']
    assert public['descriptors'][0]['closeBlockedByUnconfirmedConnection'] is True
    obj.close();assert sql.created[0].close_count==1 and fo.closed==[]
    variants.append({'route':label,'closeAttempts':1,'heldFdCloseAttempts':0,'unknown':True})
env,be,base,clock,fo,sql=environment();obj=make_inputs(env);configure_query(env)
value,public=env['attempt_registry'](obj)
assert value is not None and public['ok'] and sql.created[0].close_count==1 and fo.closed==[81]
assert public['allOwnedDescriptorsClosed'] and public['allReturnedConnectionsClosed']
families.append({'family':'L02-unified-connection-before-fd-close','variants':variants,
                 'successfulOrderControlPassed':True,'passed':True})

# New public code FD failure is part of the same final envelope, not hidden by
# the successful SQLite and held-data closes. No real open/close occurs.
env,be,base,clock,fo,sql=environment();obj=make_inputs(env)
code_stat=types.SimpleNamespace(st_dev=1,st_ino=90,st_uid=0,st_gid=0,st_mode=stat.S_IFREG|0o755,
    st_nlink=1,st_size=10,st_mtime_ns=1,st_ctime_ns=2)
fo.held[90]=code_stat;fo.close_fail_fds={90}
class FakePublicPath:
    def __init__(self,value):self.value=str(value)
    def resolve(self,strict):assert strict is True;return self
    def lstat(self):return code_stat
    def __str__(self):return self.value
env['Path']=FakePublicPath
env['public_runtime_identity']=lambda inputs,until=None:inputs.code_pin('public-code',until=until)
value,public=env['attempt_registry'](obj)
assert value is None and not public['ok'] and public['observationUnknown']
assert public['allReturnedConnectionsClosed'] and public['allHeldDescriptorsClosed']
assert not public['allPublicCodeDescriptorsClosed'] and not public['allOwnedDescriptorsClosed']
assert fo.closed.count(90)==1 and fo.closed.count(81)==1 and sql.created[0].close_count==1
obj.close();assert fo.closed.count(90)==1
families[1]['publicCodeFdCloseFailureVisible']=True

# Family 3: a returned close cannot make a late 3s/45s attempt green.
deadline_variants=[]
for after_close,success in ((2.999,True),(3.0,False),(3.001,False)):
    env,be,base,clock,fo,sql=environment();obj=make_inputs(env);configure_query(env);sql.close_time=after_close
    value,public=env['attempt_registry'](obj)
    assert public['ok'] is success and (value is not None) is success
    assert public['queries'][0]['completedMonotonic']==after_close
    assert public['allOwnedDescriptorsClosed'] and sql.created[0].close_count==1
    if not success:assert public['error']['code']=='original_capture_or_query_deadline_exhausted'
    deadline_variants.append({'completed':after_close,'success':success})
env,be,base,clock,fo,sql=environment();obj=make_inputs(env);configure_query(env);fo.after_close=45.001
value,public=env['attempt_registry'](obj)
assert value is None and not public['ok'] and public['observationUnknown']
assert public['allOwnedDescriptorsClosed'] and not public['originalDeadlineMetAfterClosure']
assert public['completedMonotonic']==45.001 and fo.closed==[81]
families.append({'family':'L03-original-completion-deadlines','query':deadline_variants,
                 'lateCaptureAfterFdCloseRefused':True,'passed':True})

# Family 4: full nine-field parent/main/WAL/SHM identity changes each refuse.
def fake_stat(values):
    names=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    return types.SimpleNamespace(**dict(zip(names,values)))
identity_rows={'parent':[1,11,501,20,stat.S_IFDIR|0o700,3,128,100,200],
               'main':[1,21,501,20,stat.S_IFREG|0o600,1,8192,101,201],
               'wal':[1,22,501,20,stat.S_IFREG|0o600,1,512,102,202],
               'shm':[1,23,501,20,stat.S_IFREG|0o600,1,32768,103,203]}
drifts=[]
for changed in (None,*((kind,i) for kind in identity_rows for i in range(9))):
    env,be,base,clock,fo,sql=environment();obj=make_inputs(env);obj.fds=[]
    parent={'fd':10,'path':'/','parent':None,'name':'/'}
    original=identity_rows['parent'];fo.named[(None,'/')]=fake_stat(original);fo.held[10]=fake_stat(original)
    bundle={'parents':[{'row':parent,'expected':base.identity(fake_stat(original))}],
            'journal':'/synthetic-owned/main.sqlite-journal','verified':False,'checks':0}
    for i,kind in enumerate(('main','wal','shm'),20):
        values=identity_rows[kind];row={'name':kind,'parent':parent,'fd':i,'expected':base.identity(fake_stat(values))}
        bundle[kind]=row;fo.named[(10,kind)]=fake_stat(values);fo.held[i]=fake_stat(values)
    obj.absent[bundle['journal']]={'name':'journal','parent':parent}
    if changed is not None:
        kind,index=changed;values=list(identity_rows[kind]);values[index]+=1
        if kind=='parent':fo.named[(None,'/')]=fake_stat(values);fo.held[10]=fake_stat(values)
        else:fo.named[(10,kind)]=fake_stat(values);fo.held[bundle[kind]['fd']]=fake_stat(values)
    try:env['verify_bundle'](obj,bundle,until=45.0)
    except base.CaptureRefused as error:
        assert changed is not None
        assert str(error)==('registry_wal_full_parent_changed' if changed[0]=='parent' else 'registry_wal_full_leaf_changed')
        drifts.append({'kind':changed[0],'fieldIndex':changed[1],'refused':True})
    else:assert changed is None and bundle['verified'] and bundle['checks']==1
assert len(drifts)==36
families.append({'family':'L04-full-nine-field-fences','baselinePassed':True,'drifts':drifts,'passed':True})

result={'schema':'heptabao.mac-registry-wal-four-ledger-components.r1','families':families,
        'familyCount':4,'allPassed':all(x['passed'] for x in families),
        'sourceSha256':payload['sha256'],'selectedDefinitionSha256':actual_definition_hashes,
        'candidateModulesImported':False,'actualSqliteConnections':0,'actualDescriptorsOpenedByComponents':0,
        'actualChildProcesses':0,'networkActions':0,'hostAccess':False,'ioAuditGuardInstalled':True}
print(json.dumps(result,sort_keys=True,indent=2))
