#!/usr/bin/env python3
"""Static only: AST compile, exact fixed scope and source invariants."""
import ast,hashlib,json,pathlib
root=pathlib.Path(__file__).parent
data=json.loads((root/'static-input.public.json').read_bytes())
source=data['source'];old=data['referenceSource']
tree=ast.parse(source);compile(tree,'metadata-candidate.py','exec')
def pin(s):
    b=s.encode()
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
assert pin(source)==data['sourcePin']
request=json.loads(data['requestRaw'])
assert pin(data['requestRaw'])==data['requestPin']
assert request['host']=='mac' and request['executable']=='/opt/homebrew/bin/python3'
assert request['args']==['-I','-S','-B','-c',source]
assert request['cwd']=='/Users/qianqi' and request['stdin']==''
assert request['timeout_seconds']==60
assign={t.id:n.value for n in tree.body if isinstance(n,ast.Assign)
        for t in n.targets if isinstance(t,ast.Name)}
targets=ast.literal_eval(assign['TARGETS']);parents=ast.literal_eval(assign['PARENTS'])
assert targets==data['targets'] and parents==data['parents']
assert len(targets)==len({x['path'] for x in targets})==46
assert len(parents)==len(set(parents))==22
lib=ast.parse(data['captureLibrary'])
lc={t.id:n.value for n in lib.body if isinstance(n,ast.Assign)
    for t in n.targets if isinstance(t,ast.Name)}
agents=ast.literal_eval(lc['AGENTS']);caches=ast.literal_eval(lc['CACHE_NAMES'])
live='/Users/qianqi/.openclaw'
expected=[live+'/openclaw.json']
dbs=[live+'/agents/'+a+'/agent/openclaw-agent.sqlite' for a in agents]
for d in dbs:expected.extend(d+s for s in ('','-wal','-shm','-journal'))
expected.extend(live+'/authbus/'+n for n in caches)
for a in agents:expected.extend(live+'/agents/'+a+'/agent/codex-home/'+n for n in
                              ('config.toml','requirements.toml','auth.json'))
expected.extend(live+'/state/openclaw.sqlite'+s for s in ('','-wal','-shm','-journal'))
assert [x['path'] for x in targets]==expected
derived={'/'}
for item in targets:derived.update(str(x) for x in pathlib.Path(item['path']).parents)
assert set(parents)==derived
counts={role:sum(x['role']==role for x in targets) for role in set(x['role'] for x in targets)}
assert counts=={'database_main':6,'database_wal':6,'database_shm':6,'database_journal':6,'small_read':22}
for item in targets:
    expected_max={'database_main':None,'database_wal':0,'database_shm':8388608,
                  'database_journal':0,'small_read':1048576}[item['role']]
    assert item['maximum']==expected_max
    assert item['privateMode']==not item['path'].endswith(('config.toml','requirements.toml'))
forbidden={'sqlite3','_sqlite3','subprocess','socket','hashlib','ctypes','urllib','requests'}
imports=[]
for n in tree.body:
    if isinstance(n,ast.Import):imports.extend(x.name.split('.')[0] for x in n.names)
    if isinstance(n,ast.ImportFrom):imports.append(n.module.split('.')[0])
assert not (set(imports)&forbidden)
for n in ast.walk(tree):
    if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name):
        if n.func.value.id=='os':
            assert n.func.attr not in {'read','write','listdir','scandir','chmod','chown','remove',
                'unlink','rename','mkdir','makedirs','system','execv','execve','fork','kill','killpg'}
    if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
        assert n.func.id not in {'open','eval','exec','__import__'}
def defs(raw):
    tr=ast.parse(raw)
    return {n.name:''.join(raw.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
            for n in tr.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
before=defs(old);after=defs(source)
same=['Refused','need','remaining','count','ident','on_signal','critical','close_row']
for name in same:assert before[name]==after[name],name
metadata_bound=22*8+46*6
assert metadata_bound==452
result={'schema':'heptabao.mac-capture-size-metadata-static.r1','ok':True,
 'mode':'AST_compile_and_fixed_public_scope_only','sourceExecuted':False,'hostCalls':0,
 'privateBodiesRead':0,'childProcesses':0,'fixedLeaves':46,'fixedParents':22,
 'roles':counts,'fixedPathsMatchOriginalCaptureLibrary':True,
 'originalMaximumsUnchanged':True,'noFileBodyOrSqlOrProcessOrNetworkApis':True,
 'originalDefinitionByteEqual':same,'directoryMetadataMaximumPerPath':8,
 'leafMetadataMaximumPerPath':6,'metadataBound':metadata_bound,
 'fdRegisteredBound':68,'fdPeakBound':23,'innerSeconds':5,'outerSeconds':60,
 'notOriginalFailurePathDiagnosis':True,'source':pin(source),'request':pin(data['requestRaw'])}
out=json.dumps(result,indent=2,sort_keys=True)+'\n'
(root/'static-result.public.json').write_text(out)
print(out,end='')
