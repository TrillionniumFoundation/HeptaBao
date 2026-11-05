#!/usr/bin/env python3
"""Selected-function tests with fake process/FD/clock objects; no candidate main."""
import ast, contextlib, hashlib, json, pathlib, subprocess as std_subprocess, types
source=pathlib.Path(__file__).with_name('probe.py').read_bytes()
tree=ast.parse(source)
names={'Refused','need','sha','safe_error','observe_ps_launch','typed_child'}
selected=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in names]
assert {n.name for n in selected}==names
code=compile(ast.Module(body=selected,type_ignores=[]),'<selected-public-ps-functions>','exec')
checks=[]
def record(name,value):
    assert value,name
    checks.append(name)
def exercise(kind):
    state={'now':0.0,'depth':0,'popen_calls':0,'communicate_calls':0,'stream_closes':0,
           'stream_close_depths':[],'argv':None,'kwargs':None}
    @contextlib.contextmanager
    def critical():
        state['depth']+=1
        try:yield
        finally:state['depth']-=1
    class Stream:
        def close(self):
            state['stream_closes']+=1
            state['stream_close_depths'].append(state['depth'])
            if kind=='stream-close-error':raise OSError(5,'synthetic-close')
    class Process:
        pid=111
        returncode=None
        def __init__(self):
            self.stdout=Stream();self.stderr=Stream()
        def communicate(self,timeout):
            state['communicate_calls']+=1
            assert 0<timeout<=4
            if kind=='timeout':
                raise std_subprocess.TimeoutExpired('fixed-public-command',timeout)
            self.returncode=7 if kind=='nonzero' else 0
            if kind=='late':state['now']=4.01
            if kind=='bad-projection':return b'101 90 100 501 S fixed-birth\n',b''
            if kind=='nonzero':return b'',b'public-diagnostic'
            return b'100 90 100 501 S fixed-birth\n',b''
    def popen(argv,**kwargs):
        state['popen_calls']+=1;state['argv']=argv;state['kwargs']=kwargs
        assert state['depth']>0
        assert kwargs['start_new_session'] is False and kwargs['close_fds'] is True
        assert kwargs['env']=={'LC_ALL':'C'}
        if kind=='permission-1':raise PermissionError(1,'synthetic-secret-message','/synthetic-secret-name')
        if kind=='permission-13':raise PermissionError(13,'synthetic-secret-message','/synthetic-secret-name')
        if kind=='missing':raise FileNotFoundError(2,'synthetic-secret-message')
        if kind=='cancel':raise KeyboardInterrupt()
        return Process()
    fake_os=types.SimpleNamespace(getpid=lambda:100,getppid=lambda:90,getpgrp=lambda:100,
         geteuid=lambda:501,environ={})
    fake_sub=types.SimpleNamespace(Popen=popen,DEVNULL=-3,PIPE=-1,
                                  _USE_POSIX_SPAWN=True,_HAVE_POSIX_SPAWN_CLOSEFROM=False)
    g={'os':fake_os,'subprocess':fake_sub,'time':types.SimpleNamespace(monotonic=lambda:state['now']),
       'critical':critical,'remaining':lambda:45.0-state['now'],'until':45.0,
       'PS_SECONDS':4.0,'COPIED_PS':pathlib.Path('/synthetic-owned/ps'),
       'ps_launches':[],'hashlib':hashlib,'json':json,'PUBLIC_HASH_BOUND':8*1024*1024}
    exec(code,g)
    row=g['observe_ps_launch']('system')
    assert state['popen_calls']==1
    assert state['argv']==['/bin/ps','-p','100','-o','pid=,ppid=,pgid=,uid=,stat=,lstart=']
    assert row['signalsSent']==[] and row['actualSpawnBranchObserved'] is False
    assert state['depth']==0 and all(v>0 for v in state['stream_close_depths'])
    assert 'synthetic-secret' not in json.dumps(row)
    return row,state,g
for k in ('permission-1','permission-13'):
    r,s,_=exercise(k)
    record(k,r['knownObservation'] and not r['executionSucceeded'] and not r['popenReturned']
           and not r['outcomeUnknown'] and r['errorStage']=='popen' and s['stream_closes']==0)
r,s,_=exercise('success')
record('successful-numeric-projection',r['executionSucceeded'] and r['directChildReaped']
       and r['exitCode']==0 and s['stream_closes']==2 and not r['outcomeUnknown'])
r,s,_=exercise('nonzero')
record('known-nonzero-no-success',r['knownObservation'] and not r['executionSucceeded']
       and r['exitCode']==7 and r['directChildReaped'] and not r['outcomeUnknown'])
r,s,_=exercise('bad-projection')
record('wrong-numeric-identity-rejected',r['knownObservation'] and not r['executionSucceeded']
       and r['errorCode']=='numeric_self_projection_identity')
r,s,_=exercise('timeout')
record('timeout-unreaped-unknown-outer-delegation',r['outcomeUnknown']
       and r['cleanupDelegatedToOuterRetainedGroup'] and not r['directChildReaped']
       and s['stream_closes']==2 and r['signalsSent']==[])
r,s,_=exercise('stream-close-error')
record('stream-close-error-unknown-no-retry',r['outcomeUnknown'] and not r['streamsClosed']
       and s['stream_closes']==2 and len(r['streamCloseErrors'])==2)
r,s,_=exercise('late')
record('same-four-second-deadline-not-reset',not r['knownObservation']
       and not r['completedBeforeOriginalPsDeadline'] and r['directChildReaped'])
r,s,_=exercise('missing')
record('nonpermission-launch-error-not-admitted',not r['knownObservation']
       and r['errorType']=='FileNotFoundError' and r['errorErrno']==2)
r,s,_=exercise('cancel')
record('cancel-before-popen-return-unknown',r['outcomeUnknown'] and not r['popenReturned'])
row,state,g=exercise('success')
base={'schema':'heptabao.mac-ps-sandbox-child.r1','variant':'system','sourceSha256':'a'*64,
      'ok':True,'outcomeUnknown':False,'boundedPublicPinReadBytesThisProcess':0,
      'allOwnedDescriptorsClosed':True,'originalDeadlineMetAfterClosure':True,
      'originalAbsoluteDeadlineMonotonic':45.0,
      'ownedCommands':{'commands':[],'allOwnedCommandsStopped':True,'unknownCommandCount':0},
      'devNullRead':{'opened':True,'descriptorClosed':True,'readReturnedEof':True,
                     'expectedReadRefused':False},'psLaunches':[row]}
for key in ('productionReadAttempted','productionWriteAttempted','sqliteImported','consumerStarted',
            'providerRequested','j3160Contacted','sandboxDiskutilStarted'):base[key]=False
record('typed-success-report',g['typed_child'](json.dumps(base).encode(),'system','a'*64)['ok'] is True)
bad=json.loads(json.dumps(base));bad['psLaunches'][0]['exitCode']=False
try:g['typed_child'](json.dumps(bad).encode(),'system','a'*64)
except g['Refused']:record('bool-exitcode-not-zero',True)
else:raise AssertionError('bool accepted')
bad=json.loads(json.dumps(base));bad['psLaunches'][0]['executionSucceeded']='true'
try:g['typed_child'](json.dumps(bad).encode(),'system','a'*64)
except g['Refused']:record('nonbool-success-rejected',True)
else:raise AssertionError('string accepted')
print(json.dumps({'schema':'heptabao.public-ps-probe-selected-fake-components.r1',
      'source_sha256':hashlib.sha256(source).hexdigest(),'checks':checks,'passed':len(checks),
      'real_processes':0,'real_descriptors':0,'network_operations':0,'candidate_main_executed':False,
      'selected_definitions':sorted(names)},sort_keys=True)+'\n',end='')

