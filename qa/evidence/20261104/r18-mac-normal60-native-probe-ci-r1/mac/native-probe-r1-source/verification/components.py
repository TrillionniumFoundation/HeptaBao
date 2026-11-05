#!/usr/bin/env python3
"""Selected actual definitions with fake native APIs/processes only."""
import ast, ctypes, errno, hashlib, json, signal, types
from pathlib import Path
BASE=Path(__file__).parent
raw=(BASE/'mac_darwin_owned_projection_r1.py').read_bytes()
tree=ast.parse(raw)
class Clock:
    def __init__(self):self.now=100.0
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=max(seconds,0.001)
clock=Clock()
fakeos=types.SimpleNamespace(getpid=lambda:22,getppid=lambda:10,getpgrp=lambda:22,geteuid=lambda:501)
ns={'ctypes':ctypes,'errno':errno,'os':fakeos,'re':__import__('re'),
    'sys':types.SimpleNamespace(platform='darwin',byteorder='little'),'time':clock}
selected=[n for n in tree.body if isinstance(n,(ast.Assign,ast.ClassDef,ast.FunctionDef))]
exec(compile(ast.Module(body=selected,type_ignores=[]),'<selected-native-projection>','exec'),ns)
API=ns['NativeProjection'];Info=ns['ProcBSDInfo'];Refused=ns['NativeProjectionRefused']
checks=[]
def check(name,fn):
    fn();checks.append(name)
def refuse(fn,code=None):
    try:fn()
    except Refused as e:
        if code is not None:assert e.code==code,(e.code,code)
    else:raise AssertionError('expected refusal')
def fresh():
    clock.now=100.0
    a=object.__new__(API);a.calls=a.pid_calls=a.group_calls=0
    a.last_call=None;a.self_qualified=False;a.identity=None;a.layout=ns['abi_layout']()
    a.info_ids=[];a.list_ids=[];a.states={22:(10,22,501,2,1700000000,123456),44:(22,44,501,2,1700000001,654321)}
    def info(pid,flavor,arg,pointer,size):
        a.info_ids.append((pid,flavor,arg,size))
        assert flavor==3 and arg==1 and size==136
        x=ctypes.cast(pointer,ctypes.POINTER(Info)).contents
        ppid,pgid,uid,state,sec,usec=a.states[pid]
        x.pbi_pid=pid;x.pbi_ppid=ppid;x.pbi_pgid=pgid;x.pbi_uid=uid
        x.pbi_status=state;x.pbi_start_tvsec=sec;x.pbi_start_tvusec=usec
        return 136
    def listing(kind,pgid,pointer,size):
        a.list_ids.append((kind,pgid,size))
        assert kind==2 and pointer is not None and size==260
        ids=[pid for pid,row in a.states.items() if row[1]==pgid]
        out=ctypes.cast(pointer,ctypes.POINTER(ctypes.c_int32))
        for i,pid in enumerate(ids):out[i]=pid
        return len(ids)*4
    a._info=info;a._list=listing
    return a
def abi():
    v=ns['abi_layout']()
    assert v['sizes']['proc_bsdinfo']==136 and len(v['offsets'])==22 and v['offsets']['pbi_start_tvusec']==128
check('reference-layout-136-and-22-offsets',abi)
def live():
    a=fresh();r=a.pid_row(44,until=110)
    assert r=={'pid':44,'ppid':22,'pgid':44,'uid':501,'stateCode':2,'stateName':'SRUN','isZombie':False,
               'birthSeconds':'1700000001','birthMicroseconds':'654321'}
    assert a.info_ids==[(44,3,1,136)]
check('exact-live-numeric-row-and-zombie-arg',live)
def zombie():
    a=fresh();a.states[44]=(22,44,501,5,1700000001,654321)
    assert a.pid_row(44,until=110)['isZombie']
check('retained-zombie-numeric-row',zombie)
def short():
    a=fresh();a._info=lambda *args:135
    refuse(lambda:a.pid_row(44,until=110),'native_pid_info_not_complete')
check('short-struct-rejected',short)
def noinfoerr():
    a=fresh()
    def bad(*args):ctypes.set_errno(errno.EPERM);return 0
    a._info=bad
    refuse(lambda:a.pid_row(44,until=110),'native_pid_info_not_complete')
    assert a.last_call['errno']==errno.EPERM
check('zero-error-is-not-process-absence',noinfoerr)
def noinfoesrch():
    a=fresh()
    def bad(*args):ctypes.set_errno(errno.ESRCH);return 0
    a._info=bad;refuse(lambda:a.pid_row(44,until=110))
check('retained-child-esrch-rejected',noinfoesrch)
def empty():
    a=fresh();assert a.group_rows(55,until=110)==[]
    assert a.list_ids==[(2,55,260),(2,55,260)]
check('empty-group-requires-two-scoped-errno-zero-calls',empty)
def grouperror():
    a=fresh()
    def bad(*args):ctypes.set_errno(errno.EPERM);return 0
    a._list=bad;refuse(lambda:a.group_rows(44,until=110))
check('group-zero-with-errno-rejected',grouperror)
for n,label in [(260,'full-buffer'),(5,'misaligned-byte-count'),(-1,'negative-return')]:
    def case(n=n):
        a=fresh();a._list=lambda *args:n
        refuse(lambda:a.group_rows(44,until=110))
        assert a.calls==1
    check(label+'-rejected-without-resize-or-retry',case)
def duplicate():
    a=fresh()
    def bad(kind,pgid,ptr,size):
        out=ctypes.cast(ptr,ctypes.POINTER(ctypes.c_int32));out[0]=out[1]=44;return 8
    a._list=bad;refuse(lambda:a.group_rows(44,until=110),'native_group_pid_shape')
check('duplicate-group-pids-rejected',duplicate)
def wrongpid():
    a=fresh();base=a._info
    def bad(*args):
        n=base(*args);ctypes.cast(args[3],ctypes.POINTER(Info)).contents.pbi_pid=45;return n
    a._info=bad;refuse(lambda:a.pid_row(44,until=110),'native_pid_identity_mismatch')
check('wrong-returned-pid-rejected',wrongpid)
for state,usec,label in [(6,1,'unsupported-state'),(2,1000000,'invalid-birth-usec')]:
    def case(state=state,usec=usec):
        a=fresh();a.states[44]=(22,44,501,state,1700000001,usec)
        refuse(lambda:a.pid_row(44,until=110))
    check(label+'-rejected',case)
def drift():
    a=fresh();base=a._list;calls=[0]
    def changing(*args):
        calls[0]+=1
        if calls[0]==2:return 0
        return base(*args)
    a._list=changing;refuse(lambda:a.group_rows(44,until=110),'native_group_members_changed')
check('two-group-membership-observations-must-agree',drift)
def uid():
    a=fresh();a.states[44]=(22,44,502,2,1700000001,654321)
    refuse(lambda:a.group_rows(44,until=110),'native_group_scope_or_uid_changed')
check('group-foreign-uid-rejected',uid)
def late():
    a=fresh();base=a._info
    def delayed(*args):n=base(*args);clock.now+=4.1;return n
    a._info=delayed;refuse(lambda:a.pid_row(44,until=110),'original_projection_deadline_expired')
check('late-native-return-four-second-gate',late)
def clipped():
    a=fresh();base=a._info
    def delayed(*args):n=base(*args);clock.now+=0.6;return n
    a._info=delayed;refuse(lambda:a.pid_row(44,until=100.5),'original_projection_deadline_expired')
check('native-call-clipped-to-original-shared-deadline',clipped)
def selfok():
    a=fresh();v=a.qualify_self(until=110)
    assert a.self_qualified and v['pidUidPpidPgidMatchedIndependentOsApis']
    assert all(x[0]==22 for x in a.info_ids) and all(x[1]==22 for x in a.list_ids)
check('own-pid-ppid-pgid-uid-and-birth-crosscheck',selfok)
def selfdrift():
    a=fresh();base=a._info;calls=[0]
    def changed(*args):
        calls[0]+=1
        if calls[0]==3:a.states[22]=(10,22,501,2,1700000000,123457)
        return base(*args)
    a._info=changed;refuse(lambda:a.qualify_self(until=110),'native_self_birth_stable')
check('own-birth-drift-rejected',selfdrift)

custody_raw=(BASE/'mac_native_owned_unreaped_r1.py').read_bytes()
ct=ast.parse(custody_raw)
cn={'os':None,'signal':signal,'time':clock,'NativeProjection':API,
    'NativeProjectionRefused':Refused,'PROJECTION_SCHEMA':ns['PROJECTION_SCHEMA']}
exec(compile(ast.Module(body=[n for n in ct.body if isinstance(n,(ast.Assign,ast.ClassDef,ast.FunctionDef))],
                        type_ignores=[]),'<selected-native-custody>','exec'),cn)
class Child:
    pid=44
    def __init__(self):self.returncode=None;self.reaped=False
    def wait(self,timeout):
        assert timeout>0 and sim['event'] is not None and not sim['live']
        sim['log'].append('first-wait');self.reaped=True
        self.returncode=sim['event'].si_status if sim['event'].si_code==1 else -sim['event'].si_status
        return self.returncode
def custody_case(mode):
    global sim
    clock.now=100.0
    child=Child();sim={'live':mode!='natural','event':None,'log':[],'signals':[],'post':False}
    def event(status=0,code=1):
        return types.SimpleNamespace(si_pid=44,si_signo=signal.SIGCHLD,si_code=code,si_status=status)
    if mode=='natural':sim['event']=event()
    def waitid(which,pid,options):
        assert child.returncode is None and options==7
        sim['log'].append('wnowait');return sim['event']
    def killpg(pid,sig):
        assert child.returncode is None and pid==44
        sim['signals'].append(sig);sim['log'].append('signal')
        if sig==signal.SIGKILL or mode!='kill':
            sim['live']=False;sim['event']=event(sig,2)
    fake=types.SimpleNamespace(P_PID=1,WEXITED=1,WNOHANG=2,WNOWAIT=4,
        CLD_EXITED=1,CLD_KILLED=2,CLD_DUMPED=3,waitid=waitid,
        getpid=lambda:22,geteuid=lambda:501,getpgid=lambda pid:44,getsid=lambda pid:44,killpg=killpg)
    cn['os']=fake
    class Projection:
        self_qualified=True
        def pid_row(self,pid,until):
            assert pid==44 and clock.now<until
            sim['log'].append('pid-projection')
            birth='999' if mode=='identity-mismatch' and len(sim['log'])>5 else '1700000001'
            return {'pid':44,'ppid':22,'pgid':44,'uid':501,
                    'birthSeconds':birth,'birthMicroseconds':'654321',
                    'isZombie':not sim['live'],'stateCode':2 if sim['live'] else 5}
        def group_rows(self,pgid,until):
            assert pgid==44 and clock.now<until
            sim['log'].append('group-projection')
            if child.reaped:
                if mode=='post-reap-survivor':
                    return [{'pid':45,'ppid':22,'pgid':44,'uid':501,
                             'birthSeconds':'1700000002','birthMicroseconds':'1','isZombie':False,'stateCode':2}]
                return []
            return [self.pid_row(44,until)]
    cn['_projection']=Projection()
    if mode=='already-reaped':
        child.returncode=0;owner=None
    else:owner=cn['capture_child'](child,until=110)
    result=cn['stop_once_unreaped'](child,owner)
    if mode in ('natural','term','kill'):
        assert result['ok'] and not result['outcomeUnknown'] and result['directChildReaped']
        assert result['allGroupRowsEmptyAfterReap'] and not result['postReapSignalSent']
        expected=[] if mode=='natural' else ([signal.SIGTERM] if mode=='term' else [signal.SIGTERM,signal.SIGKILL])
        assert sim['signals']==expected
        assert sim['log'].count('first-wait')==1
    else:
        assert not result['ok'] and result['outcomeUnknown']
        if mode!='post-reap-survivor':assert sim['signals']==[]
    for i,item in enumerate(sim['log']):
        if item=='signal':
            prior=sim['log'][:i]
            assert prior.count('pid-projection')>=2 and 'group-projection' in prior
            assert 'first-wait' not in prior
    return result
for mode in ('natural','term','kill','post-reap-survivor','identity-mismatch','already-reaped'):
    check('actual-native-adapter-'+mode,lambda mode=mode:custody_case(mode))
print(json.dumps({'schema':'heptabao.darwin-native-projection-selected-components.r1',
    'passed':len(checks),'checks':checks,'projection_source_sha256':hashlib.sha256(raw).hexdigest(),
    'custody_source_sha256':hashlib.sha256(custody_raw).hexdigest(),
    'candidate_main_executed':False,'native_libraries_loaded':0,'actual_native_api_calls':0,
    'real_processes':0,'real_descriptors':0,'network_operations':0,
    'local_ctypes_struct_layout_only':True},sort_keys=True))
