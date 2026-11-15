#!/usr/bin/env python3
"""Four new synthetic Node starts; no existing seed, SDK, or credentials run."""
import ast, hashlib, json, os, stat, subprocess, sys, time, types
from pathlib import Path

OLD = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1')
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-sandbox-probe-20261106-r1')
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
CALLER_HOME = '/Users/qianqi'
PINS = {
 'mac_owned_unreaped_r1.py': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
 'mac_owned_commands_r1.py': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
 'main3_sdk_phase.py': 'b7ba622cd8937afbb1e3542f5d4910fe9eaf62f7d3cd95d73926d24c94fdde30',
}
FIXED = {
 NODE: 'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
 '/usr/bin/sandbox-exec': 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a',
}
ENV = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
started = time.monotonic()
outer_until = started + 60
opened = closed = 0
commands = None
result = {'schema': 'heptabao.mac-main3-sdk-synthetic-sandbox-factor.r1',
 'originalFailedJobId': '1a1b23ee0d9-fc05-7d25', 'originalFailedChildPid': 38400,
 'newSyntheticRoot': str(ROOT), 'privateCredentialFilesRead': False,
 'actualSdkOrPluginImported': False, 'oldFailedSeedReexecuted': False,
 'providerCalled': False, 'serviceAction': False, 'productionChanged': False,
 'originalFailureCauseEstablished': False, 'originalCampaignCwdRecorded': False,
 'originalChildSeconds': 10, 'outerSeconds': 60, 'automaticRetry': False,
 'ok': False, 'cases': []}

def need(value, code):
    if not value: raise RuntimeError(code)

def identity(s):
    return tuple(str(getattr(s, k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def read(path, maximum=2*1024*1024, pin=None):
    global opened, closed
    need(time.monotonic() < outer_until, 'original_outer_deadline')
    path=Path(path); before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,
         'bounded_regular_nonsymlink_file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC); opened+=1
    try:
        need(identity(before)==identity(os.fstat(fd)), 'named_open_file_identity')
        raw=bytearray()
        while True:
            need(time.monotonic() < outer_until, 'original_outer_deadline')
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part);need(len(raw)<=maximum,'file_bound')
        need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'file_namespace_unchanged')
        if pin:need(hashlib.sha256(raw).hexdigest()==pin,'exact_public_source_pin')
        return bytes(raw)
    finally:os.close(fd);closed+=1

def create(path, raw):
    global opened, closed
    path=Path(path);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);opened+=1
    try:
        view=memoryview(raw)
        while view:
            need(time.monotonic()<outer_until,'original_outer_deadline')
            n=os.write(fd,view);need(n>0,'write_progress');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd);closed+=1
    need(read(path)==raw,'create_only_readback')

PROBE = r'''import fs from 'node:fs';
import net from 'node:net';
const ROOT = __ROOT__;
const result={schema:'heptabao.synthetic-node-sandbox-probe.r1',entryReached:true,ok:false,
 privateCredentialFilesRead:false,providerCalled:false,openProbeFds:0,closedProbeFds:0,network:[]};
const safe=e=>['EPERM','EACCES','ECONNREFUSED','ENOENT','ENOTDIR'].includes(e?.code)?e.code:'UNPROJECTED';
function denied(path,flag){let fd;try{fd=fs.openSync(path,flag);result.openProbeFds++;return {denied:false,code:null};}
 catch(e){return {denied:['EPERM','EACCES'].includes(e?.code),code:safe(e)};}
 finally{if(fd!==undefined){fs.closeSync(fd);result.closedProbeFds++;}}}
async function network(host){return await new Promise(resolve=>{let socket,settled=false,error=null,connected=false,timedOut=false;
 const done=()=>{if(settled)return;settled=true;clearTimeout(timer);resolve({denied:['EPERM','EACCES'].includes(error),code:error,connected,timedOut,socketClosed:true});};
 const timer=setTimeout(()=>{timedOut=true;if(socket)socket.destroy();},1000);
 try{socket=net.createConnection({host,port:9});socket.once('connect',()=>{connected=true;socket.destroy();});
 socket.once('error',e=>{error=safe(e);socket.destroy();});socket.once('close',done);}
 catch(e){clearTimeout(timer);settled=true;resolve({denied:['EPERM','EACCES'].includes(e?.code),code:safe(e),connected:false,timedOut:false,socketClosed:true,constructorThrew:true});}
 });}
try{
 result.syntheticRead=denied(ROOT+'/protected-read',fs.constants.O_RDONLY);
 result.syntheticWrite=denied(ROOT+'/protected-write',fs.constants.O_WRONLY);
 try{const cwd=process.cwd();result.cwdReadable=true;result.cwdIsOwnedQa=cwd===ROOT+'/qa';}
 catch(e){result.cwdReadable=false;result.cwdErrorCode=safe(e);}
 result.homeEnvIsKnown=process.env.HOME==='/Users/qianqi';
 result.tmpEnvIsOwned=process.env.TMPDIR===ROOT+'/tmp';
 result.network.push(await network('127.0.0.1'));
 result.network.push(await network('192.0.2.1'));
 result.ok=result.syntheticRead.denied&&result.syntheticWrite.denied&&result.network.every(r=>r.denied&&r.socketClosed&&!r.connected&&!r.timedOut)&&result.openProbeFds===result.closedProbeFds;
}catch(e){result.errorType=String(e?.name??'Error');result.errorCode=safe(e);}
process.stdout.write(JSON.stringify(result)+'\n');process.exitCode=result.ok?0:1;
'''

try:
    need(os.getuid()==os.geteuid()==501,'exact_caller_uid')
    os.umask(0o077)
    inherited_cwd=os.getcwd()
    result['inheritedCwdEqualsKnownHome']=inherited_cwd==CALLER_HOME
    result['inheritedCwdIsExistingOwnedRoot']=inherited_cwd==str(OLD)
    sources={name:read(OLD/'qa'/name,pin=pin) for name,pin in PINS.items()}
    for path,pin in FIXED.items():read(path,pin=pin)
    tree=ast.parse(sources['main3_sdk_phase.py'])
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
    need(len(nodes)==1,'one_source_bound_sandbox_function')
    def profile(root):
        ns={'ROOT':root,'STATE':root/'state','json':json,'need':need}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-sandbox-function>','exec'),ns)
        return ns['sandbox_profile'](seed=True)
    need(read(OLD/'initial/seed.sb',65536)==profile(OLD),'original_actual_profile_matches_frozen_source')
    for name in ('mac_owned_unreaped_r1','mac_owned_commands_r1'):
        module=types.ModuleType(name);module.__file__=str(OLD/'qa'/(name+'.py'))
        sys.modules[name]=module
        exec(compile(sources[name+'.py'],module.__file__,'exec'),module.__dict__)
    owned=sys.modules['mac_owned_commands_r1']
    signals=owned.Signals();signals.install();commands=owned.Commands(signals)
    os.mkdir(ROOT,0o700)
    for name in ('qa','input','private','plugin','initial','tmp'):os.mkdir(ROOT/name,0o700)
    create(ROOT/'protected-read',b'owned synthetic protected read probe\n')
    create(ROOT/'protected-write',b'owned synthetic protected write probe\n')
    entry=ROOT/'qa/probe.mjs'
    create(entry,PROBE.replace('__ROOT__',json.dumps(str(ROOT))).encode())
    baseline=profile(ROOT)
    extra_dirs={Path(inherited_cwd),*Path(inherited_cwd).parents,*entry.parents,
                *(ROOT/'input/plan.synthetic.json').parents}
    extra_lines=''.join('(allow file-read* (literal '+json.dumps(str(p))+'))\n' for p in sorted(extra_dirs,key=str))
    variants=[('baseline',baseline,None,ENV),
              ('directory-literals-only',baseline+extra_lines.encode(),None,ENV),
              ('owned-cwd-only',baseline,str(ROOT/'qa'),ENV),
              ('home-tmp-env-only',baseline,None,{**ENV,'HOME':CALLER_HOME,'TMPDIR':str(ROOT/'tmp')})]
    plan={'schema':result['schema'],'sourcePins':PINS,'fixedRuntimePins':FIXED,
          'originalFailedJobId':result['originalFailedJobId'],'syntheticRoot':str(ROOT),
          'originalChildSeconds':10,'outerSeconds':60,'cases':[x[0] for x in variants],
          'ancestorPermissionType':'file-read* literal directories only','addedDirectoryCount':len(extra_dirs),
          'oldCredentialRootsNeverAddedToNewSandbox':True,'originalCampaignCwdRecorded':False}
    create(ROOT/'plan.public.json',(json.dumps(plan,sort_keys=True,separators=(',',':'))+'\n').encode())
    for label,sb,cwd,env in variants:
        need(outer_until-time.monotonic()>20,'room_for_original_child_and_cleanup')
        sb_path=ROOT/'initial'/(label+'.sb');create(sb_path,sb)
        argv=['/usr/bin/sandbox-exec','-f',str(sb_path),NODE,'--no-warnings',str(entry)]
        real_subprocess=owned.subprocess
        def launch(args,**kw):
            need(args==argv and kw.get('env')==ENV and 'cwd' not in kw,
                 'exact_original_command_launch_contract')
            kw['env']=dict(env)
            if cwd is not None:kw['cwd']=cwd
            return real_subprocess.Popen(args,**kw)
        owned.subprocess=types.SimpleNamespace(Popen=launch,PIPE=real_subprocess.PIPE,DEVNULL=real_subprocess.DEVNULL)
        try:
            row,out,err=commands.run(label,argv,until=min(outer_until-10,time.monotonic()+10),maximum=16384)
        finally:owned.subprocess=real_subprocess
        row.pop('stdoutSha256',None);row.pop('stderrSha256',None)
        row['diagnosticStreamDigestsWithheld']=True
        case={'name':label,'profileSha256':hashlib.sha256(sb).hexdigest(),'command':row,
              'newNodeResult':None,'rawUnexpectedDiagnosticPublished':False}
        create(ROOT/'private'/(label+'.stdout.private'),out)
        create(ROOT/'private'/(label+'.stderr.private'),err)
        if out:
            value=json.loads(out)
            need(isinstance(value,dict) and value.get('schema')=='heptabao.synthetic-node-sandbox-probe.r1',
                 'exact_synthetic_node_result')
            case['newNodeResult']=value
        result['cases'].append(case)
        need(not row['outcomeUnknown'] and row['streamsClosed'] and row['cleanup'].get('ok') is True,
             'original_child_custody_known_before_next_probe')
        need(read(ROOT/'protected-read')==b'owned synthetic protected read probe\n' and
             read(ROOT/'protected-write')==b'owned synthetic protected write probe\n','synthetic_protected_files_unchanged')
        need(time.monotonic()<outer_until,'original_outer_deadline')
    for path,pin in FIXED.items():read(path,pin=pin)
    for name,pin in PINS.items():read(OLD/'qa'/name,pin=pin)
    result['allOriginalSourcePinsUnchanged']=True
    result['allFourOriginalProbeOutcomesKnown']=len(result['cases'])==4 and all(not c['command']['outcomeUnknown'] for c in result['cases'])
    result['ok']=result['allFourOriginalProbeOutcomesKnown']
except BaseException as error:
    result['errorType']=type(error).__name__
    result['errorCode']=str(error) if type(error) is RuntimeError else None
finally:
    result['commands']=commands.public() if commands else None
    result['openedParentDescriptors']=opened;result['closedParentDescriptors']=closed
    result['allParentDescriptorsClosed']=opened==closed
    result['elapsedSeconds']=time.monotonic()-started
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if result['ok'] and opened==closed else 1)
