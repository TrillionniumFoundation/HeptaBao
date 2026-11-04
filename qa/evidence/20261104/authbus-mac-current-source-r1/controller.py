#!/usr/bin/env python3
"""Run two unchanged real-credential drivers against one pinned normal build."""
from __future__ import annotations
import hashlib,json,os,signal,stat,subprocess,sys,time,traceback
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SCRIPTS=ROOT/'scripts'
SOURCE=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-root-pull-response-r1/source')
BUILD=SOURCE.parent/'build-normal-r1'
BINARY=BUILD/'artifacts/heptabao-server'
LIVE=Path('/Users/qianqi/.openclaw')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
NODE='/opt/homebrew/bin/node'
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python'
NATIVE=Path('/Users/qianqi/.codex/auth.json')
PROOFROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-native-profile2-8d-20261104-a2/native-validation-r1')
PRIOR=Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1/live-r4')
COMMIT='33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE='cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
CONFIGSHA='ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d'
BINSHA='d8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20'

class Refused(Exception): pass
def need(ok,code):
    if not ok: raise Refused(code)
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):h.update(block)
    return h.hexdigest()
def put(path,value):
    raw=value if isinstance(value,bytes) else json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def source_identity():
    def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(SOURCE),*args],text=True,timeout=10).strip()
    value={'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),
           'trackedClean':subprocess.run(['/usr/bin/git','-C',str(SOURCE),'diff','--quiet'],timeout=10).returncode==0
               and subprocess.run(['/usr/bin/git','-C',str(SOURCE),'diff','--cached','--quiet'],timeout=10).returncode==0}
    need(value=={'commit':COMMIT,'tree':TREE,'trackedClean':True},'normal_source_identity_changed')
    return value
def relay_pids():
    import re
    values={}
    for name in ('bridge','egressguard','proxy','front'):
        out=subprocess.run(['/bin/launchctl','print','gui/'+str(os.geteuid())+'/ai.openclaw.authbus-relay.'+name],capture_output=True,timeout=5)
        m=re.search(rb'^\s*pid = (\d+)\s*$',out.stdout,re.M)
        values[name]=int(m[1]) if m else None
    return values
def remaining_owned():
    import shlex
    found=[]
    configs={str(ROOT/name/'server/server.json') for name in ('current-auth-rows-r1','native-profile2-selector-r1')}
    out=subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True,timeout=10)
    for line in out.splitlines():
        cols=line.strip().split(None,1)
        if len(cols)!=2:continue
        try:argv=shlex.split(cols[1])
        except ValueError:continue
        if len(argv)==3 and argv[0]==str(BINARY) and argv[1]=='--config' and argv[2] in configs:
            found.append({'pid':int(cols[0]),'config':argv[2]})
    return found
def run_phase(name,argv,env,timeout=420):
    put(ROOT/(name+'.intent.public.json'),{'argv':argv,'timeoutSeconds':timeout,'providerRequestsAllowed':0,'productionWritesAllowed':False})
    child=subprocess.Popen(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    timedout=False
    try:stdout,stderr=child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timedout=True
        need(os.getpgid(child.pid)==child.pid,'owned_child_group_changed')
        os.killpg(child.pid,signal.SIGKILL)
        stdout,stderr=child.communicate(timeout=10)
    put(ROOT/(name+'.stdout.private'),stdout);put(ROOT/(name+'.stderr.private'),stderr)
    return {'phase':name,'pid':child.pid,'returnCode':child.returncode,'timedOut':timedout,
            'stdoutSha256':hashlib.sha256(stdout).hexdigest(),'stderrSha256':hashlib.sha256(stderr).hexdigest()}

def main():
    os.umask(0o077)
    report={'schema':'heptabao.normal33-current-auth-source-chain.v1','ok':False,'checks':[],'phases':[],
        'providerCalled':False,'providerRefreshAttempted':False,'newLoginAttempted':False,'modelCalled':False,
        'j3160Contacted':False,'productionChanged':False,'productionTrafficCutover':False,'credentialValuesPublished':False,
        'productionGatewaySelectionQualified':False,'completeOpenClawDatabaseRecoveryQualified':False,'fullReplacementQualified':False}
    def check(name,value,**detail):
        report['checks'].append({'case':name,'passed':bool(value),**detail});need(value,name)
    before={}
    try:
        info=ROOT.lstat()
        check('owned_private_control_root',stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700 and not ROOT.is_symlink())
        freeze=json.loads((ROOT/'stage.public.json').read_bytes())
        before={p:sha(p) for p in freeze['pins']}
        check('all_frozen_inputs_exact',before==freeze['pins'])
        report['sourceBefore']=source_identity()
        report['relayPidsBefore']=relay_pids()
        report['sourcePins']=before
        receipt=json.loads((BUILD/'result.public.json').read_bytes())
        check('normal33_build_receipt',receipt.get('source_commit')==COMMIT and receipt.get('source_tree')==TREE
              and receipt.get('normal_default_candidate') is True and receipt.get('source_freeze_verified') is True
              and receipt.get('build_exit_code')==0 and receipt['artifacts']['heptabao-server']['sha256']==BINSHA)
        check('normal_binary_exact',sha(BINARY)==BINSHA)
        check('no_prior_owned_server',not remaining_owned())
        env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/qianqi',
             'TMPDIR':str(ROOT/'tmp'),'PYTHONDONTWRITEBYTECODE':'1'}
        current=ROOT/'current-auth-rows-r1'
        argv=[PYTHON,'-I','-B',str(SCRIPTS/'authbus_current_credential_stage.py'),
            '--work-dir',str(current),'--source',str(LIVE),'--sdk',str(SDK),'--binary',str(BINARY),
            '--server-source',str(SOURCE),'--sdk-reader',str(SCRIPTS/'current_sdk_read.mjs'),
            '--client-reader',str(SCRIPTS/'current_stage_read.mjs'),'--client-modules',str(ROOT/'transport'),
            '--binary-sha256',BINSHA,'--config-sha256',CONFIGSHA,'--node',NODE]
        phase=run_phase('current-auth-rows',argv,env);report['phases'].append(phase)
        result=json.loads((current/'result.public.json').read_bytes())
        phase['receiptSha256']=sha(current/'result.public.json');phase['checks']=len(result.get('checks',[]))
        check('current_auth_rows_driver',phase['returnCode']==0 and not phase['timedOut'] and result.get('ok') is True)
        check('current_auth_rows_server_stopped',not remaining_owned())
        custody=run_phase('current-auth-rows-custody',[PYTHON,'-I','-B',str(SCRIPTS/'authbus_current_stage_custody.py'),str(current)],env,30)
        report['phases'].append(custody)
        receipt2=json.loads((current/'custody.public.json').read_bytes());custody['receiptSha256']=sha(current/'custody.public.json')
        check('current_auth_rows_custody',custody['returnCode']==0 and receipt2.get('ok') is True)
        selector=ROOT/'native-profile2-selector-r1'
        argv=[PYTHON,'-I','-B',str(SCRIPTS/'authbus_profile2_selector_live.py'),
            '--work-dir',str(selector),'--source',str(SOURCE),'--binary',str(BINARY),'--build-result',str(BUILD/'result.public.json'),
            '--native-source',str(NATIVE),'--native-proof',str(PROOFROOT/'result.public.json'),
            '--native-capture',str(PROOFROOT/'native-auth-current.private.json'),'--live-state',str(LIVE),'--sdk',str(SDK),
            '--live-plugin',str(LIVE/'extensions/openclaw-authbus'),'--bridge',str(LIVE/'authbus-relay/bin/authbus-relay-bridge'),
            '--usage-module',str(SDK/'dist/provider-usage-BxQS-VWA.js'),'--config-sha256',CONFIGSHA,'--node',NODE,
            '--expected-commit',COMMIT,'--expected-tree',TREE,'--reuse-provider-root',str(PRIOR)]
        phase=run_phase('native-profile2-selector',argv,env);report['phases'].append(phase)
        selected=json.loads((selector/'result.public.json').read_bytes())
        phase['receiptSha256']=sha(selector/'result.public.json');phase['checks']=len(selected.get('checks',[]))
        check('actual_sdk_selector_driver',phase['returnCode']==0 and not phase['timedOut'] and selected.get('ok') is True)
        check('selector_prior_proof_exact_credential_link',selected.get('providerReadPerformedThisRun') is False
              and selected.get('priorProviderCredentialBindingQualified') is True
              and selected.get('providerValidationLink',{}).get('credentialAndResolvedAccessByteIdentical') is True)
        check('actual_sdk_and_cold_rollback',selected.get('actualInstalledDefaultResolverQualified') is True
              and selected.get('actualServerColdRestartQualified') is True and selected.get('privateLogicalStoreRollbackQualified') is True)
        report['sourceAfter']=source_identity()
        report['relayPidsAfter']=relay_pids()
        check('production_relay_processes_unchanged',report['relayPidsBefore']==report['relayPidsAfter'])
        check('all_frozen_inputs_unchanged',{p:sha(p) for p in before}==before)
        check('owned_servers_stopped',not remaining_owned())
        report.update(ok=True,normal33CurrentAuthRowMigrationQualified=True,normal33ActualSdkDefaultResolverQualified=True,
            normal33AuthOnlyColdRecoveryQualified=True,normal33PrivateLogicalRollbackQualified=True,
            currentConnectivityQualified=False,priorProviderProofLinked=True)
    except Exception as error:
        report['error']=str(error) if isinstance(error,Refused) else type(error).__name__
        report['errorFrames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        try:
            report['ownedServersRemaining']=remaining_owned()
            report['allOwnedServersStopped']=not report['ownedServersRemaining']
            if before:report['frozenInputsUnchangedAtExit']={p:sha(p) for p in before}==before
            if report['ownedServersRemaining'] or report.get('frozenInputsUnchangedAtExit') is not True:report['ok']=False
        except Exception as error:
            report['cleanupErrorClass']=type(error).__name__;report['ok']=False
        put(ROOT/'result.public.json',report)
    print(json.dumps({'ok':report['ok'],'error':report.get('error'),'result':str(ROOT/'result.public.json'),'allOwnedServersStopped':report.get('allOwnedServersStopped')}))
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())
