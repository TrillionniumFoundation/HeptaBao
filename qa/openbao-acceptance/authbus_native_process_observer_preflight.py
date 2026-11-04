#!/usr/bin/env python3
"""Focused no-credential positive/forged-lineage checks of the actual observer."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
from authbus_native_codex_live import NODE, parent_sandbox, run_owned_capture

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.work_dir
    root.mkdir(mode=0o700)
    qa = Path(__file__).parent
    pins = {str(qa / name): hashlib.sha256((qa / name).read_bytes()).hexdigest() for name in
            ('authbus_native_codex_consumer.mjs', 'authbus_native_codex_live.py',
             'authbus_native_process_observer.py')}
    text = (qa / 'authbus_native_codex_consumer.mjs').read_text()
    start = text.index('function observeOwnedNative(child) {')
    end = text.index('\n\nasync function exerciseNative', start)
    receiver = text[start:end]
    assert receiver.endswith('}\n')
    leaf = root / 'leaf.mjs'
    leaf.write_text("setInterval(()=>{},1000);\n")
    launcher = root / 'launcher.mjs'
    launcher.write_text(
        "import cp from 'node:child_process';\n"
        "const child=cp.spawn(process.execPath,[process.argv[2]],{stdio:['ignore','ignore','ignore'],detached:false});\n"
        "process.on('SIGTERM',()=>{child.kill('SIGTERM');});\n"
        "child.on('exit',()=>process.exit(0));\n")
    prefix = """import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import cp from 'node:child_process';
const report={checks:[],nativeSpawn:{}},plan={nativeBinary:process.execPath};
const need=(v,c)=>{if(!v)throw Object.assign(new Error(c),{safeCode:c})};
const check=(c,v)=>{report.checks.push({case:c,passed:v===true});need(v,c)};
"""
    tail = """
const child=cp.spawn(process.execPath,[process.argv[2],process.argv[3]],
 {env:process.env,stdio:['pipe','pipe','pipe'],detached:false});
child.on('error',()=>{});
let error=null,verified=false;
try{observeOwnedNative(child);verified=true}
catch(e){error=e.safeCode??e.constructor.name}
const waitClose=(proc,ms)=>new Promise(resolve=>{
 let timer=setTimeout(()=>resolve(false),ms);
 proc.once('close',()=>{clearTimeout(timer);resolve(true)});
});
let parentSignal0Denied=false;
try{process.kill(process.ppid,0)}catch(e){parentSignal0Denied=e.code==='EPERM'}
const ended=waitClose(child,1500);
const ownSigtermSent=child.kill('SIGTERM');
const ownSigtermWaited=await ended;
const killed=cp.spawn(process.execPath,[process.argv[3]],{env:process.env,stdio:['ignore','ignore','ignore'],detached:false});
killed.on('error',()=>{});
await new Promise(resolve=>killed.once('spawn',resolve));
const killedWait=waitClose(killed,1500);
const ownSigkillSent=killed.kill('SIGKILL');
const ownSigkillWaited=await killedWait;
const signals={parentSignal0Denied,ownSigtermSent,ownSigtermWaited,ownSigkillSent,ownSigkillWaited,
 ownSigkillObserved:killed.signalCode==='SIGKILL'};
process.stdout.write(JSON.stringify({...report,verified,error,signals,syntheticRpcDispatched:false})+'\\n');
process.exit(0);
"""
    policy = root / 'policy.sb'
    policy.write_bytes(parent_sandbox(root, 65431, pins))
    records = []
    for name, forged in [('actual-lineage', False), ('forged-launcher-parent', True)]:
        case = root / name
        case.mkdir(mode=0o700)
        source = receiver
        if forged:
            assert source.count('launcherPid: child.pid') == 1
            source = source.replace('launcherPid: child.pid', 'launcherPid: process.ppid')
        script = case / 'probe.mjs'
        script.write_text(prefix + source + tail)
        env = {'PATH':'/opt/homebrew/bin:/usr/bin:/bin', 'HOME':str(case), 'TMPDIR':str(case)}
        lifecycle = run_owned_capture(['/usr/bin/sandbox-exec','-f',str(policy),str(NODE),
            str(script),str(launcher),str(leaf)], env, case, 8,
            case / 'stdout.public.json', case / 'stderr.private',
            native_observer={'nodeExecutable':str(NODE.resolve()),
                             'nativeExecutable':str(NODE.resolve())})
        raw = (case / 'stdout.public.json').read_bytes()
        result = json.loads(raw) if raw else {'verified':False,'error':'no_report'}
        no_survivors = lifecycle['noGroupSurvivors'] and lifecycle['primaryReaped']
        passed = (lifecycle['exitCode'] == 0 and not lifecycle['outcomeUnknown']
                  and no_survivors and result['verified'] is (not forged)
                  and lifecycle['nativeProcessObserver']['verified'] is (not forged)
                  and result.get('syntheticRpcDispatched') is False
                  and bool(result.get('signals')) and all(result['signals'].values()))
        if forged:
            passed = passed and lifecycle['nativeProcessObserver'].get('error') == 'launcher_real_parent_group_birth'
        records.append({'case':name,'passed':passed,'lifecycle':lifecycle,'receiver':result,
                        'sourceSha256':hashlib.sha256(script.read_bytes()).hexdigest()})
    report = {'schema':'heptabao.outer-owned-native-observer-preflight.v1',
              'ok':all(r['passed'] for r in records),'checks':records,'sourcePins':pins,
              'policySha256':hashlib.sha256(policy.read_bytes()).hexdigest(),
              'credentialsSupplied':False,'providerRequests':0,'nativeAppServerStarted':False,
              'scope':'Actual receiver function and outer libproc observer; real synthetic Node lineage and forged parent rejection, same shared kernel policy, no auth/model data.'}
    data=(json.dumps(report,indent=2)+'\n').encode()
    output=root/'result.public.json'
    with output.open('xb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    print(json.dumps({'result':str(output),'sha256':hashlib.sha256(data).hexdigest(),
                      'ok':report['ok'],'checks':[{'case':r['case'],'passed':r['passed']} for r in records]}))
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
