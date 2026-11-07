#!/usr/bin/env python3
"""Create-only synthetic Mac fixture. No launchctl mutation or credential capture."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import time
import types

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r2')
HOME=Path('/Users/qianqi/heptabao-mac-fresh-synthetic-launchd-20261106-r2')
PREP=Path('/Users/qianqi/heptabao-mac-fresh-synthetic-preparation-20261106-r2')
JOURNAL=Path('/Users/qianqi/heptabao-mac-fresh-synthetic-journal-20261106-r2')
QA=ROOT/'qa'
CANONICAL=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/artifacts/heptabao-server')
CANONICAL_SHA='5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CANONICAL_BYTES=92359328
EXPECTED_PINS={'mac_public_code_pin_excerpt_r1.py': {'bytes': 1792, 'sha256': '7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f'}, 'mac_owned_commands_r1.py': {'bytes': 6154, 'sha256': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530'}, 'mac_t5_volume_guard_r1.py': {'bytes': 13391, 'sha256': '9d5a6ea743e5abe87f6f84bcbcf6ddb7ba9f080fd3f51e54040d56122159394a'}, 'mac_owned_launchd_r3.py': {'bytes': 58613, 'sha256': '9209144dd581ed547478e5210fffc8e1c75e7bc5511637ba02aed18a63129354'}, 'mac_native_process_observer_r1.py': {'bytes': 13423, 'sha256': 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'}, 'mac_owned_unreaped_r1.py': {'bytes': 14877, 'sha256': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298'}, 'mac_current_server_owner_r1.py': {'bytes': 16139, 'sha256': 'c7eaf0a36bcfac4355c778d93e27bdff58fbcc0cba625987cee6e98e72909be5'}, 'fresh_synthetic_controller_r1.py': {'bytes': 29955, 'sha256': '4697eb12c7af0b88fc8faec697518e0397cc8f620cf2581f301b18206f54f42c'}, 'test_fresh_synthetic_controller_r1.py': {'bytes': 11349, 'sha256': '5b4d3f2cc67196ef2eab036467493edcb90db5e5902e92619b5d78236f754e7a'}, 'tls_complete_http_probe.py': {'bytes': 4750, 'sha256': '7e92967416e0dcdc80b9c5d56e0655775630cef9198aba5541fa75bbf98c42fc'}, 'test_suid_ps_tls_r2.py': {'bytes': 16309, 'sha256': '261d38cdf25e873a99fc99c901d1cefcbdc0d434388877caa26d57cac7496bc6'}}

def need(value,code):
    if not value:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(s):return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))

def main():
    started=time.monotonic();until=started+120.0
    def remaining():
        left=until-time.monotonic();need(left>0,'preparation_120_seconds');return left
    os.umask(0o077);need(sys.platform=='darwin' and os.geteuid()==501,'exact_mac_owner')
    raw=sys.stdin.buffer.read(1048576+1);need(len(raw)<=1048576,'bounded_public_source_bundle')
    bundle=json.loads(raw);need(set(bundle)=={'sources','preparerSource'},'fixed_bundle_schema')
    sources={name:value.encode('utf-8') for name,value in bundle['sources'].items()}
    need(set(sources)==set(EXPECTED_PINS),'exact_bundle_source_set')
    for name,source in sources.items():
        remaining();pin=EXPECTED_PINS[name]
        need(len(source)==pin['bytes'] and sha(source)==pin['sha256'],'whole_source_before_staging')
        ast.parse(source)
    need(len(bundle['preparerSource'].encode())<=65536,'preparer_source_bound')
    os.mkdir(PREP,0o700)
    prep_fd=os.open(PREP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    prep_identity=identity(os.fstat(prep_fd))[:5]
    need(prep_identity==identity(PREP.lstat())[:5] and int(prep_identity[2])==501
         and stat.S_IMODE(int(prep_identity[4]))==0o700,'new_preparation_directory')
    def public_new(name,raw):
        remaining();need('/' not in name and name.endswith(('.py','.json')),'fixed_preparation_leaf')
        need(identity(os.fstat(prep_fd))[:5]==identity(PREP.lstat())[:5]==prep_identity,'same_preparation_root')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=prep_fd)
        try:
            before=os.fstat(fd);offset=0
            need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
                 and stat.S_IMODE(before.st_mode)==0o600,'new_preparation_file')
            while offset<len(raw):
                remaining();count=os.write(fd,raw[offset:]);need(count>0,'preparation_write_progress');offset+=count
            os.fsync(fd);os.fsync(prep_fd);after=os.fstat(fd)
            need(identity(before)[:6]==identity(after)[:6] and after.st_size==len(raw)
                 and identity(after)==identity(os.stat(name,dir_fd=prep_fd,follow_symlinks=False)), 'preparation_created_file_bound')
        finally:os.close(fd)
        return {'path':str(PREP/name),'bytes':len(raw),'sha256':sha(raw)}
    public_new('prepare_fresh_synthetic_r1.py',bundle['preparerSource'].encode())
    # Execute pinned pure libraries in memory; no current config/capture source is loaded.
    for name in ('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py','mac_native_process_observer_r1.py',
                 'mac_t5_volume_guard_r1.py','mac_public_code_pin_excerpt_r1.py','mac_owned_launchd_r3.py'):
        module=types.ModuleType(Path(name).stem);module.__file__=str(QA/name)
        sys.modules[module.__name__]=module;exec(compile(sources[name],str(QA/name),'exec'),module.__dict__)
    from mac_owned_commands_r1 import Signals,Commands
    from mac_t5_volume_guard_r1 import HeldT5
    from mac_public_code_pin_excerpt_r1 import public_code_pin
    from mac_owned_launchd_r3 import HomeControl
    signals=Signals();signals.install();commands=Commands(signals)
    guard=None;home=None;report={'schema':'heptabao.mac-fresh-synthetic-preparation-terminal.r2',
        'ok':False,'serviceMutationExecuted':False,'currentCredentialInputsRead':False,
        'canonicalBinaryModified':False,'oldR2Modified':False,'sourcePins':EXPECTED_PINS}
    try:
        anchor={'schema':'heptabao.mac-current-t5-public-anchor.r1','source_inventory_sha256':sha(encoded(EXPECTED_PINS)),
            'volumeUUID':'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice':str(Path('/Volumes/T5').lstat().st_dev),
            'anchors':[{'path':path,'identity':list(identity(Path(path).lstat()))} for path in ('/','/Volumes','/Volumes/T5')]}
        anchor_raw=encoded(anchor)
        guard=HeldT5(anchor_raw,sha(anchor_raw),remaining,signals.critical)
        row,out,err=commands.run('prepare-t5-volume',['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown'] and not err,'actual_t5_volume_probe')
        guard.accept_diskutil(out)
        for relative in ('','qa','launchd','bin','server','server/data','server/home','server/tmp','server/tls'):
            guard.mkdir_new(ROOT/relative)
        for name,source in sources.items():
            actual=guard.write_new(QA/name,source)
            need(actual['sha256']==EXPECTED_PINS[name]['sha256'],'staged_source_matches_pin')
        source_fd=os.open(CANONICAL,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            original=os.fstat(source_fd)
            need(stat.S_ISREG(original.st_mode) and original.st_uid==501 and original.st_nlink==1
                 and stat.S_IMODE(original.st_mode)==0o700 and original.st_size==CANONICAL_BYTES
                 and identity(original)==identity(CANONICAL.lstat()),'canonical_qualified_binary_custody')
            with guard.parent(ROOT/'bin/heptabao-server') as (parent,name):
                destination=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
                try:
                    digest=hashlib.sha256();size=0
                    while True:
                        remaining();block=os.read(source_fd,1048576)
                        if not block:break
                        digest.update(block);size+=len(block);need(size<=CANONICAL_BYTES,'binary_copy_bound')
                        offset=0
                        while offset<len(block):
                            count=os.write(destination,block[offset:]);need(count>0,'binary_copy_progress');offset+=count
                    need(size==CANONICAL_BYTES and digest.hexdigest()==CANONICAL_SHA
                         and identity(original)==identity(os.fstat(source_fd))==identity(CANONICAL.lstat()),'whole_canonical_binary_pin')
                    os.fchmod(destination,0o500);os.fsync(destination);os.fsync(parent)
                    current=os.fstat(destination)
                    need(current.st_uid==501 and current.st_nlink==1 and stat.S_IMODE(current.st_mode)==0o500
                         and current.st_size==CANONICAL_BYTES and identity(current)==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)), 'retained_copy_mode_500')
                    copy_identity=list(identity(current))
                finally:os.close(destination)
        finally:os.close(source_fd)
        openssl_config=b'[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\nCN = localhost\n[v3]\nsubjectAltName = DNS:localhost,IP:127.0.0.1\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage = serverAuth\n'
        guard.write_new(ROOT/'server/tls/openssl.cnf',openssl_config)
        row,out,err=commands.run('synthetic-self-signed-tls',['/usr/bin/openssl','req','-x509','-newkey','rsa:2048',
            '-sha256','-nodes','-days','1','-config',str(ROOT/'server/tls/openssl.cnf'),
            '-keyout',str(ROOT/'server/tls/server.key'),'-out',str(ROOT/'server/tls/server.crt')],
            until=min(until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown'],'synthetic_tls_generation_complete')
        certificate=guard.read(ROOT/'server/tls/server.crt',65536)
        leaf=sha(ssl.PEM_cert_to_DER_cert(certificate.decode('ascii')))
        # Key bytes and their digest are never read into a public report.
        key_info=(ROOT/'server/tls/server.key').lstat()
        need(stat.S_ISREG(key_info.st_mode) and key_info.st_uid==501 and key_info.st_nlink==1
             and stat.S_IMODE(key_info.st_mode)==0o600 and 0<key_info.st_size<65536,'synthetic_tls_private_key_custody')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        config={'listen':'127.0.0.1:'+str(port),'data_dir':str(ROOT/'server/data'),
            'audit_file':str(ROOT/'server/audit.jsonl'),'tls_cert_file':str(ROOT/'server/tls/server.crt'),
            'tls_key_file':str(ROOT/'server/tls/server.key'),'storage':{'native_v6_file':{'path':str(ROOT/'server/data')}}}
        config_pin=guard.write_new(ROOT/'server/server.json',encoded(config))
        for generation in ('server-initial','server-cold-new-process'):
            plan={'schema':'heptabao.mac-owned-launchd-server-plan.private.r1','generation':generation,
                'binaryPath':str(ROOT/'bin/heptabao-server'),'binarySha256':CANONICAL_SHA,'binaryBytes':CANONICAL_BYTES,
                'configPath':str(ROOT/'server/server.json'),'configSha256':config_pin['sha256'],
                'port':port,'workRoot':str(ROOT)}
            guard.write_new(ROOT/'launchd'/(generation+'.private.json'),encoded(plan))
        copy_pins={'mac_current_server_owner_r1.py':(EXPECTED_PINS['mac_current_server_owner_r1.py']['bytes'],
                    EXPECTED_PINS['mac_current_server_owner_r1.py']['sha256'])}
        home=HomeControl(remaining=remaining,critical=signals.critical,copy_pins=copy_pins,create=True)
        home.write_new(HOME/'mac_current_server_owner_r1.py',sources['mac_current_server_owner_r1.py'],copy=True)
        binding=home.actual_binding()
        python_runtime=public_code_pin('/opt/homebrew/bin/python3',remaining=remaining,critical=signals.critical)
        plan={'schema':'heptabao.mac-fresh-synthetic-preparation.r2','root':str(ROOT),'home':str(HOME),'journal':str(JOURNAL),
            'sourcePins':EXPECTED_PINS,'homeCopyPins':{name:EXPECTED_PINS[name] for name in copy_pins},'homeBinding':binding,
            'pythonRuntime':python_runtime,'anchorBase64':base64.b64encode(anchor_raw).decode(),'anchorSha256':sha(anchor_raw),
            'canonicalProduct':{'commit':'4bde9aee03fcd27c59e13607e529b1cee594b249',
                'tree':'f08493a23f8ea0637073651231865ea9607b790e','sourcePath':str(CANONICAL),
                'bytes':CANONICAL_BYTES,'sha256':CANONICAL_SHA,'copyPath':str(ROOT/'bin/heptabao-server'),
                'copyIdentity':copy_identity,'canonicalMode':0o700,'retainedCopyMode':0o500},
            'port':port,'certificateLeafSha256':leaf,'wrapperSeconds':30,'execObservationSeconds':10,
            'managerSeconds':600,'failureCleanupSeconds':60,'syntheticStartupOnly':True,
            'preparerSourceSha256':sha(bundle['preparerSource'].encode()),'credentialsRead':False,'serviceStarted':False}
        report['plan']=public_new('plan.public.json',encoded(plan))
        report['ok']=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,RuntimeError) else None
    finally:
        if guard is not None:guard.close();report['volumeClosure']=guard.public_state()
        if home is not None:report['homeClosure']=home.close()
        report['commands']=commands.public()
        report['ok']=bool(report['ok'] and report.get('volumeClosure',{}).get('allDescriptorsClosed')
            and not report.get('volumeClosure',{}).get('closeErrors')
            and report.get('homeClosure',{}).get('allReturnedDescriptorsClosed')
            and report['commands']['allOwnedCommandsStopped'] and report['commands']['unknownCommandCount']==0)
        report['elapsedSeconds']=time.monotonic()-started
        report['terminalFile']=public_new('prepare-terminal.public.json',encoded(report))
        os.close(prep_fd)
        print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['ok'] else 1

if __name__=='__main__':sys.exit(main())
