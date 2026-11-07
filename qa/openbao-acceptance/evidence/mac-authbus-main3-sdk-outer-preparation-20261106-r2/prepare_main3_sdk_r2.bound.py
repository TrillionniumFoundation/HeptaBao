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

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
HOME=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-20261106-r2')
PREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-preparation-20261106-r2')
JOURNAL=Path('/Users/qianqi/heptabao-mac-authbus-main3-sdk-journal-20261106-r2')
QA=ROOT/'qa'
CANONICAL=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-4bde9-r1/artifacts/heptabao-server')
CANONICAL_SHA='5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CANONICAL_BYTES=92359328
EXPECTED_PINS={'mac_owned_unreaped_r1.py': {'bytes': 14877, 'sha256': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298'}, 'mac_owned_commands_r1.py': {'bytes': 6154, 'sha256': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530'}, 'mac_t5_volume_guard_r1.py': {'bytes': 13385, 'sha256': '8e02de07bc4535fd5c577c38c7e42f56e914526a17452b908f6cacc030d8a826'}, 'mac_owned_launchd_r3.py': {'bytes': 58613, 'sha256': '37038b37713db2d5f43f4fd1749590f31d5a192a71263aefe718a9318e8d421f'}, 'mac_native_process_observer_r1.py': {'bytes': 13423, 'sha256': 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b'}, 'mac_current_server_owner_r1.py': {'bytes': 16143, 'sha256': 'd4ca6bcecbec1c3a2fb2a1e26cf3bcd35ea49d4157b54dd69bad6d28f423a3ea'}, 'mac_public_code_pin_excerpt_r1.py': {'bytes': 1792, 'sha256': '7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f'}, 'tls_complete_http_probe.py': {'bytes': 4750, 'sha256': '7e92967416e0dcdc80b9c5d56e0655775630cef9198aba5541fa75bbf98c42fc'}, 'test_suid_ps_tls_r2.py': {'bytes': 16309, 'sha256': '261d38cdf25e873a99fc99c901d1cefcbdc0d434388877caa26d57cac7496bc6'}, 'main3_source_fence.py': {'bytes': 16577, 'sha256': 'a9ac8f4018240c104e41e13bdd54496fc4e1c2330c0647666722138f930238a4'}, 'main3_api_cycle.py': {'bytes': 17862, 'sha256': '424dec36ff4a23777ea721599c240b6866600865f6151d381155a032306e8e63'}, 'test_main3_api_guards.py': {'bytes': 15130, 'sha256': '14f273d329325dd173e6ae995c309a62d0959595d144b85c04f31d83fc7148b6'}, 'main3_source_authority.py': {'bytes': 2406, 'sha256': '1db9ebcbe9a2251acaff2f13a109c9f6613df9a538acdc59ad6301a165ddc290'}, 'main3_capture_payload_0.py': {'bytes': 60008, 'sha256': '220e0620b337f3ab1f800e043a935bbdb8ee1a4eb4da92c820c6dde575e52eb8'}, 'main3_capture_payload_1.py': {'bytes': 60008, 'sha256': 'c186c7d835c75b9518018ef011ea9c7ad5de20e01daf4ad13dfa26bc5a7e14c4'}, 'main3_capture_payload_2.py': {'bytes': 60008, 'sha256': 'cefb74033c9fd209cd3cbd92ec48bdc28d7569aee55ae8f26584bce1341278c2'}, 'main3_capture_payload_3.py': {'bytes': 36668, 'sha256': '742338b1acbc9ca240eab49d34f4ae586628c68773f48bb13c2ed15f51d9ef1e'}, 'main3_capture_launcher.py': {'bytes': 30681, 'sha256': '6a456279bb01774d7f9b61ef4a6f04953bbfd9be6b374d0f715905e7d044ef5d'}, 'main3_inline_capture.py': {'bytes': 15731, 'sha256': '0a26a0cd175efa68e252962481b8acd4e1cce798c87720973b29f5276c32c24a'}, 'test_main3_inline_capture.py': {'bytes': 9233, 'sha256': '091cefa8a44317cdbe172fefde7b77e278846b3557145e12bc061bff15019bb2'}, 'main3_http_complete.py': {'bytes': 9110, 'sha256': 'ce02882b991e1abb1d135e05c571d2d112032e93a5857769a8b90d25425d5c96'}, 'test_main3_http_complete.py': {'bytes': 10216, 'sha256': '2aaaa0225a1720f7bad4f1f4b2d9a0d1ed9a33469b45ed24cf951dc23a6a9f6c'}, 'qualify_main3_http_tls.py': {'bytes': 8195, 'sha256': '85955fd71a7ec8a350e08d2022cfd8dd84066eeaa10655342ac5851763c44308'}, 'main3_sdk_public_pins.py': {'bytes': 2391, 'sha256': 'a6b4fb50efed1f6b9a05652f6caf6769a2adea109d0728b1620bc119b5c969ee'}, 'main3_sdk_phase.py': {'bytes': 24271, 'sha256': '2ae860ba7fbfef5c48254cd74f0800fcd5ddc341653a7965c1d31c889397a910'}, 'main3_sdk_controller.py': {'bytes': 33429, 'sha256': '907da95534f5d065ffb9ed2df2b3f6be126d995d963e9d9da51db7a0f29657ce'}, 'test_main3_sdk_controller.py': {'bytes': 11340, 'sha256': '6c0d1a96dea4caac4803b1331478b070de4411f3d80286d1601e8956afbeefc6'}}

EXPECTED_ASSETS={'qa/main3_sdk_cycle_r2.mjs': {'bytes': 31439, 'sha256': '7d4f7a1090fc0931ec5fa8f1ca1e48c5402b09997590e27ce8aa0b56ad08f36d'}, 'qa/main3_sdk_wire_r2.mjs': {'bytes': 12400, 'sha256': '2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'}, 'qa/main3_auth_rows_cas_r1.mjs': {'bytes': 3040, 'sha256': '8502f9fa33d2a20076a30f09f02bad612da3ba6e71125f336d72629175092123'}, 'qa/main3_authbus_cache_cas_r1.mjs': {'bytes': 6983, 'sha256': '7c198034ccc1010bea05d21d116e00e5c19bd3008052c01ebf9e73c224eb278d'}, 'qa/main3_sdk_seed_r1.mjs': {'bytes': 7715, 'sha256': 'f1ed65e478eca61d7d5db9a3a0242f7db155a693ca2920aa5645e23e5b6cca00'}, 'plugin/index.js': {'bytes': 54455, 'sha256': 'b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b'}, 'plugin/package.json': {'bytes': 980, 'sha256': 'e9a39d1880a285e76b5b09fb69c9614cfbecff0e1021eb29ce214a6340fd7334'}, 'plugin/order-policy.js': {'bytes': 7376, 'sha256': '16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301'}, 'plugin/runtime-refresh-policy.js': {'bytes': 956, 'sha256': '8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547'}, 'plugin/codex-client-recycler.js': {'bytes': 2120, 'sha256': 'd3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d'}, 'plugin/provider-error-classifier.js': {'bytes': 4670, 'sha256': '3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77'}, 'plugin/bad-refresh-quarantine.js': {'bytes': 5438, 'sha256': '916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286'}, 'plugin/lease-assignments.js': {'bytes': 6932, 'sha256': '24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7'}}

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
    bundle=json.loads(raw);need(set(bundle)=={'sources','assets','preparerSource'},'fixed_bundle_schema')
    sources={name:value.encode('utf-8') for name,value in bundle['sources'].items()}
    need(set(sources)==set(EXPECTED_PINS),'exact_bundle_source_set')
    for name,source in sources.items():
        remaining();pin=EXPECTED_PINS[name]
        need(len(source)==pin['bytes'] and sha(source)==pin['sha256'],'whole_source_before_staging')
        ast.parse(source)
    assets={name:text.encode() for name,text in bundle['assets'].items()}
    need(set(assets)==set(EXPECTED_ASSETS),'exact_public_asset_inventory')
    for name,source in assets.items():
        pin=EXPECTED_ASSETS[name]
        need(len(source)==pin['bytes'] and sha(source)==pin['sha256'],'exact_public_asset_pin')
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
    guard=None;home=None;report={'schema':'heptabao.mac-main3-sdk-preparation-terminal.r2',
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
        for relative in ('', 'qa', 'plugin', 'node_modules', 'input', 'private', 'initial', 'cold-new-process', 'state', 'state/tmp', 'state/tmp/openclaw-501', 'state/oauth', 'state/state', 'state/agents', 'state/agents/main', 'state/agents/main/agent', 'state/agents/trnm', 'state/agents/trnm/agent', 'state/agents/hepta-ui', 'state/agents/hepta-ui/agent', 'state/agents/hepta', 'state/agents/hepta/agent', 'state/agents/hepta-backend', 'state/agents/hepta-backend/agent', 'launchd', 'bin', 'server', 'server/data', 'server/home', 'server/tmp', 'server/tls', 'server/private'):
            guard.mkdir_new(ROOT/relative)
        for name,source in sources.items():
            actual=guard.write_new(QA/name,source)
            need(actual['sha256']==EXPECTED_PINS[name]['sha256'],'staged_source_matches_pin')
        for relative,source in assets.items():
            actual=guard.write_new(ROOT/relative,source)
            need(actual['sha256']==EXPECTED_ASSETS[relative]['sha256'],'staged_public_asset_matches_pin')
        with guard.parent(ROOT/'node_modules/openclaw') as (parent,name):
            os.symlink('/opt/homebrew/lib/node_modules/openclaw',name,dir_fd=parent);os.fsync(parent)
            need(os.readlink(name,dir_fd=parent)=='/opt/homebrew/lib/node_modules/openclaw','fixed_bare_import_sdk_link')
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
        plan={'schema':'heptabao.mac-main3-sdk-preparation.r2','root':str(ROOT),'home':str(HOME),'journal':str(JOURNAL),
            'sourcePins':EXPECTED_PINS,'assetPins':EXPECTED_ASSETS,'homeCopyPins':{name:EXPECTED_PINS[name] for name in copy_pins},'homeBinding':binding,
            'pythonRuntime':python_runtime,'anchorBase64':base64.b64encode(anchor_raw).decode(),'anchorSha256':sha(anchor_raw),
            'canonicalProduct':{'commit':'4bde9aee03fcd27c59e13607e529b1cee594b249',
                'tree':'f08493a23f8ea0637073651231865ea9607b790e','sourcePath':str(CANONICAL),
                'bytes':CANONICAL_BYTES,'sha256':CANONICAL_SHA,'copyPath':str(ROOT/'bin/heptabao-server'),
                'copyIdentity':copy_identity,'canonicalMode':0o700,'retainedCopyMode':0o500},
            'port':port,'certificateLeafSha256':leaf,'wrapperSeconds':30,'execObservationSeconds':10,
            'managerSeconds':600,'failureCleanupSeconds':60,'startupCustodyOnly':True,
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
