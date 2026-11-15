#!/usr/bin/env python3
"""Privileged read/copy only: create one private, immutable QA backup phase.

No subprocess, network packet, firewall command, original-file write, restore,
permission change, or retry is performed. The caller supplies the original EOF
authority from the two preceding fixed readonly native commands.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import time

ROOT = Path('/home/qq/heptabao-ha-ufw-peer-ports-20261106-r2')
PHASES = {'before', 'after-add-mac', 'after-add-x230', 'after-delete-x230', 'after-delete-mac', 'before-delete-x230', 'before-ha-r3'}
CONFIGS = {
 'etc-ufw-user.rules': '/etc/ufw/user.rules',
 'etc-ufw-user6.rules': '/etc/ufw/user6.rules',
 'etc-ufw-before.rules': '/etc/ufw/before.rules',
 'etc-ufw-after.rules': '/etc/ufw/after.rules',
 'etc-ufw-before6.rules': '/etc/ufw/before6.rules',
 'etc-ufw-after6.rules': '/etc/ufw/after6.rules',
 'etc-ufw-ufw.conf': '/etc/ufw/ufw.conf',
 'etc-default-ufw': '/etc/default/ufw',
}
PINS = {
 '/usr/sbin/ufw': (4959, 'e2ff4f8178807f04b411aad08315d875cb915ce8d9aa5895703bb7f0055e5d28'),
 '/usr/sbin/nft': (26928, '7b3efd79bd3a70d72275b7bbfe19f2234a837968a3c0ad5528126a396a00d42f'),
 '/usr/sbin/xtables-nft-multi': (224632, '603f55a8877a2db138615f961901ef23ba77451ac0a53233bd01f1c9b216636a'),
 '/usr/lib/python3/dist-packages/ufw/frontend.py': (36093, 'c61d78d719778acf01314b222078db152fbfb45b2f9de66f3df51be45868d7eb'),
 '/usr/lib/python3/dist-packages/ufw/backend.py': (27407, '24a372164947a8a3808b8797db49430d285f6ec1113f2c2895e403a058689232'),
 '/usr/lib/python3/dist-packages/ufw/backend_iptables.py': (58842, '69cabdd144d3feef41910ac44fd79dde9fd518aa2c9eb8d9e6a7800c4661fc55'),
 '/usr/lib/python3/dist-packages/ufw/parser.py': (31980, 'db8d0769467fb4af3fd843980bf19dd82d55161e1986e8ae4723a5ae81f62d0b'),
 '/usr/lib/python3/dist-packages/ufw/common.py': (22531, '3eacf4b886260b0a9b1f9b74986fd6fcba3e0e90afed38c01db30736cce41728'),
 '/usr/lib/python3/dist-packages/ufw/util.py': (32791, '7bb332974f8caf4322b6246c51fc72af6b6ff67ad18ce62b4735dc762e9dd6cc'),
}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def identity(st):
    return tuple(getattr(st, k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def alarm(signum, frame):
    raise RuntimeError('capture_deadline')


def main():
    os.umask(0o077)
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(20)
    held = []
    dirs = []
    created_opened = 0
    close_attempts = {'created':0,'input':0,'directory':0}
    close_successes = {'created':0,'input':0,'directory':0}
    close_errors = []
    def close_once(fd,role):
        close_attempts[role]+=1
        try:
            os.close(fd); close_successes[role]+=1; return True
        except BaseException as error:
            row={'role':role,'errorType':type(error).__name__}
            if isinstance(error,OSError): row['errno']=error.errno
            close_errors.append(row)
            return False
    report = {'schema':'heptabao.ai395-ufw-private-phase-capture.r1','ok':False,
              'firewallWrites':0,'childCount':0,'networkPacketsSent':0,
              'originalFilesOrPermissionsChanged':False,'crossSourceSnapshotIsAtomic':False}
    try:
        need(os.getuid()==0 and platform.node()=='ai395' and len(sys.argv)==2, 'fixed_privileged_observer')
        need(len(sys.argv[1].encode())<=32768, 'bounded_manifest')
        manifest=json.loads(sys.argv[1])
        need(set(manifest)=={'phase','expectedRootIdentity','kernelInputs'}, 'exact_manifest_fields')
        phase=manifest['phase']
        need(phase in PHASES and isinstance(manifest['kernelInputs'],list) and len(manifest['kernelInputs'])==2, 'fixed_phase')
        need({row.get('kind') for row in manifest['kernelInputs']}=={'nft','iptables-filter'}, 'closed_kernel_inputs')
        report['phase']=phase

        def read(path, uid, maximum):
            path=Path(path); st=path.lstat()
            need(path.resolve(strict=True)==path and stat.S_ISREG(st.st_mode) and st.st_uid==uid
                 and st.st_nlink==1 and not st.st_mode&0o022 and st.st_size<=maximum, 'regular_owned_bounded_input')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            held.append((path,fd,identity(st)))
            need(identity(os.fstat(fd))==identity(st), 'same_open_input')
            data=bytearray()
            while True:
                block=os.read(fd, min(65536, st.st_size+1-len(data)))
                if not block: break
                data.extend(block); need(len(data)<=st.st_size, 'bounded_input_growth')
            need(len(data)==st.st_size and identity(os.fstat(fd))==identity(path.lstat())==identity(st), 'stable_full_input')
            return bytes(data), identity(st)

        for path,(size,digest) in PINS.items():
            data,_=read(path,0,1048576)
            need(len(data)==size and hashlib.sha256(data).hexdigest()==digest, 'fixed_system_source_pin')

        inputs={}
        for name,path in CONFIGS.items():
            data,ident=read(path,0,1048576)
            inputs[name]=(data,ident,path)
        need(re.search(rb'(?m)^ENABLED=yes\s*$',inputs['etc-ufw-ufw.conf'][0]) is not None, 'ufw_enabled_before_or_after')

        authority={}
        for row in manifest['kernelInputs']:
            need(set(row)=={'kind','path','bytes','sha256','eofAuthorityOriginal'}, 'exact_kernel_input_fields')
            need(type(row['bytes']) is int and 0<row['bytes']<=2097152
                 and re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None, 'bounded_kernel_pin')
            match=re.fullmatch(r'/home/qq/\.local/state/hepta-runtime-mac-worker/terminals/(dpty-[a-z0-9-]+)/output\.log',row['path'])
            need(match is not None and isinstance(row['eofAuthorityOriginal'],str), 'fixed_native_archive_origin')
            original=json.loads(row['eofAuthorityOriginal']); status=original['status']
            need(original['host']=='ai395' and original['session_id']==match.group(1)
                 and original['offset']==original['next_offset']==original['available_end']==row['bytes']
                 and original['output_complete'] is True and original['truncated_before_offset'] is False
                 and original['text_is_lossy'] is False and original['bytes_hex']=='' and original['text']==''
                 and status['state']=='exited' and status['exit_code']==0 and status['output_complete'] is True
                 and status['capture_error'] is None and status['bytes_seen']==status['bytes_stored']==row['bytes'], 'complete_natural_exit_authority')
            data,ident=read(row['path'],1000,2097152)
            need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'], 'original_kernel_bytes')
            if row['kind']=='nft':
                parsed=json.loads(data.decode())
                need(set(parsed)=={'nftables'} and isinstance(parsed['nftables'],list) and parsed['nftables'], 'complete_nft_json')
            else:
                lines=data.decode().splitlines()
                need(sum(line=='*filter' for line in lines)==1 and sum(line=='COMMIT' for line in lines)==1, 'complete_filter_dump')
            name=row['kind']+'.original.private.log'
            inputs[name]=(data,ident,row['path'])
            authority[row['kind']]=row['eofAuthorityOriginal'].encode()

        parent=ROOT.parent.lstat()
        need(ROOT.parent.resolve(strict=True)==ROOT.parent and stat.S_ISDIR(parent.st_mode)
             and parent.st_uid==1000 and not parent.st_mode&0o022, 'known_parent_directory')
        parent_fd=os.open(ROOT.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); dirs.append(parent_fd)
        need(identity(os.fstat(parent_fd))[:5]==identity(parent)[:5], 'held_parent_identity')
        if phase=='before':
            need(manifest['expectedRootIdentity'] is None, 'new_root_only')
            os.mkdir(ROOT.name,0o700,dir_fd=parent_fd)
        root_fd=os.open(ROOT.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd); dirs.append(root_fd)
        root_ident=identity(os.fstat(root_fd))[:5]
        need(root_ident[2:4]==(0,0) and stat.S_IMODE(root_ident[4])==0o700, 'private_root_custody')
        if phase!='before':
            need([str(x) for x in root_ident]==manifest['expectedRootIdentity'], 'original_private_root_identity')
        os.mkdir(phase,0o700,dir_fd=root_fd)
        phase_fd=os.open(phase,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd); dirs.append(phase_fd)
        phase_ident=identity(os.fstat(phase_fd))[:5]

        def create(name,data):
            nonlocal created_opened
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=phase_fd)
            created_opened+=1
            try:
                view=memoryview(data)
                while view:
                    count=os.write(fd,view); need(count>0,'complete_backup_write'); view=view[count:]
                os.fsync(fd)
            finally:
                need(close_once(fd,'created'),'backup_fd_close_failed')

        pins={}
        for name,(data,ident,path) in inputs.items():
            create(name,data)
            pins[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                        'originalPath':str(path),'originalIdentity':[str(x) for x in ident]}
        for kind,data in authority.items(): create(kind+'.eof-authority.original.json',data)
        for path,fd,ident in held:
            need(path.resolve(strict=True)==path and identity(os.fstat(fd))==identity(path.lstat())==ident, 'all_original_inputs_still_stable')
        need(identity(ROOT.parent.lstat())[:5]==identity(parent)[:5]
             and identity(ROOT.lstat())[:5]==root_ident
             and identity((ROOT/phase).lstat())[:5]==phase_ident, 'backup_directory_bindings_stable')
        report.update(ok=True,privateBackupComplete=True,systemSourcePinsUnchanged=True,
                      rootIdentity=[str(x) for x in root_ident],phaseIdentity=[str(x) for x in phase_ident],files=pins)
        create('capture.public.json',(json.dumps(report,sort_keys=True)+'\n').encode())
        os.fsync(phase_fd); os.fsync(root_fd); os.fsync(parent_fd)
    except BaseException as error:
        report['ok']=False; report['privateBackupComplete']=False; report['errorType']=type(error).__name__
        if type(error) is RuntimeError: report['errorCode']=str(error)
        if isinstance(error,OSError): report['errno']=error.errno
    finally:
        signal.alarm(0)
        for _,fd,_ in held: close_once(fd,'input')
        for fd in reversed(dirs): close_once(fd,'directory')
        opened={'created':created_opened,'input':len(held),'directory':len(dirs)}
        all_closed=not close_errors and close_attempts==close_successes==opened
        report['fdCloseFacts']={'opened':opened,
                                'attemptedOnce':close_attempts,'knownClosed':close_successes,
                                'allOpenedFdsKnownClosed':all_closed,
                                'firstError':close_errors[0] if close_errors else None,
                                'errorCount':len(close_errors)}
        if not all_closed:
            report['ok']=False; report['privateBackupComplete']=False
            report.setdefault('errorCode','one_or_more_fd_closes_failed')
        print(json.dumps(report,sort_keys=True,separators=(',',':')))
    return 0 if report['ok'] else 1


if __name__=='__main__': raise SystemExit(main())
