#!/usr/bin/env python3
"""Create-only qualified public artifact relay; no Git, service or candidate execution."""
from pathlib import Path
import hashlib,json,os,platform,shlex,signal,stat,subprocess,sys,time
PARENT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OUT=PARENT/'public-current-linux-artifact-transfer-20261106-r1'
RECEIVER_ROOT='/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1'
ABI_RECEIPT='/home/qian/heptabao-current-4bde9-static-abi-20261106-r1/current-pocket4-capture-r1/capture/result.public.json'
ABI_SHA='ca07a01f3c67d6934e18e1be4c9869cf90677ed735cfc3f8266f9f0e857669c6'
START=time.monotonic();DEADLINE=START+840
REPORT={'schema':'heptabao.mac-current-normal-artifact-relay.v1','status':'running','steps':[],
        'source_commit':'4bde9aee03fcd27c59e13607e529b1cee594b249',
        'source_tree':'f08493a23f8ea0637073651231865ea9607b790e',
        'producer_host':'pocket4','receiver_host':'x230','ssh_aliases':['pocket4','x230'],
        'production_changed':False,'rust_build_executed':False,'product_binary_executions':0,
        'credential_files_copied':False,'automatic_retry':False,
        'transport_grants_runtime_qualification':False,'source_preparation_and_workloads_still_required':True,
        'new_receiver_root':RECEIVER_ROOT,'remote_effects_unknown':False}
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
SSH = '/usr/bin/ssh'
TOOL_PINS = {'/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14': (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'), '/usr/bin/ssh': (1584576, '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3')}
SSH_ARGS = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']
REMOTE_COMMON = "from pathlib import Path\nimport hashlib,json,os,platform,stat,sys\nos.umask(0o077)\ndef need(ok,label):\n if not ok:raise RuntimeError(label)\ndef ident(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\ndef directory(path):\n s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o022 and path.resolve()==path,'owned_real_directory')\ndef read_file(path,size,sha):\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n try:\n  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size and before.st_uid==1000 and not before.st_mode&0o022,'source_regular_size')\n  with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(size+1)\n  need(len(data)==size and hashlib.sha256(data).hexdigest()==sha and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'source_identity_or_hash')\n  return data\n finally:os.close(fd)\n"
FILES = [{'bytes': 110799168, 'destination': 'artifacts/heptabao-server', 'mode': 448, 'name': 'heptabao-server', 'sha256': '85c1e21771cc1110e6442ba06cbda31db5ba7040d15f8b5c1930aa6fa40c5e5c', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/artifacts/heptabao-server'}, {'bytes': 102211888, 'destination': 'artifacts/heptabao-seed', 'mode': 448, 'name': 'heptabao-seed', 'sha256': '434c32ed59201c13d8af498f5a6b19f10935e744b085a4f8029c241523f4d968', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/artifacts/heptabao-seed'}, {'bytes': 285431, 'destination': 'provenance/normal107.result.original.public.json', 'mode': 384, 'name': 'normal107.result.original.public.json', 'sha256': 'b52b67303587b3f94f1bed5330dfd2b0edaecabb89feb93d3fd3ff81419a47f5', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/result.public.json'}, {'bytes': 142663, 'destination': 'provenance/test-selection.public.json', 'mode': 384, 'name': 'test-selection.public.json', 'sha256': '869feff2d8672fe37a26a2fb671cdc853b3c9d7f889edfe76650eed8103f44e9', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/test-selection.public.json'}, {'bytes': 21718, 'destination': 'provenance/normal107.controller.original.py', 'mode': 384, 'name': 'normal107.controller.original.py', 'sha256': 'c8ef09b133312149eecc1886322cc96dcecda18c637b0db9fc3a5e917b3f6564', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/controller.py'}, {'bytes': 733, 'destination': 'provenance/normal107.terminal.exact-tool-text.json', 'mode': 384, 'name': 'normal107.terminal.exact-tool-text.json', 'sha256': '8ec1de7b5b992112d479afa5f64233fd9196e83ab323581041b3f6f99670ef63', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/native-build-projection-r1/normal107.terminal.exact-tool-text.json'}, {'bytes': 377715, 'destination': 'provenance/candidate.bundle', 'mode': 384, 'name': 'candidate.bundle', 'sha256': '9d7d937b2d324f73913f7f1fc144c6368ffa79593dad1dfede82e8033362f7b0', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/candidate.bundle'}, {'bytes': 3992, 'destination': 'provenance/native-build.public.json', 'mode': 384, 'name': 'native-build.public.json', 'sha256': '25263aa341d5525570da0c950ff519ed808110fc301c63fab7b1611015b7fa8e', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/native-build-projection-r1/native-build.public.json'}, {'bytes': 729, 'destination': 'provenance/native-projection.terminal.exact-tool-text.json', 'mode': 384, 'name': 'native-projection.terminal.exact-tool-text.json', 'sha256': 'fa639c83f44a98ededc81a7a3deddb6a6c63a1db153972b573d6135990899d8f', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/native-static-abi-producer-r1/projection.terminal.exact-tool-text.json'}, {'bytes': 37794, 'destination': 'provenance/producer-abi.result.original.public.json', 'mode': 384, 'name': 'producer-abi.result.original.public.json', 'sha256': 'd19c0efdebc27940a56ddef6c5ced9ff68bcc23465c2730d07d396fc915d1b4f', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/native-static-abi-producer-r1/capture/result.public.json'}, {'bytes': 426720, 'destination': 'provenance/13-normal-release-build.stdout', 'mode': 384, 'name': '13-normal-release-build.stdout', 'sha256': '86d3c08fca966faa8c89030321be891b5585ed94bf4f73fd9e05059792995ca5', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/13-normal-release-build.stdout'}, {'bytes': 12124, 'destination': 'provenance/13-normal-release-build.stderr', 'mode': 384, 'name': '13-normal-release-build.stderr', 'sha256': '3af0957a299738eed655d7b639971e05b8cf1c5462e44e66d49c70f1d2465ede', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/build-test-r1/13-normal-release-build.stderr'}, {'bytes': 33147, 'destination': 'control/x230_current_candidate_qualification.py', 'mode': 384, 'name': 'x230_current_candidate_qualification.py', 'sha256': '448696002a72dbca1c9d2b070d826a34aac4ef0bc4ad7c3e77feab7a66fa7655', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/x230_current_candidate_qualification.py'}, {'bytes': 22881, 'destination': 'control/x230_native_abi_capture.py', 'mode': 384, 'name': 'x230_native_abi_capture.py', 'sha256': '3f49130cc7dbf5c1a9bde8e0a83d26a7280d41eb59b03fb9c5f48a0dc7a1cd63', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/x230_native_abi_capture.py'}, {'bytes': 14323, 'destination': 'control/x230_native_abi_admission.py', 'mode': 384, 'name': 'x230_native_abi_admission.py', 'sha256': '1b6594238cfaf26a2411ec422a858f9958626c98e2d5dece8464f24ee8ed73b4', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/x230_native_abi_admission.py'}, {'bytes': 26131, 'destination': 'control/kv2_dr_process_custody.py', 'mode': 384, 'name': 'kv2_dr_process_custody.py', 'sha256': '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/kv2_dr_process_custody.py'}, {'bytes': 729, 'destination': 'provenance/producer-abi.terminal.exact-tool-text.json', 'mode': 384, 'name': 'producer-abi.terminal.exact-tool-text.json', 'sha256': '0f71a30b723ec5a58882d95bfbe88395553c97f4cd038058bdbc10cdf32e6051', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/producer-abi.terminal.exact-tool-text.json'}, {'bytes': 729, 'destination': 'provenance/x230-static-abi.terminal.exact-tool-text.json', 'mode': 384, 'name': 'x230-static-abi.terminal.exact-tool-text.json', 'sha256': '083e3abfb39cbe4edb4270ebb5802906a59cb322192500723820bd6a51771f1c', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/x230-static-abi.terminal.exact-tool-text.json'}, {'bytes': 8158, 'destination': 'provenance/transfer.manifest.public.json', 'mode': 384, 'name': 'transfer.manifest.public.json', 'sha256': '782e3048c803228436ee0a8a0b71b61794c59df0b4e1707a4b2e2d0a0f26ca02', 'source': '/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/current-x230-public-artifact-export-r1/transfer.manifest.public.json'}]

def need(ok, label):
    if not ok:
        raise RuntimeError(label)

def ident(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def file_pin(path, size=None, digest=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= 128 * 1024 * 1024, 'bounded_regular_file_pin')
        h = hashlib.sha256()
        total = 0
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            total += len(data)
            need(total <= before.st_size and time.monotonic() < DEADLINE, 'bounded_original_file_and_deadline')
            h.update(data)
        need(total == before.st_size and ident(before) == ident(os.fstat(fd)) == ident(path.lstat()), 'file_changed_during_pin')
        need((size is None or before.st_size == size)
             and (digest is None or h.hexdigest() == digest), 'file_pin_mismatch')
        return {'bytes': before.st_size, 'sha256': h.hexdigest(), 'uid': before.st_uid,
                'mode': stat.S_IMODE(before.st_mode)}
    finally:
        os.close(fd)

def write_exclusive(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def ssh_argv(alias, code):
    need(alias in ('pocket4', 'x230'), 'existing_alias_only')
    remote = shlex.join(['/usr/bin/python3', '-I', '-S', '-B', '-c', code])
    return [SSH, *SSH_ARGS, alias, remote]

def run(label, alias, code, stdout_path, *, stdin_path=None, seconds=180):
    remaining = DEADLINE - time.monotonic()
    need(remaining > 0, 'relay_absolute_deadline')
    cap = min(seconds, remaining)
    errpath = OUT / (label + '.stderr')
    row = {'label': label, 'alias': alias, 'budget_seconds': cap, 'attempts': 1,
           'timed_out': False, 'owned_ssh_session_signals': [],
           'remote_mutation_dispatched': alias == 'x230' and label != 'verify-x230-delivery'}
    proc = None
    incoming = None
    try:
        incoming = stdin_path.open('rb') if stdin_path is not None else None
        with stdout_path.open('xb') as outstream, errpath.open('xb') as errstream:
            try:
                proc = subprocess.Popen(ssh_argv(alias, code),
                                        stdin=incoming if incoming is not None else subprocess.DEVNULL,
                                        stdout=outstream, stderr=errstream, start_new_session=True)
                row['pid'] = proc.pid
                try:
                    row['exit_code'] = proc.wait(timeout=cap)
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    raise
            finally:
                if proc is not None and proc.poll() is None:
                    need(os.getpgid(proc.pid) == proc.pid, 'owned_ssh_process_group')
                    for sig, budget in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
                        try:
                            os.killpg(proc.pid, sig)
                            row['owned_ssh_session_signals'].append(signal.Signals(sig).name)
                        except ProcessLookupError:
                            break
                        try:
                            proc.wait(timeout=budget)
                            break
                        except subprocess.TimeoutExpired:
                            pass
                    need(proc.poll() is not None, 'owned_ssh_parent_retired')
                outstream.flush()
                errstream.flush()
                os.fsync(outstream.fileno())
                os.fsync(errstream.fileno())
    finally:
        if incoming is not None:
            incoming.close()
        if stdout_path.exists():
            row['stdout'] = file_pin(stdout_path)
        if errpath.exists():
            row['stderr'] = file_pin(errpath)
        row['remote_effects_unknown'] = row['remote_mutation_dispatched'] and row.get('exit_code') != 0
        if row['remote_effects_unknown']:
            REPORT['remote_effects_unknown'] = True
        REPORT['steps'].append(row)
    need(row.get('exit_code') == 0 and not row['timed_out'], label + '_failed')
    return row

def main():
    os.umask(0o077)
    parent=PARENT.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid()
         and not parent.st_mode&0o022 and PARENT.resolve()==PARENT,'actual_owned_mac_parent')
    OUT.mkdir(mode=0o700)
    try:
        need(platform.system()=='Darwin' and os.getuid()==501
             and str(Path(sys.executable).resolve())==str(Path(PYTHON).resolve()),'fixed_mac_python_and_host')
        REPORT['tools_before']={path:file_pin(path,*pin) for path,pin in TOOL_PINS.items()}
        names=[r['name'] for r in FILES];destinations=[r['destination'] for r in FILES]
        need(len(FILES)==19 and len(set(names))==19 and len(set(destinations))==19,'closed_nineteen_public_files')
        for row in FILES:
            need(Path(row['name']).name==row['name'] and row['name'] not in ('','.','..')
                 and len(Path(row['destination']).parts)==2
                 and Path(row['destination']).parts[0] in ('artifacts','provenance','control')
                 and Path(row['destination']).name==row['name'],'closed_literal_destination')
            need(row['mode']==(0o700 if row['destination'].startswith('artifacts/') else 0o600),
                 'binary_or_public_provenance_mode')
            code=REMOTE_COMMON+('need(platform.node()=="alex-G1628-04" and os.getuid()==1000,"exact_producer")\n'
                'data=read_file(Path('+repr(row['source'])+'),'+str(row['bytes'])+','+repr(row['sha256'])+')\n'
                'sys.stdout.buffer.write(data);sys.stdout.buffer.flush()\n')
            run('download-'+row['name'],'pocket4',code,OUT/row['name'])
            file_pin(OUT/row['name'],row['bytes'],row['sha256'])
        prepare=REMOTE_COMMON+('need(platform.node()=="qian-ThinkPad-X230" and os.getuid()==1000,"exact_receiver")\n'
            'parent=Path("/home/qian");directory(parent)\n'
            'proof=json.loads(read_file(Path('+repr(ABI_RECEIPT)+'),313210,'+repr(ABI_SHA)+'))\n'
            'need(proof.get("status")=="passed" and proof.get("role")=="receiver" and proof.get("static_receiver_compatibility_qualified") is True,"actual_static_receiver_proof")\n'
            'dest=Path('+repr(RECEIVER_ROOT)+');dest.mkdir(mode=0o700);directory(dest)\n'
            'for name in ("artifacts","provenance","control"):(dest/name).mkdir(mode=0o700)\n'
            'print(json.dumps({"status":"created","private_mode":448}),flush=True)\n')
        run('prepare-x230-root','x230',prepare,OUT/'prepare-x230-root.stdout',seconds=30)
        REPORT['transferred_files']=[]
        for row in FILES:
            file_pin(OUT/row['name'],row['bytes'],row['sha256'])
            code=REMOTE_COMMON+('root=Path('+repr(RECEIVER_ROOT)+');directory(root)\n'
                'dest=root/'+repr(row['destination'])+';directory(dest.parent)\n'
                'size='+str(row['bytes'])+';expected='+repr(row['sha256'])+';mode='+str(row['mode'])+'\n'
                'h=hashlib.sha256();total=0\n'
                'with dest.open("xb") as f:\n'
                ' while True:\n'
                '  data=sys.stdin.buffer.read(min(1048576,size-total+1))\n'
                '  if not data:break\n'
                '  total+=len(data);need(total<=size,"received_bytes_exceed_pin");h.update(data);f.write(data)\n'
                ' need(total==size and h.hexdigest()==expected,"received_whole_hash");f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)\n'
                'read_file(dest,size,expected)\n'
                'need(stat.S_IMODE(dest.lstat().st_mode)==mode,"exact_receiver_file_mode")\n'
                'print(json.dumps({"status":"received","bytes":size,"sha256":expected,"mode":mode}),flush=True)\n')
            status_path=OUT/('upload-'+row['name']+'.stdout')
            run('upload-'+row['name'],'x230',code,status_path,stdin_path=OUT/row['name'])
            status=json.loads(status_path.read_bytes())
            need(status=={'status':'received','bytes':row['bytes'],'sha256':row['sha256'],'mode':row['mode']},
                 'receiver_whole_file_readback')
            file_pin(OUT/row['name'],row['bytes'],row['sha256'])
            REPORT['transferred_files'].append({'name':row['name'],'destination':row['destination'],
                'bytes':row['bytes'],'sha256':row['sha256'],'mode':row['mode'],
                'source_mac_receiver_hashes_equal':True})
        verify=REMOTE_COMMON+('root=Path('+repr(RECEIVER_ROOT)+');directory(root)\n'
            'rows=json.loads('+repr(json.dumps(FILES,separators=(',',':')))+')\n'
            'need({p.name for p in root.iterdir()}=={"artifacts","provenance","control"},"closed_new_receiver_root")\n'
            'for folder in ("artifacts","provenance","control"):\n'
            ' directory(root/folder)\n'
            ' need({p.name for p in (root/folder).iterdir()}=={r["name"] for r in rows if r["destination"].startswith(folder+"/")},"closed_receiver_members")\n'
            'for row in rows:\n'
            ' path=root/row["destination"];read_file(path,row["bytes"],row["sha256"])\n'
            ' need(stat.S_IMODE(path.lstat().st_mode)==row["mode"],"final_private_file_mode")\n'
            'print(json.dumps({"status":"complete_public_delivery","files":len(rows),"product_binary_executions":0}),flush=True)\n')
        run('verify-x230-delivery','x230',verify,OUT/'verify-x230-delivery.stdout',seconds=60)
        final=json.loads((OUT/'verify-x230-delivery.stdout').read_bytes())
        need(final=={'status':'complete_public_delivery','files':19,'product_binary_executions':0},'exact_closed_receiver_result')
        REPORT['tools_after']={path:file_pin(path,*pin) for path,pin in TOOL_PINS.items()}
        need(REPORT['tools_after']==REPORT['tools_before'],'mac_tools_unchanged')
        REPORT.update(status='transferred_and_verified',all_transferred_whole_hashes_equal=True,
                      receiver=final,remote_effects_unknown=False)
    except BaseException as error:
        REPORT.update(status='failed',failure=str(error) if isinstance(error,RuntimeError) else type(error).__name__)
    REPORT['elapsed_seconds']=time.monotonic()-START
    write_exclusive(OUT/'result.public.json',(json.dumps(REPORT,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({'status':REPORT['status'],'result':str(OUT/'result.public.json'),
        'remote_effects_unknown':REPORT['remote_effects_unknown'],'product_binary_executions':0}),flush=True)
    return 0 if REPORT['status']=='transferred_and_verified' else 1

if __name__=='__main__':
    raise SystemExit(main())
