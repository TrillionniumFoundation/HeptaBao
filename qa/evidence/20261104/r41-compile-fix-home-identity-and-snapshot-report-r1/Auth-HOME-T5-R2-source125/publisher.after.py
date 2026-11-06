#!/usr/bin/env python3
"""Create fresh T5 ROOT plus HOME public controls, 22 sources and eight public documents.

No current credentials, production SQLite, consumer, manager or server is read
or executed. Three pinned import-safe custody libraries are loaded from the
already verified stdin bytes to guard diskutil and descriptor-relative writes.
The finite HomeControl definition creates two public wrapper copies only. No
wrapper, manager, SDK or candidate entrypoint executes during this publisher.
"""
from __future__ import annotations
import ast, base64, hashlib, json, os, re, select, signal, stat, sys, time, types
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+45.0
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2')
QA=ROOT/'qa'
PROOFS=ROOT/'proofs'
PINS={
    "mac_auth_rows_cas_r1.mjs": [
        3108,
        "f77ecb7fd607b2cc377619e050f89c7460420df96d42110de142bdadbf33ce73"
    ],
    "mac_authbus_cache_cas_r1.mjs": [
        6846,
        "91644b97ae7deb4ede468832d3f91646bb00cd919149a510bfffe38d23544af8"
    ],
    "mac_capture_sqlite_synthetic_r1.py": [
        16476,
        "108f956eb3779fce31e01d630547344e22362839041afecb3821bf8053ff392c"
    ],
    "mac_capture_sqlite_synthetic_r2.py": [
        16915,
        "f3c6bb336814411aa4a24490f0904cdbd0fac2bb89dbcc36d6151ada13a51ba2"
    ],
    "mac_current_capture_entry_wal_r1.py": [
        42083,
        "f13e9a727d51d91184e97ee0b2042824706664db5ac7366ee7adf26bffa43203"
    ],
    "mac_current_cycle_r2.mjs": [
        24012,
        "04ab9aab3b6ee292835c97f2b208c054e3089814ecc40a493ce21a157e41f092"
    ],
    "mac_current_fixture_materializer_r1.py": [
        25973,
        "070642a2fecc974794ace1b1cba8eac4672b789aecd4d00a3b4944fb773e853e"
    ],
    "mac_current_outer_inputs_r2.py": [
        33001,
        "cd7fcc48fc6eff9c4d166eab996e40723e6918fabf4815e55e2080096129734d"
    ],
    "mac_current_outer_wal_r1.py": [
        73918,
        "c67d6fe6444e52acfa909912232233e893aa1e1e7278dbb8fe5793a84c50f0a7"
    ],
    "mac_current_phase_owner_r2.py": [
        25647,
        "3a28e7877782e8627a41a41c62973ee348d89e96a8bb05b0abe8ad52c792c855"
    ],
    "mac_current_server_owner_r1.py": [
        14052,
        "34aa6a9799419573dfc8cf6b63f479162b3e9e316dc391d54c5f0c0c54cdedb1"
    ],
    "mac_darwin_owned_projection_r1.py": [
        12858,
        "77b63286d79827671009d56d238494c472f37e3674bf903ab2da092b42733740"
    ],
    "mac_guarded_current_capture_r3.py": [
        23578,
        "606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693"
    ],
    "mac_native_owned_commands_r1.py": [
        5972,
        "717feff0a8719a6c208b14aa1598cefd59881fffa09d19c781a89689b025b9cd"
    ],
    "mac_native_owned_unreaped_r1.py": [
        10761,
        "880794d5e0f01f45e9c559688b2ebd33c2c96399124ea3ecb9e58720a2424d0c"
    ],
    "mac_native_process_observer_r1.py": [
        13423,
        "cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b"
    ],
    "mac_owned_commands_r1.py": [
        5965,
        "eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867"
    ],
    "mac_owned_launchd_r3.py": [
        58452,
        "8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4"
    ],
    "mac_owned_unreaped_r1.py": [
        10990,
        "a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d"
    ],
    "mac_registry_readonly_wal_r1.py": [
        31776,
        "60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed"
    ],
    "mac_single_native_r2.mjs": [
        33148,
        "d89f77d412c4394b40f0eba09e17354234cf7362b79bf1450521ff0a390b33ef"
    ],
    "mac_t5_volume_guard_r1.py": [
        13392,
        "1480cc85311f39a037ccd7ab3f7bb51b847fbd1211eccb77d92b4d3e592d4dd7"
    ]
}
DOCUMENT_PINS={
    "candidate-current-manager-wal-r1.public.json": [
        7499,
        "4194d61794ec066d23ca17863d2323674a918779f9524cf20fb2109e334d1e56"
    ],
    "proofs/native-proc-r2.authority.public.json": [
        733,
        "411ea26371219c49547abc014464585551ba4a69b70bb906b92561a8d5bddf23"
    ],
    "proofs/native-proc-r2.child-stdout.public.json": [
        11066,
        "bb5717753866c0d7e647e4fd5c18a3342db0f530016cc7d92cb508c955ff8644"
    ],
    "proofs/native-proc-r2.stdout.public.json": [
        24032,
        "7a1b715e595a2badf18e4f01506cca2ee7c4c0a760c5ef3c86708a435ace9c4f"
    ],
    "proofs/registry-wal-r1.authority.public.json": [
        733,
        "b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f"
    ],
    "proofs/registry-wal-r1.stdout.public.json": [
        62662,
        "7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82"
    ],
    "proofs/synthetic-r2.authority.public.json": [
        733,
        "1b33a9144712ac2bc3d16d87bb2a9ea1c2e4c0be236dfd08d8b599f7518942dd"
    ],
    "proofs/synthetic-r2.stdout.public.json": [
        16228,
        "6c14a7f95e4f059090da2e88a3fff80eac79c1d83ef58a29df3cc67a610cd8f5"
    ]
}
PAYLOAD_BYTES=837520
PAYLOAD_SHA="f68c2a291856da7fe9d2145d420b16fbcd68f1b9b165af509f9881bd996ba423"
ANCHOR_SHA='dd6dce82fb0276d7c0fd181152aef07bb2857e47506311f70ae67cce41b1eab8'
protected=0;pending=None
class Refused(RuntimeError):pass
ManagerRefused=Refused
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def remaining():
    need(pending is None,'inert_cancelled')
    left=UNTIL-time.monotonic();need(left>0,'original_inert45_exhausted');return left
def on_signal(signum,_frame):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def file_identity(s):
    return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))


HOME_CONTROL=Path('/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2')
HOME_COPY_NAMES=('mac_current_server_owner_r1.py','mac_current_phase_owner_r2.py')
HOME_GENERATIONS=('server-initial','server-cold-new-process','initial',
                  'cold-new-process','initial-inverse','cold-new-process-inverse')
HOME_FD_ATTEMPTS=64
HOME_METADATA_CALLS=4096
HOME_READ_CALLS=256
HOME_READ_BYTES=2*1024*1024
HOME_WRITE_CALLS=64
HOME_WRITE_BYTES=131072

class HomeControl:
    """Finite public launchd controls; private plans and business data stay on T5."""
    def __init__(self,*,remaining,critical,copy_pins,binding=None,create=False):
        self.rows=[];self.parents=[];self.root_row=None;self.files={}
        self.open_attempts=0;self.open_pending=0;self.registration_unknown=False
        self.close_errors=[];self.closed=False;self.init_started=True;self.init_complete=False;self.io_ready=False
        self.root_creation_attempted=False;self.root_created=False;self.effect_unknown=False
        self.last_own_create_root_observation=None
        self.counts={'metadata':0,'readCalls':0,'readBytes':0,'writeCalls':0,'writeBytes':0}
        self.remaining=remaining;self.critical=critical;self.create=create
        self.copy_pins=dict(copy_pins);self.root_identity=None
        need(type(create) is bool and set(self.copy_pins)==set(HOME_COPY_NAMES),
             'home_exact_copy_inventory')
        need(all(isinstance(p,(list,tuple)) and len(p)==2 and type(p[0]) is int
             and 0<p[0]<=1048576 and isinstance(p[1],str)
             and re.fullmatch(r'[0-9a-f]{64}',p[1]) for p in self.copy_pins.values()),
             'home_copy_size_hash_contract')
        need((create and binding is None) or (not create and isinstance(binding,dict)),
             'home_create_or_actual_binding')
        if not create:
            need(set(binding)=={'schema','root','parents','copies'}
                 and binding['schema']=='heptabao.mac-owned-home-control-binding.r1'
                 and set(binding['root'])=={'path','identity'}
                 and binding['root']['path']==str(HOME_CONTROL)
                 and isinstance(binding['parents'],list) and len(binding['parents'])==3
                 and set(binding['copies'])==set(HOME_COPY_NAMES),'home_exact_actual_binding')
        chain=(Path('/'),Path('/Users'),Path('/Users/qianqi'))
        for index,path in enumerate(chain):
            self.remaining()
            parent=None if index==0 else self.parents[-1]['fd']
            row=self._open(str(path) if index==0 else path.name,
                os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                parent=parent,path=path,kind='shared_parent')
            info=self._fstat(row['fd']);named=self._stat(path if index==0 else path.name,parent)
            ident=file_identity(info)
            need(ident==file_identity(named) and stat.S_ISDIR(info.st_mode)
                 and info.st_uid in (0,501) and not stat.S_IMODE(info.st_mode)&0o022,
                 'home_parent_fd_name_owner_mode')
            row['identity']=ident;self.parents.append(row)
            if not create:
                expected=binding['parents'][index]
                need(set(expected)=={'path','identity'} and expected['path']==str(path)
                     and self._identity(expected['identity'])[:5]==ident[:5],
                     'home_parent_actual_first5_binding')
        parent=self.parents[-1]['fd']
        self._check_parents()
        if create:
            for _ in range(2):
                self.remaining()
                try:self._stat(HOME_CONTROL.name,parent)
                except FileNotFoundError:pass
                else:raise ManagerRefused('home_create_only_root_already_exists')
            self._check_parents()
            with self.critical():
                self.remaining();self.root_creation_attempted=True;self.effect_unknown=True
                os.mkdir(HOME_CONTROL.name,0o700,dir_fd=parent)
                self.root_created=True
        self.root_row=self._open(HOME_CONTROL.name,
            os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
            parent=parent,path=HOME_CONTROL,kind='owned_root')
        info=self._fstat(self.root_row['fd']);named=self._stat(HOME_CONTROL.name,parent)
        ident=file_identity(info)
        need(ident==file_identity(named) and stat.S_ISDIR(info.st_mode)
             and info.st_uid==501 and info.st_gid==20 and stat.S_IMODE(info.st_mode)==0o700,
             'home_owned_root_fd_name_mode')
        self.root_row['identity']=ident;self.root_identity=ident
        if not create:
            need(ident==self._identity(binding['root']['identity']),'home_actual_root_full9_before_effects')
            for name in HOME_COPY_NAMES:
                entry=binding['copies'][name]
                need(set(entry)=={'path','identity','bytes','sha256'}
                     and entry['path']==str(HOME_CONTROL/name)
                     and entry['bytes']==self.copy_pins[name][0]
                     and entry['sha256']==self.copy_pins[name][1],'home_actual_copy_binding')
                identity=self._identity(entry['identity'])
                self.files[name]={'kind':'copy','identity':identity,
                    'bytes':entry['bytes'],'sha256':entry['sha256']}
            self.io_ready=True
            for name in HOME_COPY_NAMES:
                need(sha(self.read(HOME_CONTROL/name,1048576))==self.copy_pins[name][1],
                     'home_actual_copy_whole_before_private_inputs')
        else:self.io_ready=True
        self.effect_unknown=False;self.check();self.remaining();self.init_complete=True

    @staticmethod
    def _identity(value):
        need(isinstance(value,(list,tuple)) and len(value)==9
             and all(isinstance(x,str) and re.fullmatch(r'[0-9]{1,30}',x) for x in value),
             'home_full9_decimal_strings')
        return tuple(value)

    def _metadata(self):
        need(self.counts['metadata']<HOME_METADATA_CALLS,'home_metadata_bound')
        self.counts['metadata']+=1

    def _fstat(self,fd):
        self._metadata();return os.fstat(fd)

    def _stat(self,name,parent=None):
        self._metadata()
        return os.stat(name,dir_fd=parent,follow_symlinks=False)

    def _open(self,name,flags,*,parent,path,kind,mode=0o600):
        self.remaining()
        with self.critical():
            need(self.open_attempts<HOME_FD_ATTEMPTS,'home_fd_attempt_bound')
            self.open_attempts+=1;self.open_pending+=1
            try:fd=os.open(name,flags,mode,dir_fd=parent)
            except OSError:
                self.open_pending-=1
                raise
            try:
                row={'fd':fd,'path':str(path),'kind':kind,
                     'closeAttempted':False,'closed':False}
                self.rows.append(row);self.open_pending-=1
            except BaseException:
                self.registration_unknown=True
                raise
        return row

    def _close_one(self,row):
        if row['closeAttempted']:return
        with self.critical():
            row['closeAttempted']=True
            try:os.close(row['fd']);row['closed']=True
            except BaseException as error:
                self.close_errors.append({'path':row['path'],'type':type(error).__name__,
                                          'errno':getattr(error,'errno',None)})

    def _check_parents(self):
        for index,row in enumerate(self.parents):
            info=self._fstat(row['fd'])
            named=self._stat(Path(row['path']) if index==0 else Path(row['path']).name,
                             None if index==0 else self.parents[index-1]['fd'])
            actual=file_identity(info)
            need(actual==file_identity(named) and actual[:5]==row['identity'][:5],
                 'home_shared_parent_held_named_first5')

    def check(self,*,check_deadline=True):
        if check_deadline:self.remaining()
        need(self.io_ready and not self.closed and self.root_row is not None,
             'home_initialized_held_root')
        self._check_parents()
        info=self._fstat(self.root_row['fd'])
        named=self._stat(HOME_CONTROL.name,self.parents[-1]['fd'])
        need(file_identity(info)==file_identity(named)==self.root_identity,
             'home_owned_root_held_named_current_full9')
        for name,row in self.files.items():
            actual=file_identity(self._stat(name,self.root_row['fd']))
            expected=row['identity']
            need((actual[:6]==expected[:6] if row['kind']=='stdio' else actual==expected),
                 'home_fixed_leaf_identity')
        if check_deadline:self.remaining()

    def _name(self,path):
        path=Path(path)
        need(path.is_absolute() and path.parent==HOME_CONTROL
             and path==Path(os.path.normpath(str(path))),'home_fixed_flat_path')
        name=path.name
        allowed=set(HOME_COPY_NAMES)|{g+s for g in HOME_GENERATIONS
                                    for s in ('.plist','.stdout.private','.stderr.private')}
        need(name in allowed,'home_finite_leaf_name')
        return name

    def write_new(self,path,raw,*,copy=False):
        self.remaining();self.check()
        name=self._name(path)
        need(isinstance(raw,bytes) and len(raw)<=65536 and name not in self.files
             and not self.effect_unknown,'home_bounded_once_create')
        need((self.create and copy and name in HOME_COPY_NAMES)
             or (not self.create and not copy and name not in HOME_COPY_NAMES),
             'home_exact_write_role')
        kind='copy' if copy else ('stdio' if name.endswith('.private') else 'plist')
        need(kind!='stdio' or raw==b'','home_precreated_empty_stdio_only')
        need(self.counts['writeBytes']+len(raw)<=HOME_WRITE_BYTES,'home_total_write_bound')
        self.effect_unknown=True
        row=self._open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                       parent=self.root_row['fd'],path=path,kind='write')
        try:
            before=self._fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_gid==20
                 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                 and before.st_size==0,'home_new_regular_600')
            offset=0
            while offset<len(raw):
                self.remaining()
                need(self.counts['writeCalls']<HOME_WRITE_CALLS,'home_write_call_bound')
                self.counts['writeCalls']+=1
                amount=os.write(row['fd'],raw[offset:])
                need(type(amount) is int and 0<amount<=len(raw)-offset,'home_write_progress')
                offset+=amount;self.counts['writeBytes']+=amount
            os.fsync(row['fd']);self.remaining()
            info=self._fstat(row['fd']);named=self._stat(name,self.root_row['fd'])
            identity=file_identity(info)
            need(identity==file_identity(named) and identity[:6]==file_identity(before)[:6]
                 and info.st_size==len(raw),'home_created_leaf_full9')
            result={'kind':kind,'identity':identity,'bytes':len(raw),'sha256':sha(raw)}
            self.files[name]=result
            os.fsync(self.root_row['fd']);self.remaining()
            current=file_identity(self._fstat(self.root_row['fd']))
            named_root=file_identity(self._stat(HOME_CONTROL.name,self.parents[-1]['fd']))
            before_root=self.root_identity
            self.last_own_create_root_observation={
                'beforeFull9':list(before_root),'currentFull9':list(current),
                'namedFull9':list(named_root),'heldNamedFull9Equal':current==named_root,
                'sameRootObjectFirst5':current[:5]==before_root[:5],
                'fieldEqualToBefore':[x==y for x,y in zip(current,before_root)]}
            need(current==named_root and current[:5]==before_root[:5],
                 'home_own_create_preserves_root_object')
            self.root_identity=current
            self.effect_unknown=False
            return {'path':str(path),'identity':list(identity),'bytes':len(raw),'sha256':sha(raw)}
        finally:
            self._close_one(row)
            self.remaining()
            need(row['closed'],'home_write_fd_close_known')

    def _read(self,fd,count,offset=None):
        self.remaining()
        need(type(count) is int and 0<count<=65536 and self.counts['readCalls']<HOME_READ_CALLS
             and self.counts['readBytes']+count<=HOME_READ_BYTES,'home_read_remaining_bound')
        self.counts['readCalls']+=1
        raw=os.read(fd,count) if offset is None else os.pread(fd,count,offset)
        self.counts['readBytes']+=len(raw)
        need(len(raw)<=count,'home_read_return_bound');self.remaining()
        return raw

    def read(self,path,maximum=2*1024*1024):
        self.remaining();self.check()
        name=self._name(path);entry=self.files.get(name)
        need(entry is not None and not name.endswith('.stderr.private')
             and type(maximum) is int and 0<maximum<=2*1024*1024
             and not self.effect_unknown,'home_finite_body_read')
        row=self._open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                       parent=self.root_row['fd'],path=path,kind='read')
        try:
            info=self._fstat(row['fd']);before=file_identity(info)
            need(stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_gid==20
                 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
                 and 0<=info.st_size<=maximum
                 and (before[:6]==entry['identity'][:6] if entry['kind']=='stdio'
                      else before==entry['identity']),'home_read_leaf_custody')
            need(self.counts['readBytes']+info.st_size+1<=HOME_READ_BYTES,
                 'home_read_whole_plus_eof_remaining')
            raw=bytearray()
            while len(raw)<info.st_size:
                block=self._read(row['fd'],min(65536,info.st_size-len(raw)))
                need(bool(block),'home_nonempty_progress');raw.extend(block)
            need(self._read(row['fd'],1)==b'','home_whole_eof')
            after=file_identity(self._fstat(row['fd']))
            named=file_identity(self._stat(name,self.root_row['fd']))
            need(len(raw)==info.st_size and before==after==named,'home_read_full9_interval')
            if entry['kind']!='stdio':
                need(sha(raw)==entry['sha256'],'home_known_file_whole_hash')
            self.check();return bytes(raw)
        finally:
            self._close_one(row)
            self.remaining()
            need(row['closed'],'home_read_fd_close_known')

    def prefix(self,path):
        self.remaining();self.check()
        name=self._name(path);entry=self.files.get(name)
        need(name in ('server-initial.stdout.private','server-cold-new-process.stdout.private')
             and entry is not None and entry['kind']=='stdio' and not self.effect_unknown,
             'home_only_two_server_public_prefixes')
        row=self._open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                       parent=self.root_row['fd'],path=path,kind='prefix')
        try:
            first=self._fstat(row['fd'])
            need(file_identity(first)[:6]==entry['identity'][:6]
                 and 0<first.st_size<=2*1024*1024,'home_server_prefix_size_identity')
            block=self._read(row['fd'],min(65536,first.st_size),0)
            position=block.find(b'\n');need(position>=0,'complete_wrapper_prefix')
            raw=block[:position+1]
            need(self._read(row['fd'],len(raw),0)==raw,'wrapper_prefix_same_fd_exact')
            after=self._fstat(row['fd']);named=self._stat(name,self.root_row['fd'])
            need(file_identity(first)[:6]==file_identity(after)[:6]==file_identity(named)[:6]
                 and first.st_size<=after.st_size<=2*1024*1024
                 and named.st_size>=len(raw),'server_stdout_name_and_prefix_fence')
            self.check();return raw
        finally:
            self._close_one(row)
            self.remaining()
            need(row['closed'],'home_prefix_fd_close_known')

    def actual_binding(self):
        need(self.create and set(self.files)==set(HOME_COPY_NAMES),'home_stage_copy_set')
        self.check()
        return {'schema':'heptabao.mac-owned-home-control-binding.r1',
            'root':{'path':str(HOME_CONTROL),'identity':list(self.root_identity)},
            'parents':[{'path':r['path'],'identity':list(r['identity'])} for r in self.parents],
            'copies':{name:{'path':str(HOME_CONTROL/name),'identity':list(self.files[name]['identity']),
                'bytes':self.files[name]['bytes'],'sha256':self.files[name]['sha256']}
                for name in HOME_COPY_NAMES}}

    def leaf_closure_known(self):
        return bool(self.init_complete and self.open_pending==0 and not self.registration_unknown
            and not self.effect_unknown and not self.close_errors
            and all(r['closed'] for r in self.rows if r['kind'] not in ('shared_parent','owned_root')))

    def close(self):
        if self.closed:return self.public()
        with self.critical():
            for row in reversed(self.rows):self._close_one(row)
            self.closed=True
        return self.public()

    def public(self):
        return {'schema':'heptabao.mac-owned-home-control-closure.r1',
            'path':str(HOME_CONTROL),
            'currentRootIdentity':None if self.root_identity is None else list(self.root_identity),
            'lastOwnCreateRootObservation':self.last_own_create_root_observation,
            'initStarted':self.init_started,
            'initComplete':self.init_complete,'rootCreationAttempted':self.root_creation_attempted,
            'rootCreated':self.root_created,'effectUnknown':self.effect_unknown,
            'openAttempts':self.open_attempts,'openPending':self.open_pending,
            'registrationUnknown':self.registration_unknown,'fdRows':[dict(r) for r in self.rows],
            'closeErrors':list(self.close_errors),'counts':dict(self.counts),
            'allReturnedDescriptorsClosed':bool(self.closed and self.init_complete
                and self.open_pending==0 and not self.registration_unknown and not self.close_errors
                and all(r['closed'] for r in self.rows)),
            'allFiniteLeavesClosed':self.leaf_closure_known(),
            'sharedParentsUseFirst5ObjectIdentity':True,
            'directoryContentsExhaustivelyInventoried':False,
            'currentRootFull9UpdatedOnlyAfterOwnExclusiveCreate':True,
            'privateCredentialPlansMovedHere':False,
            'descriptorScope':'returned HomeControl application descriptors only',
            'interpreterAndDynamicLoaderInternalFdsNotEnumerated':True}

def stdin_once():
    need(sys.stdin.fileno()==0,'fixed_stdin')
    os.set_blocking(0,False);parts=[];size=0
    while True:
        readable,_,_=select.select([0],[],[],min(remaining(),0.1))
        if not readable:continue
        raw=os.read(0,min(65536,PAYLOAD_BYTES+1-size))
        if not raw:break
        size+=len(raw);need(size<=PAYLOAD_BYTES,'public_payload_bound');parts.append(raw)
    remaining();return b''.join(parts)
def load_definition_module(name,raw):
    need(name in ('mac_t5_volume_guard_r1.py','mac_owned_unreaped_r1.py','mac_owned_commands_r1.py'),
         'only_reviewed_library_definitions')
    key=name[:-3];need(key not in sys.modules,'fresh_library_namespace')
    module=types.ModuleType(key);module.__file__='<reviewed-stdin:'+name+'>'
    sys.modules[key]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def fresh_root_absent(guard):
    with guard.parent(ROOT) as (parent,name):
        info=os.fstat(parent)
        before=tuple(str(x) for x in (
            info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        observations=[]
        for _ in range(2):
            remaining();guard.check()
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:observations.append(True)
            else:raise Refused('fresh_root_already_exists')
        info=os.fstat(parent)
        after=tuple(str(x) for x in (
            info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        need(before==after,'fresh_root_parent_stable')
        guard.check();remaining()
        return {'path':str(ROOT),'twoEnoentObservations':observations,
                'heldParentIdentity':list(before)}

def publish_public(guard,path,content,expected,kind):
    remaining()
    written=guard.write_new(path,content)
    # write_new closes its write descriptor. This is a separate held read FD.
    readback=guard.read(path,1048576,private=False)
    need(readback==content and written['sha256']==expected[1]
        and written['bytes']==expected[0],'held_whole_public_readback')
    with guard.parent(path) as (parent,name):
        info=os.stat(name,dir_fd=parent,follow_symlinks=False)
        current=[str(x) for x in (info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)]
        need(current==written['identity'] and info.st_uid==501 and info.st_nlink==1
            and info.st_mode&0o7777==0o600,'published_full_identity')
    guard.check();remaining()
    return {'name':str(path.relative_to(ROOT)),'kind':kind,**written,
            'wholeReadbackVerified':True,'readbackUsesSeparateHeldFd':True}

def main():
    os.umask(0o077)
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,on_signal)
    report={'schema':'heptabao.mac-current-home-launch-inert.r1','ok':False,'files':[],'homeCopies':[],
        'currentPrivateInputsOpened':False,'productionSqliteOpened':False,'sqliteExecuted':False,
        'consumerExecuted':False,'serviceStarted':False,'gitStarted':False,'cargoStarted':False,
        'fixedLibraryDefinitionsLoadedOnly':True,'newOriginalInertSeconds':45,
        'sourceCount':22,'publicDocumentCount':8,'compiledPythonCountExpected':18,
        'candidateFileAloneIsNotQualification':True}
    guard=None;commands=None;candidate=None;prepared=False
    home=None;home_init_started=False;home_init_complete=False
    try:
        need(sys.platform=='darwin' and os.getuid()==501,'exact_mac_inert_owner')
        raw=stdin_once()
        need(len(raw)==PAYLOAD_BYTES and sha(raw)==PAYLOAD_SHA,'entire_fixed_public_payload')
        payload=json.loads(raw)
        need(set(payload)=={'schema','files','documents','anchorBase64'}
            and payload['schema']=='heptabao.mac-current-home-launch-inert-public-inputs.r1',
            'exact_public_payload_schema')
        need(isinstance(payload['files'],dict) and set(payload['files'])==set(PINS),'exact_22_sources')
        need(isinstance(payload['documents'],dict) and set(payload['documents'])==set(DOCUMENT_PINS),
             'exact_eight_public_documents')
        decoded={};compiled=[]
        for name,(size,pin) in PINS.items():
            remaining()
            content=base64.b64decode(payload['files'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_source_pin.'+name)
            if name.endswith('.py'):
                compile(ast.parse(content,filename=name),name,'exec');compiled.append(name)
            else:need(name.endswith('.mjs'),'fixed_source_extension')
            decoded[name]=content
        need(len(compiled)==18,'exact_python_compile_count')
        decoded_documents={}
        for name,(size,pin) in DOCUMENT_PINS.items():
            remaining()
            content=base64.b64decode(payload['documents'][name],validate=True)
            need(len(content)==size and sha(content)==pin,'whole_public_document_pin.'+name)
            decoded_documents[name]=content
        contract=json.loads(decoded_documents['candidate-current-manager-wal-r1.public.json'])
        need(contract['sourcePins']=={name:pair[1] for name,pair in PINS.items()}
            and contract['publicVolumeAnchorSha256']==ANCHOR_SHA,'fixed_candidate_source_anchor')
        anchor=base64.b64decode(payload['anchorBase64'],validate=True)
        need(len(anchor)==967 and sha(anchor)==ANCHOR_SHA,'actual_public_t5_anchor')
        report['inputSha256']=sha(raw);report['inputBytes']=len(raw)
        report['compiledSources']=compiled
        report['byteVerifiedJavascriptSources']=[name for name in PINS if name.endswith('.mjs')]
        report['inputEntrypointsExecuted']=False
        custody=load_definition_module('mac_owned_unreaped_r1.py',decoded['mac_owned_unreaped_r1.py'])
        runner=load_definition_module('mac_owned_commands_r1.py',decoded['mac_owned_commands_r1.py'])
        volume=load_definition_module('mac_t5_volume_guard_r1.py',decoded['mac_t5_volume_guard_r1.py'])
        report['loadedLibraryDefinitions']=['mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
                                             'mac_t5_volume_guard_r1.py']
        # The above import-safe libraries contain no import-time process/file
        # action. Only the following fixed, reviewed guard is now called.
        class SignalState:
            @property
            def pending(self):return pending
            def critical(self):return critical()
        commands=runner.Commands(SignalState())
        guard=volume.HeldT5(anchor,ANCHOR_SHA,remaining,critical)
        query,out,_=commands.run('inert-t5-volume',
              ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
              until=min(UNTIL,time.monotonic()+30),maximum=262144)
        need(query['exitCode']==0 and not query['outcomeUnknown'],'actual_prewrite_t5_complete')
        guard.accept_diskutil(out);report['volumeProbe']=query
        report['freshRootAbsence']=fresh_root_absent(guard)
        home_init_started=True;home=HomeControl.__new__(HomeControl)
        home.__init__(remaining=remaining,critical=critical,
            copy_pins={name:PINS[name] for name in HOME_COPY_NAMES},binding=None,create=True)
        home_init_complete=True
        for name in HOME_COPY_NAMES:
            content=decoded[name]
            written=home.write_new(HOME_CONTROL/name,content,copy=True)
            need(home.read(HOME_CONTROL/name,1048576)==content
                 and written['bytes']==PINS[name][0] and written['sha256']==PINS[name][1],
                 'home_staged_copy_separate_held_whole_readback')
            report['homeCopies'].append({'name':name,**written,
                'wholeReadbackVerified':True,'readbackUsesSeparateHeldFd':True})
        report['homeControlBinding']=home.actual_binding()
        report['homePublicOnly']=True;report['privatePlansAndBusinessDataRemainOnT5']=True
        guard.mkdir_new(ROOT);report['createdRoot']=str(ROOT)
        guard.mkdir_new(QA);report['createdQa']=str(QA)
        guard.mkdir_new(PROOFS);report['createdProofs']=str(PROOFS)
        for name,content in decoded.items():
            report['files'].append(publish_public(guard,QA/name,content,PINS[name],'source'))
        for name,content in decoded_documents.items():
            report['files'].append(publish_public(
                guard,ROOT/name,content,DOCUMENT_PINS[name],'public_document'))
        guard.check();remaining()
        prepared=True
        report['preparedCandidate']=True
        receipt=encode(report)
        candidate=publish_public(guard,ROOT/'inert-registry-wal-4e808-result.public.json',
                                 receipt,(len(receipt),sha(receipt)),'inert_candidate_receipt')
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        if home is not None:
            try:home.close();report['homeControlFinal']=home.public()
            except BaseException as error:
                report['homeControlClosureErrorType']=type(error).__name__
        home_closed=bool(home_init_complete
            and report.get('homeControlFinal',{}).get('allReturnedDescriptorsClosed') is True
            and report['homeControlFinal'].get('allFiniteLeavesClosed') is True
            and report['homeControlFinal'].get('effectUnknown') is False)
        report['homeControlInitializationStarted']=home_init_started
        report['homeControlInitializationComplete']=home_init_complete
        report['allReturnedHomeControlDescriptorsClosed']=home_closed
        if guard is not None:
            guard.close();report['heldT5Final']=guard.public_state()
        report['commands']=None if commands is None else commands.public()
        stopped=commands is not None and report['commands']['allOwnedCommandsStopped']
        closed=bool(guard is not None and report['heldT5Final']['allDescriptorsClosed'] and home_closed)
        final_anchor=guard is not None and report['heldT5Final']['lastAnchorCheckPassed']
        report['allOwnedCommandsStopped']=stopped
        report['allOwnedDescriptorsClosed']=closed
        report['outcomeUnknown']=bool(pending is not None or (commands is not None
            and report['commands']['unknownCommandCount']) or not stopped or not closed)
        completed=time.monotonic();report['elapsedSeconds']=completed-START
        report['candidateReceiptSha256']=None if candidate is None else candidate['sha256']
        report['candidateReceipt']=candidate
        report['originalDeadlineMetAfterClosure']=completed<UNTIL
        report['authoritativeExitZeroRequired']=True
        report['ok']=bool(prepared and candidate is not None and len(report['files'])==30
            and len(report['homeCopies'])==2 and report.get('homePublicOnly') is True
            and sum(x['kind']=='source' for x in report['files'])==22
            and sum(x['kind']=='public_document' for x in report['files'])==8
            and stopped and closed and final_anchor and not report['outcomeUnknown'] and completed<UNTIL)
        out=encode(report);need(len(out)<=65536,'public_result_bound')
        sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
    return 0 if report['ok'] and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
