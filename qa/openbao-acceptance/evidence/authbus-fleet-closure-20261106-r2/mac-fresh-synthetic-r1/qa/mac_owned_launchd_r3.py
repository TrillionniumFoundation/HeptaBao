#!/usr/bin/env python3
"""Finite owned launchd control for the independent synthetic Mac startup fixture.

Separate qualification derivative; original source retained. Launchd owns wrappers; wrappers own their actual
Popen children. This manager never claims those children are its direct children
and never sends a signal to a numeric PID or process group. Unknown state stops
the operation graph. Failed cleanup cannot become a successful generation.
"""
from __future__ import annotations
import base64, hashlib, json, os, plistlib, re, stat, time
from pathlib import Path
from mac_native_process_observer_r1 import ProcessReader

PYTHON_LAUNCHER = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
PYTHON_KERNEL_IMAGE = "/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1')
QA=ROOT/'qa'
BINDING_READY=True  # Independent synthetic startup scope; canonical 4bde9 normal107 pin.
DOMAIN='gui/501'
LABELS={'server':'org.heptabao.qa.mac-fresh-synthetic-20261106-r1.server',
        'consumer':'org.heptabao.qa.mac-fresh-synthetic-20261106-r1.consumer'}
SERVER=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1/bin/heptabao-server')
SERVER_SHA='5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
GRAPH=(('server-start','server-initial'),('server-kill','server-initial'),
       ('server-start','server-cold-new-process'),('server-kill','server-cold-new-process'))
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
NEW_MANAGER_SECONDS=600.0
NEW_CLEANUP_SECONDS=60.0
NEW_WRAPPER_READY_SECONDS=30.0
NEW_EXEC_OBSERVATION_SECONDS=10.0
NEW_FAILURE_TERM_GRACE_SECONDS=20.0
MAX_COMMANDS=4096
NEW_MANAGER_POLL_SECONDS=0.25
QUERY_SECONDS=10.0
PS_SECONDS=4.0

class ManagerRefused(RuntimeError):pass
def need(value,code):
    if not value:raise ManagerRefused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def file_identity(s):
    return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))

def parse_print(raw,target):
    need(isinstance(raw,bytes) and len(raw)<=262144,'bounded_launchctl_print')
    lines=raw.decode('utf-8','strict').splitlines()
    need(1<=len(lines)<=4096 and lines[0].strip()==target+' = {','exact_launchctl_target')
    fields={};arguments=[];depth=1;in_arguments=False;arguments_seen=False
    allowed=('path','program','pid','state','runs','last exit code','last terminating signal')
    for line in lines[1:]:
        text=line.strip()
        if in_arguments:
            if text=='}':
                in_arguments=False;depth-=1;continue
            need(depth==2 and text and '{' not in text and '}' not in text
                 and len(text)<=16384,'plain_fixed_launchctl_argument')
            arguments.append(text)
            need(len(arguments)<=32,'bounded_launchctl_arguments')
            continue
        if depth==1 and text=='arguments = {':
            need(not arguments_seen,'one_launchctl_arguments_block')
            arguments_seen=True;in_arguments=True;depth+=1;continue
        if depth==1 and ' = ' in text and not text.endswith('{'):
            name,value=text.split(' = ',1)
            if name in allowed:
                need(name not in fields,'unique_launchctl_field');fields[name]=value
        depth+=text.count('{')-text.count('}')
        need(depth>=0,'balanced_launchctl_print')
        if depth==0:
            need(text=='}' and line==lines[-1],'one_complete_launchctl_record')
    need(depth==0 and not in_arguments and arguments_seen,'complete_launchctl_arguments')
    for name in ('pid','runs','last exit code'):
        if name in fields:
            typed_value=fields[name]
            if name=='last exit code' and typed_value=='(never exited)':
                # An unexited registration has no successful exit observation.
                # Keep None so actual_launchd_phase_exit_zero still rejects it.
                fields[name]=None
                continue
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
                typed_value='78'
            need(re.fullmatch(r'-?[0-9]{1,10}',typed_value) is not None,'typed_launchctl_integer')
            fields[name]=int(typed_value)
    need('pid' not in fields or fields['pid']>1,'actual_launchctl_pid')
    fields['arguments']=arguments
    return fields

def missing_service(code,out,err,label):
    if code not in (3,113) or out:return False
    try:lines=err.decode('utf-8','strict').splitlines()
    except UnicodeError:return False
    exact='Could not find service "'+label+'" in domain for user gui: 501'
    return lines in ([exact],['Bad request.',exact])


HOME_CONTROL=Path('/Users/qianqi/heptabao-mac-fresh-synthetic-launchd-20261106-r1')
HOME_COPY_NAMES=('mac_current_server_owner_r1.py',)
HOME_GENERATIONS=('server-initial','server-cold-new-process')
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

class OwnedLaunchd:
    def __init__(self,*,guard,commands,signals,until,anchor_raw,anchor_sha256,qa_pins,python_runtime,home_control):
        need(BINDING_READY is True,'mac_normal61_binding_not_admitted')
        now=time.monotonic()
        need(now<until<=now+NEW_MANAGER_SECONDS,'one_new_manager_deadline')
        need(guard.uuid_verified and not guard.closed,'held_t5_before_manager')
        need(isinstance(anchor_raw,bytes) and sha(anchor_raw)==anchor_sha256,'exact_public_anchor')
        need(isinstance(qa_pins,dict) and all(isinstance(k,str) and isinstance(v,str)
             and re.fullmatch(r'[0-9a-f]{64}',v) for k,v in qa_pins.items()),'typed_qa_pins')
        self.guard=guard;self.commands=commands;self.signals=signals;self.until=until
        self.started=now;self.anchor_raw=anchor_raw;self.anchor_sha=anchor_sha256
        self.qa_pins=dict(qa_pins);self.reader=ProcessReader()
        need(isinstance(home_control,HomeControl) and home_control.init_complete
             and not home_control.create,'actual_bound_home_control')
        self.home=home_control;self.home.check()
        self.entries=[];self.graph_index=0;self.events=[];self.unknown=False
        self.failure_cleanup_attempted=False;self.cleanup_until=None
        self.command_count=0;self.finished=False;self.fd_rows=[]
        self._remaining()
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        actual_python=public_code_pin('/opt/homebrew/bin/python3',remaining=self._remaining,
                                      critical=self.signals.critical)
        need(actual_python==python_runtime and actual_python['path']==PYTHON_LAUNCHER,
             'same_actual_synthetic_python_for_wrappers')
        self.python_runtime=dict(actual_python)
        for kind in ('server','consumer'):
            need(self._query(LABELS[kind],None) is None,'owned_label_initially_absent')

    def _remaining(self,until=None,*,cleanup=False):
        if not cleanup:need(self.signals.pending is None,'manager_cancelled')
        bound=self.cleanup_until if cleanup else self.until
        need(bound is not None,'cleanup_deadline_exists')
        if until is not None:bound=min(bound,until)
        left=bound-time.monotonic();need(left>0,'original_manager_or_cleanup_deadline')
        return left

    def _call(self,label,argv,*,until=None,cleanup=False,ps=False):
        self._remaining(until,cleanup=cleanup)
        need(self.command_count<MAX_COMMANDS,'finite_manager_command_count')
        self.command_count+=1
        limit=PS_SECONDS if ps else QUERY_SECONDS
        bound=min(self.cleanup_until if cleanup else self.until,time.monotonic()+limit)
        if until is not None:bound=min(bound,until)
        row,out,err=self.commands.run(label,argv,until=bound,
                                      allow_cancelled_cleanup=cleanup,maximum=262144)
        if row['outcomeUnknown'] or not row['completeBeforeDeadline']:
            self.unknown=True
            raise ManagerRefused('owned_manager_command_unknown')
        self._remaining(until,cleanup=cleanup)
        return row,out,err

    def _query(self,label,entry,*,until=None,cleanup=False):
        need(label in LABELS.values(),'only_two_owned_labels')
        target=DOMAIN+'/'+label
        row,out,err=self._call('launchd-print',['/bin/launchctl','print',target],
                              until=until,cleanup=cleanup)
        if missing_service(row['exitCode'],out,err,label):return None
        need(row['exitCode']==0 and not err,'known_launchctl_query')
        value=parse_print(out,target)
        if entry is not None:
            need(value.get('path')==str(entry['plist'])
                 and value.get('program')==entry['arguments'][0]
                 and value['arguments']==entry['arguments'],'exact_registered_generation')
            need(value.get('runs') in (0,1),'one_launchd_run_only')
        return value

    def _record(self,kind,generation,detail):
        self._remaining()
        value={'schema':'heptabao.mac-owned-launchd-event.r3','index':len(self.events),
               'kind':kind,'generation':generation,'detail':detail}
        path=ROOT/'launchd'/('%03d-%s-%s.public.json'%(len(self.events),generation,kind))
        binding=self.guard.write_new(path,encoded(value))
        self.events.append({'kind':kind,'generation':generation,'path':str(path),**binding})

    def _expect_action(self,kind,generation):
        self._remaining()
        need(not self.finished and self.graph_index<len(GRAPH)
             and GRAPH[self.graph_index]==(kind,generation),'finite_launchd_operation_graph')
        need(not self.unknown,'no_business_after_unknown')

    def _advance(self):
        self._remaining();self.graph_index+=1

    def _plan(self,generation):
        path=ROOT/'launchd'/(generation+'.private.json')
        named_before=file_identity(path.lstat())
        raw=self.guard.read(path)
        need(named_before==file_identity(path.lstat()),'plan_identity_around_whole_read')
        value=json.loads(raw)
        need(isinstance(value,dict) and value.get('generation')==generation,'fixed_generation_plan')
        return path,raw,value

    def _args(self,kind,path,plan_sha):
        common=['--plan',str(path),'--plan-sha256',plan_sha,
            '--public-volume-anchor-base64',base64.b64encode(self.anchor_raw).decode('ascii'),
            '--public-volume-anchor-sha256',self.anchor_sha]
        if kind=='consumer':
            wrapper=QA/'mac_current_phase_owner_r2.py'
            common+=['--volume-guard-source-sha256',self.qa_pins['mac_t5_volume_guard_r1.py']]
        else:
            wrapper=QA/'mac_current_server_owner_r1.py'
            names=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
                   'mac_t5_volume_guard_r1.py','mac_native_process_observer_r1.py')
            raw=encoded({n:self.qa_pins[n] for n in names})
            common+=['--public-source-pins-base64',base64.b64encode(raw).decode('ascii'),
                     '--public-source-pins-sha256',sha(raw)]
        raw=self.guard.read(wrapper,1024*1024)
        need(sha(raw)==self.qa_pins[wrapper.name],'exact_wrapper_before_registration')
        home_wrapper=HOME_CONTROL/wrapper.name
        need(self.home.read(home_wrapper,1048576)==raw,'exact_staged_wrapper_copy_before_registration')
        return [PYTHON_LAUNCHER,'-I','-S','-B',str(home_wrapper),*common]

    def _new_entry(self,kind,generation):
        label=LABELS[kind]
        need(not any(e['label']==label and not e['registrationClosed'] for e in self.entries),
             'previous_owned_registration_closed')
        need(self._query(label,None) is None,'label_absent_before_new_generation')
        path,raw,plan=self._plan(generation)
        argv=self._args(kind,path,sha(raw))
        stdout=HOME_CONTROL/(generation+'.stdout.private')
        stderr=HOME_CONTROL/(generation+'.stderr.private')
        plist=HOME_CONTROL/(generation+'.plist')
        expected={'Label':label,'ProgramArguments':argv,'RunAtLoad':True,'KeepAlive':False,
            'AbandonProcessGroup':False,'ProcessType':'Background','ExitTimeOut':10,'Umask':0o077,
            'WorkingDirectory':str(HOME_CONTROL),'StandardOutPath':str(stdout),
            'StandardErrorPath':str(stderr),
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                    'LANG':'C','LC_ALL':'C'}}
        self.home.write_new(plist,plistlib.dumps(expected,fmt=plistlib.FMT_XML,sort_keys=True))
        named_before=file_identity(plist.lstat())
        actual=self.home.read(plist)
        need(named_before==file_identity(plist.lstat()),'plist_identity_around_whole_read')
        need(plistlib.loads(actual)==expected,'exact_owned_plist_no_keepalive')
        # Precreate both append targets with exact private modes before launchd.
        self.home.write_new(stdout,b'');self.home.write_new(stderr,b'')
        # Only these public-control/stdio paths use HomeControl; private plans stay on T5.
        entry={'kind':kind,'generation':generation,'label':label,'target':DOMAIN+'/'+label,
            'plan':path,'planSha256':sha(raw),'plist':plist,'plistSha256':sha(actual),
            'arguments':argv,'stdout':stdout,'stderr':stderr,'wrapperIdentity':None,
            'execIdentity':None,'groups':set(),'registrationClosed':False,
            'lineagesClosed':False,'completeKnownSuccess':False,'attempts':{},
            'planIdentity':file_identity(path.lstat()),'plistIdentity':file_identity(plist.lstat())}
        cleanup_plan={'schema':'heptabao.mac-owned-launchd-cleanup-intent.r3',
            'generation':generation,'label':label,'target':entry['target'],
            'termArgv':['/bin/launchctl','kill','SIGTERM',entry['target']],
            'killArgv':['/bin/launchctl','kill','SIGKILL',entry['target']],
            'bootoutArgv':['/bin/launchctl','bootout',entry['target']],
            'newCleanupSeconds':NEW_CLEANUP_SECONDS,'noNumericPidOrGroupSignals':True}
        self.guard.write_new(ROOT/'launchd'/(generation+'.cleanup-intent.public.json'),
                             encoded(cleanup_plan))
        self._record('bootstrap-intent',generation,{'planSha256':entry['planSha256'],
            'plistSha256':entry['plistSha256'],'argv':['/bin/launchctl','bootstrap',DOMAIN,str(plist)]})
        self.entries.append(entry)
        return entry

    def _dispatch_once(self,entry,operation,argv,*,until=None,cleanup=False):
        need(operation in ('bootstrap','term','kill','bootout'),'fixed_manager_operation')
        expected={'bootstrap':['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])],
            'term':['/bin/launchctl','kill','SIGTERM',entry['target']],
            'kill':['/bin/launchctl','kill','SIGKILL',entry['target']],
            'bootout':['/bin/launchctl','bootout',entry['target']]}[operation]
        need(argv==expected and operation not in entry['attempts'],'once_exact_manager_dispatch')
        with self.signals.critical():
            self._remaining(until,cleanup=cleanup)
            entry['attempts'][operation]={'attempted':True,'complete':False}
        try:
            row,out,err=self._call('launchd-'+operation,argv,until=until,cleanup=cleanup)
            entry['attempts'][operation].update(complete=True,exitCode=row['exitCode'],
                stdoutSha256=sha(out),stderrSha256=sha(err),command=row)
            need(row['exitCode']==0,'known_launchctl_mutation_success')
            return row
        except BaseException:
            self.unknown=True
            raise

    def _ready(self,entry):
        until=min(self.until,time.monotonic()+NEW_WRAPPER_READY_SECONDS)
        path=ROOT/'launchd'/(entry['generation']+'.ready.public.json')
        while True:
            self._remaining(until)
            state=self._query(entry['label'],entry,until=until)
            need(state is not None,'registration_present_while_waiting_ready')
            try:raw=self.guard.read(path)
            except FileNotFoundError:
                need(state.get('pid') is not None or state.get('runs')==0,'wrapper_did_not_exit_before_ready')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)));continue
            ready=json.loads(raw)
            expected_schema=('heptabao.mac-phase-wrapper-ready.r1' if entry['kind']=='consumer'
                             else 'heptabao.mac-server-wrapper-ready.r1')
            need(isinstance(ready,dict) and ready.get('schema')==expected_schema
                 and ready.get('generation')==entry['generation']
                 and ready.get('planSha256')==entry['planSha256'],'typed_wrapper_ready')
            identity=ready.get('wrapperIdentity')
            need(isinstance(identity,dict) and type(identity.get('pid')) is int
                 and state.get('pid')==identity['pid'] and state.get('runs')==1,
                 'launchd_actual_wrapper_pid')
            observed=self.reader.read(identity['pid'])
            need(observed==identity and observed['uid']==501
                 and observed['pid']==observed['pgid']
                 and observed['executable']==PYTHON_KERNEL_IMAGE,
                 'actual_wrapper_birth_executable')
            entry['wrapperIdentity']=identity;entry['groups'].add(identity['pgid'])
            entry['readySha256']=sha(raw)
            admission={'schema':'heptabao.mac-owned-manager-admission.r1',
                'generation':entry['generation'],'planSha256':entry['planSha256'],
                'wrapperIdentity':identity}
            self.guard.write_new(ROOT/'launchd'/(entry['generation']+'.admitted.private.json'),
                                 encoded(admission))
            self._record('actual-wrapper-admitted',entry['generation'],
                         {'wrapperIdentity':identity,'readySha256':sha(raw)})
            return

    def _rows(self,groups,*,until=None,cleanup=False):
        row,out,err=self._call('owned-launchd-group-observation',
            ['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],until=until,cleanup=cleanup,ps=True)
        need(row['exitCode']==0 and not err,'complete_group_observation')
        values=[]
        for line in out.decode('ascii','strict').splitlines():
            fields=line.split()
            need(len(fields)==5 and all(x.isdecimal() for x in fields[:3])
                 and (fields[3].isdecimal() or fields[3]=='-2'),'typed_process_row')
            pid,ppid,pgid,uid=map(int,fields[:4])
            if pgid in groups:values.append({'pid':pid,'ppid':ppid,'pgid':pgid,'uid':uid,'state':fields[4]})
        return values

    def _check_registration_files(self,entry):
        # Read-only metadata used in cleanup also: no expired private read,
        # no mutation, and no new business budget is granted.
        self.guard.check(check_deadline=False)
        self.home.check(check_deadline=False)
        need(file_identity(entry['plan'].lstat())==entry['planIdentity']
             and file_identity(entry['plist'].lstat())==entry['plistIdentity'],
             'registration_input_identity_unchanged')

    def _bootout(self,entry,*,cleanup=False,until=None):
        self._check_registration_files(entry)
        state=self._query(entry['label'],entry,until=until,cleanup=cleanup)
        if state is None:
            need('bootout' in entry['attempts'],'no_unexplained_registration_disappearance')
        elif 'bootout' not in entry['attempts']:
            if not cleanup:
                need(state.get('pid') is None,'known_wrapper_exit_before_bootout')
                self._record('bootout-intent',entry['generation'],{'argv':['/bin/launchctl','bootout',entry['target']]})
            self._dispatch_once(entry,'bootout',['/bin/launchctl','bootout',entry['target']],
                                until=until,cleanup=cleanup)
        while self._query(entry['label'],entry,until=until,cleanup=cleanup) is not None:
            self._remaining(until,cleanup=cleanup)
            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until,cleanup=cleanup)))
        remaining=self._rows(entry['groups'],until=until,cleanup=cleanup)
        entry['remainingGroupRows']=remaining
        need(not remaining,'owned_group_empty_after_label_removal')
        entry['registrationClosed']=True
        if not cleanup:self._record('bootout-complete',entry['generation'],{'groupRows':remaining})

    def _server_stdout_prefix(self,entry):
        # The same first LF record is read twice through one held HOME descriptor.
        self._remaining();self.guard.check()
        raw=self.home.prefix(entry['stdout'])
        self.guard.check();self._remaining()
        return raw

    def start_server(self,generation):
        self._expect_action('server-start',generation)
        entry=self._new_entry('server',generation)
        try:
            self._dispatch_once(entry,'bootstrap',['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])])
            self._ready(entry)
            until=min(self.until,time.monotonic()+NEW_EXEC_OBSERVATION_SECONDS)
            original=entry['wrapperIdentity']
            while True:
                self._remaining(until)
                state=self._query(entry['label'],entry,until=until)
                need(state is not None and state.get('pid')==original['pid']
                     and state.get('runs')==1,'same_launchd_pid_before_server_exec')
                observed=self.reader.read(original['pid'])
                need(all(observed[k]==original[k] for k in
                     ('pid','ppid','pgid','uid','birthSec','birthUsec')),'server_exec_same_birth')
                if observed['executable']==str(SERVER.resolve()):break
                need(observed['executable']==original['executable'],'no_foreign_executable')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)))
            raw=self.guard.read(ROOT/'launchd'/(generation+'.exec-ready.public.json'))
            candidate=json.loads(raw)
            stdout=self._server_stdout_prefix(entry)
            terminal=json.loads(stdout)
            need(isinstance(candidate,dict) and isinstance(terminal,dict)
                 and candidate.get('schema')=='heptabao.mac-owned-launchd-server-wrapper.r1'
                 and terminal.get('schema')==candidate['schema']
                 and terminal.get('generation')==generation
                 and terminal.get('ok') is True and terminal.get('readyToExec') is True
                 and terminal.get('outcomeUnknown') is False
                 and terminal.get('ownedBusinessWorkingDirectoryHeldT5') is True
                 and terminal.get('candidateReceiptSha256')==sha(raw)
                 and terminal.get('wrapperIdentity')==original
                 and terminal.get('binaryPath')==str(SERVER) and terminal.get('binarySha256')==SERVER_SHA
                 and terminal.get('elapsedSeconds',31)<30,'server_wrapper_completion_before_exec')
            closure=terminal.get('volumeGuardClosed',{});commands=terminal.get('commands',{})
            need(closure.get('allDescriptorsClosed') is True
                 and closure.get('lastAnchorCheckPassed') is True and closure.get('closeErrors')==[]
                 and commands.get('allOwnedCommandsStopped') is True
                 and commands.get('unknownCommandCount')==0,'server_wrapper_closure')
            entry['execIdentity']=observed
            entry['serverWrapperClosed']=True
            entry['execReceiptSha256']=sha(raw)
            entry['wrapperTerminalPrefixSha256']=sha(stdout)
            self._record('actual-server-exec',generation,{'identity':observed,
                'binarySha256':SERVER_SHA,'execReceiptSha256':sha(raw)})
            self._advance()
            return {'generation':generation,'serverIdentity':observed,'execReceiptSha256':sha(raw)}
        except BaseException:
            self.unknown=True
            raise

    def kill_server_for_cold_or_inverse(self,generation):
        self._expect_action('server-kill',generation)
        entry=next((e for e in self.entries if e['generation']==generation),None)
        need(entry is not None and entry['execIdentity'] is not None,'actual_server_before_kill')
        state=self._query(entry['label'],entry)
        need(state is not None and state.get('pid')==entry['execIdentity']['pid']
             and self.reader.read(state['pid'])==entry['execIdentity'],'exact_server_before_sigkill')
        self._record('server-sigkill-intent',generation,{'argv':['/bin/launchctl','kill','SIGKILL',entry['target']]})
        self._dispatch_once(entry,'kill',['/bin/launchctl','kill','SIGKILL',entry['target']])
        until=min(self.until,time.monotonic()+QUERY_SECONDS)
        while True:
            state=self._query(entry['label'],entry,until=until)
            need(state is not None and state.get('runs')==1,'same_registration_after_sigkill')
            if state.get('pid') is None:break
            need(state['pid']==entry['execIdentity']['pid'],'no_server_restart')
            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(until)))
        need(state.get('last terminating signal') in ('9','SIGKILL','Killed: 9','9 (Killed: 9)'),
             'actual_launchd_sigkill_terminal')
        need(not self._rows(entry['groups'],until=until),'server_group_empty_after_sigkill')
        entry['lineagesClosed']=entry.get('serverWrapperClosed') is True
        entry['completeKnownSuccess']=True
        self._bootout(entry,until=until)
        self._record('server-sigkill-complete',generation,
                     {'actualSignal':'SIGKILL','samePid':entry['execIdentity']['pid'],'groupRows':[]})
        self._advance()

    def run_phase(self,generation):
        self._expect_action('phase',generation)
        entry=self._new_entry('consumer',generation)
        try:
            self._dispatch_once(entry,'bootstrap',['/bin/launchctl','bootstrap',DOMAIN,str(entry['plist'])])
            self._ready(entry)
            while True:
                state=self._query(entry['label'],entry)
                need(state is not None and state.get('runs')==1,'same_phase_registration')
                if state.get('pid') is None:break
                need(state['pid']==entry['wrapperIdentity']['pid']
                     and self.reader.read(state['pid'])==entry['wrapperIdentity'],'same_phase_process')
                time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining()))
            need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')
            raw=self.guard.read(ROOT/'launchd'/(generation+'.result.public.json'))
            result=json.loads(raw)
            stdout=self.home.read(entry['stdout'])
            need(len(stdout.splitlines())==1,'one_final_phase_stdout_record')
            terminal=json.loads(stdout)
            need(isinstance(result,dict) and isinstance(terminal,dict)
                 and result.get('schema')=='heptabao.mac-five-agent-phase-owner.r2'
                 and result.get('generation')==generation and result.get('ok') is True
                 and result.get('outcomeUnknown') is False
                 and result.get('ownedBusinessWorkingDirectoryHeldT5') is True
                 and result.get('allOwnedStopped') is True
                 and result.get('allObserverClosuresAttemptedOnce') is True
                 and result.get('originalSharedPhaseSeconds')==120
                 and terminal.get('generation')==generation and terminal.get('ok') is True
                 and terminal.get('outcomeUnknown') is False
                 and terminal.get('allOwnedStopped') is True and terminal.get('resultSha256')==sha(raw)
                 and type(terminal.get('elapsedSeconds')) in (int,float)
                 and 0<=terminal['elapsedSeconds']<120,'phase_raw_result_terminal_exit_conjunction')
            closure=terminal.get('volumeGuardClosed',{})
            need(closure.get('allDescriptorsClosed') is True
                 and closure.get('lastAnchorCheckPassed') is True and closure.get('closeErrors')==[],
                 'phase_t5_closure_after_candidate_publication')
            inverse=generation.endswith('-inverse')
            records=result.get('records')
            expected=(['inverse-five-agents-and-six-caches'] if inverse else
                      ['authbus-five-agent-cycle',*['native-'+a for a in AGENTS]])
            need(isinstance(records,list) and [x.get('name') for x in records]==expected
                 and result.get('nativeWorkerCount')==(0 if inverse else 5),'exact_four_phase_matrix')
            for record in records:
                life=record.get('lifecycle',{});worker=record.get('report',{})
                need(life.get('exitCode')==0 and life.get('primaryReaped') is True
                     and life.get('noGroupSurvivors') is True and life.get('outcomeUnknown') is False
                     and life.get('remainingGroupMembers')==[]
                     and worker.get('ok') is True and worker.get('outcomeUnknown') is False,
                     'worker_known_and_actual_lineage_closed')
                pgid=life.get('ownedProcessGroup')
                need(type(pgid) is int and pgid>1,'typed_owned_worker_group')
                entry['groups'].add(pgid)
                if record.get('agentId') is not None:
                    observer=life.get('nativeProcessObserver',{})
                    need(observer.get('verified') is True and observer.get('requests')==1,
                         'separate_actual_single_native_observer')
            need(not self._rows(entry['groups']),'all_actual_phase_groups_empty')
            entry['lineagesClosed']=True;entry['completeKnownSuccess']=True
            entry['resultSha256']=sha(raw);entry['terminalSha256']=sha(stdout)
            entry['phaseRecordCount']=len(records)
            self._bootout(entry)
            self._record('phase-complete',generation,{'resultSha256':sha(raw),
                'terminalSha256':sha(stdout),'actualExitCode':0,'phaseRecords':len(records),
                'allKnownGroupsEmpty':True})
            self._advance()
            return result
        except BaseException:
            self.unknown=True
            raise

    def abort_cleanup_once(self):
        if self.failure_cleanup_attempted:return self.public()
        with self.signals.critical():
            self.failure_cleanup_attempted=True
            self.cleanup_until=time.monotonic()+NEW_CLEANUP_SECONDS
            self.unknown=True
            for entry in reversed(self.entries):
                if entry['registrationClosed']:continue
                try:
                    self._check_registration_files(entry)
                    state=self._query(entry['label'],entry,cleanup=True)
                    if state is None:
                        entry['registrationClosed']=True
                        entry['remainingGroupRows']=self._rows(entry['groups'],cleanup=True)
                        if entry['remainingGroupRows']:entry['registrationClosed']=False
                        continue
                    pid=state.get('pid')
                    expected=entry['execIdentity'] or entry['wrapperIdentity']
                    if pid is not None:
                        need(expected is not None and pid==expected['pid']
                             and self.reader.read(pid)==expected,'cleanup_exact_current_owned_identity')
                        operation='kill' if entry['kind']=='server' and entry['execIdentity'] else 'term'
                        if operation not in entry['attempts']:
                            signal_name='SIGKILL' if operation=='kill' else 'SIGTERM'
                            self._dispatch_once(entry,operation,
                                ['/bin/launchctl','kill',signal_name,entry['target']],cleanup=True)
                        grace=min(self.cleanup_until,time.monotonic()+NEW_FAILURE_TERM_GRACE_SECONDS)
                        while self._remaining(grace,cleanup=True):
                            state=self._query(entry['label'],entry,until=grace,cleanup=True)
                            if state is None or state.get('pid') is None:break
                            need(state['pid']==expected['pid'],'cleanup_no_replacement_pid')
                            time.sleep(min(NEW_MANAGER_POLL_SECONDS,self._remaining(grace,cleanup=True)))
                    self._bootout(entry,cleanup=True)
                    if entry['kind']=='server' and entry.get('serverWrapperClosed'):
                        entry['lineagesClosed']=not entry.get('remainingGroupRows')
                except BaseException as error:
                    entry['cleanupErrorType']=type(error).__name__
                    entry['cleanupErrorCode']=str(error) if isinstance(error,ManagerRefused) else None
            return self.public()

    def finish(self):
        self._remaining()
        need(self.graph_index==len(GRAPH) and not self.failure_cleanup_attempted
             and not self.unknown and all(e['registrationClosed'] and e['lineagesClosed']
             and e['completeKnownSuccess'] for e in self.entries),'entire_finite_manager_graph_complete')
        self.home.check()
        need(self.home.leaf_closure_known(),'home_all_leaf_closures_before_manager_success')
        commands=self.commands.public()
        need(commands['allOwnedCommandsStopped'] and commands['unknownCommandCount']==0
             and all(r['closed'] for r in self.fd_rows),'all_manager_helpers_and_descriptors_closed')
        self.finished=True
        return self.public()

    def public(self):
        entries=[]
        for e in self.entries:
            entries.append({'kind':e['kind'],'generation':e['generation'],'label':e['label'],
                'planSha256':e['planSha256'],'plistSha256':e['plistSha256'],
                'wrapperIdentity':e['wrapperIdentity'],'execIdentity':e['execIdentity'],
                'knownOwnedGroups':sorted(e['groups']),'attempts':e['attempts'],
                'registrationClosed':e['registrationClosed'],'lineagesClosed':e['lineagesClosed'],
                'completeKnownSuccess':e['completeKnownSuccess'],
                'remainingGroupRows':e.get('remainingGroupRows'),
                'resultSha256':e.get('resultSha256'),'terminalSha256':e.get('terminalSha256'),
                'cleanupErrorType':e.get('cleanupErrorType'),'cleanupErrorCode':e.get('cleanupErrorCode')})
        commands=self.commands.public()
        return {'schema':'heptabao.mac-owned-launchd-manager.r3','ok':bool(self.finished and not self.unknown and time.monotonic()<self.until),
            'outcomeUnknown':self.unknown,'newManagerSeconds':NEW_MANAGER_SECONDS,
            'newFailureCleanupSeconds':NEW_CLEANUP_SECONDS,'originalPhaseSeconds':120,'syntheticStartupOnly':True,'businessPhasesExecuted':False,
            'pythonRuntime':dict(self.python_runtime),'pythonKernelImage':PYTHON_KERNEL_IMAGE,
            'homeControlRoot':str(HOME_CONTROL),'businessRoot':str(ROOT),
            'homeControlFinalDescriptorsOwnedByOuter':True,
            'operationGraph':list(GRAPH),'completedOperationCount':self.graph_index,
            'registrations':entries,'events':list(self.events),'ownedCommands':commands,
            'allRegistrationsClosed':all(e['registrationClosed'] for e in self.entries),
            'allKnownLineagesClosed':all(e['lineagesClosed'] for e in self.entries),
            'allOwnedCommandsStopped':commands['allOwnedCommandsStopped'],
            'allManagerReadDescriptorsClosed':all(r['closed'] for r in self.fd_rows),
            'newMaximumCommandCount':MAX_COMMANDS,'newManagerPollSeconds':NEW_MANAGER_POLL_SECONDS,
            'failureCleanupAttempted':self.failure_cleanup_attempted,
            'elapsedSeconds':time.monotonic()-self.started,
            'noNumericPidOrGroupSignals':True,'productionManagerQualification':False}

PUBLIC_MANAGER_FAILURE_CODES=frozenset(["actual_bound_home_control","actual_launchctl_pid","actual_launchd_phase_exit_zero","actual_launchd_sigkill_terminal","actual_server_before_kill","actual_wrapper_birth_executable","all_actual_phase_groups_empty","all_manager_helpers_and_descriptors_closed","balanced_launchctl_print","bounded_launchctl_arguments","bounded_launchctl_print","cleanup_deadline_exists","cleanup_exact_current_owned_identity","cleanup_no_replacement_pid","complete_group_observation","complete_launchctl_arguments","complete_wrapper_prefix","entire_finite_manager_graph_complete","exact_four_phase_matrix","exact_launchctl_target","exact_owned_plist_no_keepalive","exact_public_anchor","exact_registered_generation","exact_server_before_sigkill","exact_staged_wrapper_copy_before_registration","exact_wrapper_before_registration","finite_launchd_operation_graph","finite_manager_command_count","fixed_generation_plan","fixed_manager_operation","held_t5_before_manager","home_actual_copy_binding","home_actual_copy_whole_before_private_inputs","home_actual_root_full9_before_effects","home_all_leaf_closures_before_manager_success","home_bounded_once_create","home_copy_size_hash_contract","home_create_only_root_already_exists","home_create_or_actual_binding","home_created_leaf_full9","home_exact_actual_binding","home_exact_copy_inventory","home_exact_write_role","home_fd_attempt_bound","home_finite_body_read","home_finite_leaf_name","home_fixed_flat_path","home_fixed_leaf_identity","home_full9_decimal_strings","home_initialized_held_root","home_known_file_whole_hash","home_metadata_bound","home_new_regular_600","home_nonempty_progress","home_only_two_server_public_prefixes","home_own_create_preserves_root_object","home_owned_root_fd_name_mode","home_owned_root_held_named_current_full9","home_parent_actual_first5_binding","home_parent_fd_name_owner_mode","home_precreated_empty_stdio_only","home_prefix_fd_close_known","home_read_fd_close_known","home_read_full9_interval","home_read_leaf_custody","home_read_remaining_bound","home_read_return_bound","home_read_whole_plus_eof_remaining","home_server_prefix_size_identity","home_shared_parent_held_named_first5","home_stage_copy_set","home_total_write_bound","home_whole_eof","home_write_call_bound","home_write_fd_close_known","home_write_progress","known_launchctl_mutation_success","known_launchctl_query","known_wrapper_exit_before_bootout","label_absent_before_new_generation","launchd_actual_wrapper_pid","mac_normal61_binding_not_admitted","manager_cancelled","no_business_after_unknown","no_foreign_executable","no_server_restart","no_unexplained_registration_disappearance","once_exact_manager_dispatch","one_complete_launchctl_record","one_final_phase_stdout_record","one_launchctl_arguments_block","one_launchd_run_only","one_new_manager_deadline","only_two_owned_labels","original_manager_or_cleanup_deadline","owned_group_empty_after_label_removal","owned_label_initially_absent","owned_manager_command_unknown","phase_raw_result_terminal_exit_conjunction","phase_t5_closure_after_candidate_publication","plain_fixed_launchctl_argument","plan_identity_around_whole_read","plist_identity_around_whole_read","previous_owned_registration_closed","registration_input_identity_unchanged","registration_present_while_waiting_ready","same_actual_synthetic_python_for_wrappers","same_launchd_pid_before_server_exec","same_phase_process","same_phase_registration","same_registration_after_sigkill","separate_actual_single_native_observer","server_exec_same_birth","server_group_empty_after_sigkill","server_stdout_name_and_prefix_fence","server_wrapper_closure","server_wrapper_completion_before_exec","typed_launchctl_integer","typed_owned_worker_group","typed_process_row","typed_qa_pins","typed_wrapper_ready","unique_launchctl_field","worker_known_and_actual_lineage_closed","wrapper_did_not_exit_before_ready","wrapper_prefix_same_fd_exact"])
def public_failure_code(error):
    if not isinstance(error,ManagerRefused):return None
    code=str(error)
    return code if code in PUBLIC_MANAGER_FAILURE_CODES else None
