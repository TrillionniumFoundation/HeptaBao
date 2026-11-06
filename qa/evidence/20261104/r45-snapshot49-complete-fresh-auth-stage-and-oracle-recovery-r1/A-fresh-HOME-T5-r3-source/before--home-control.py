
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
