#!/usr/bin/env python3
"""Bounded current Mac credential observation; no whole-database copy.

Library only: no import-time I/O, subprocess, SQL, write or CLI entry. Its caller
must be an explicitly reviewed sandbox-exec capture process with production
writes and all networking denied. Actual synthetic SQLite proof is mandatory.
Immutable intentionally skips SQLite change detection; our held FD/name fences
do not turn this into a SQLite transaction snapshot or a cross-agent snapshot.
"""
from __future__ import annotations
import base64, hashlib, json, os, re, sqlite3, stat, sys, time
from pathlib import Path

LIVE=Path('/Users/qianqi/.openclaw')
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
CACHE_NAMES=('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
             'refresh-backoff.json','lease-epochs.json','status.json')
TABLES=(('store','auth_profile_store','store_key','store_json'),
        ('state','auth_profile_state','state_key','state_json'))
CONFIG_SHA='ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d'
MIB=1024*1024
MAX_RETURNED_AND_READ_BYTES=8*MIB
MAX_ROW_BYTES=MIB
MAX_QUERY_SECONDS=3.0
NEW_CAPTURE_SECONDS=45.0

class CaptureRefused(RuntimeError):pass
def need(value,code):
    if not value:raise CaptureRefused(code)
def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def parent_identity(s):return identity(s)[:5]

class FixedInputs:
    def __init__(self, *, until, critical, live=LIVE, synthetic=False):
        need(callable(critical),'descriptor_signal_guard_required')
        need(live==LIVE or synthetic,'synthetic_root_requires_explicit_component_mode')
        self.live=Path(live);self.synthetic=synthetic;self.until=until;self.critical=critical
        self.fds=[];self.parents={};self.files={};self.absent={};self.connections=[];self.byte_count=0
        self.closed=False;self.close_errors=[];self.verified=False
        self.uid=os.geteuid()
        need(self.uid==501 or synthetic,'actual_mac_uid')
    def remaining(self,until=None):
        n=min(self.until,until if until is not None else self.until)-time.monotonic()
        need(n>0,'original_capture_or_query_deadline_exhausted')
        return n
    def _open_fd(self,name,flags,parent=None):
        self.remaining()
        with self.critical():
            fd=os.open(name,flags,**({} if parent is None else {'dir_fd':parent}))
            row={'fd':fd,'closeAttempted':False,'closed':False};self.fds.append(row)
        return row
    def parent(self,path):
        path=Path(path)
        need(path.is_absolute() and path==Path(os.path.normpath(str(path)))
             and path.is_relative_to(self.live),'fixed_current_input_scope')
        target=path.parent
        previous=None
        for directory in [Path('/'),*reversed(target.parents),target]:
            # reversed(target.parents) already contains '/'; do not observe it twice.
            key=str(directory)
            if key in self.parents:
                previous=self.parents[key];continue
            if directory==Path('/'):
                name='/';named=os.lstat('/')
            else:
                need(previous is not None and Path(previous['path'])==directory.parent,
                     'held_parent_chain_order')
                name=directory.name
                named=os.stat(name,dir_fd=previous['fd'],follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode) and not stat.S_IMODE(named.st_mode)&0o022,
                 'current_parent_plain_no_external_write')
            if directory==self.live or directory.is_relative_to(self.live):
                need(named.st_uid==self.uid,'current_parent_owner')
            row=self._open_fd(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                              None if previous is None else previous['fd'])
            need(parent_identity(os.fstat(row['fd']))==parent_identity(named),'held_parent_open_identity')
            row.update(path=key,name=name,parent=previous,expected=parent_identity(named))
            self.parents[key]=row;previous=row
        need(previous['path']==str(target),'exact_current_input_parent')
        return previous
    def directory(self,path,*,optional=False):
        path=Path(path);key=str(path)
        if key in self.parents:return self.parents[key]
        parent=self.parent(path)
        try:named=os.stat(path.name,dir_fd=parent['fd'],follow_symlinks=False)
        except FileNotFoundError:
            need(optional,'required_current_directory_absent')
            self.absent[key]={'parent':parent,'name':path.name}
            return None
        need(stat.S_ISDIR(named.st_mode) and named.st_uid==self.uid
             and not stat.S_IMODE(named.st_mode)&0o022,'current_directory_custody')
        row=self._open_fd(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,parent['fd'])
        need(parent_identity(os.fstat(row['fd']))==parent_identity(named),'current_directory_fd')
        row.update(path=key,name=path.name,parent=parent,expected=parent_identity(named))
        self.parents[key]=row
        return row
    def hold(self,path,*,optional=False,maximum=None,require_empty=False,private=True):
        path=Path(path);key=str(path)
        if key in self.files:return self.files[key]
        need(key not in self.absent,'absence_not_reopened_as_present')
        parent=self.parent(path)
        try:named=os.stat(path.name,dir_fd=parent['fd'],follow_symlinks=False)
        except FileNotFoundError:
            need(optional,'required_current_input_absent')
            self.absent[key]={'parent':parent,'name':path.name}
            return None
        need(stat.S_ISREG(named.st_mode) and named.st_uid==self.uid and named.st_nlink==1
             and (stat.S_IMODE(named.st_mode)==0o600 if private else
                  stat.S_IMODE(named.st_mode)&0o022==0) and named.st_size>=0,'current_input_custody')
        if maximum is not None:need(named.st_size<=maximum,'current_input_size_bound')
        if require_empty:need(named.st_size==0,'nonempty_wal_refused_before_sqlite')
        row=self._open_fd(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent['fd'])
        need(identity(named)==identity(os.fstat(row['fd'])),'current_input_open_identity')
        row.update(path=key,parent=parent,name=path.name,expected=identity(named))
        self.files[key]=row
        return row
    def account(self,size):
        need(type(size) is int and size>=0,'byte_accounting')
        self.byte_count+=size
        need(self.byte_count<=MAX_RETURNED_AND_READ_BYTES,'capture_returned_and_read_byte_cap')
    def read(self,path,*,optional=False,maximum=MIB,private=True):
        row=self.hold(path,optional=optional,maximum=maximum,private=private)
        if row is None:return None
        os.lseek(row['fd'],0,os.SEEK_SET);parts=[];count=0
        while count<=maximum:
            self.remaining()
            data=os.read(row['fd'],min(65536,maximum+1-count))
            if not data:break
            count+=len(data);self.account(len(data));parts.append(data)
        need(count==int(row['expected'][6]),'current_input_read_length')
        self.verify()
        return b''.join(parts)
    def database(self,path):
        main=self.hold(path)
        need(int(main['expected'][6])>=512,'current_database_header_bound')
        wal=self.hold(Path(str(path)+'-wal'),optional=True,maximum=0,require_empty=True)
        shm=self.hold(Path(str(path)+'-shm'),optional=True,maximum=8*MIB)
        journal=self.hold(Path(str(path)+'-journal'),optional=True,maximum=0)
        need(journal is None,'rollback_journal_refused_before_immutable')
        # We deliberately do not read/copy the main database or SHM bytes.
        self.verify()
        return main
    def verify(self):
        self.remaining();self.verified=False
        for row in self.parents.values():
            named=os.lstat('/') if row['parent'] is None else os.stat(
                row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
            need(parent_identity(named)==parent_identity(os.fstat(row['fd']))==row['expected'],
                 'held_current_parent_changed')
        for row in self.files.values():
            named=os.stat(row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
            need(identity(named)==identity(os.fstat(row['fd']))==row['expected'],
                 'current_input_fd_name_or_metadata_changed')
        for row in self.absent.values():
            try:os.stat(row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise CaptureRefused('current_input_absence_changed')
        self.remaining();self.verified=True
    def close(self):
        if self.closed:return
        for row in reversed(self.fds):
            if row['closeAttempted']:continue
            with self.critical():
                row['closeAttempted']=True
                try:os.close(row['fd']);row['closed']=True
                except BaseException as error:self.close_errors.append(type(error).__name__)
        self.closed=True
    def public(self):
        return {'boundedReadAndReturnedBytes':self.byte_count,
            'sqlitePageReadBytesMeasured':False,'wholeDatabaseCopied':False,
            'wholeDatabaseBackupQualified':False,'sqliteTransactionSnapshotClaimed':False,
            'crossAgentAtomicSnapshotClaimed':False,'observation':'bounded_point_in_time_with_fd_name_fences',
            'actualDatabaseSizes':{p:int(r['expected'][6]) for p,r in self.files.items() if p.endswith('.sqlite')},
            'files':{p:{'identity':list(r['expected'])} for p,r in self.files.items()},
            'absentPaths':list(self.absent),'allHeldNamesVerified':self.verified,
            'allOwnedDescriptorsClosed':self.closed and all(r['closed'] for r in self.fds)
                and all(r['closed'] for r in self.connections),
            'sqliteConnectionsOpened':len(self.connections),
            'sqliteConnectionsClosed':sum(r['closed'] for r in self.connections),
            'closeErrors':list(self.close_errors)}

def runtime_identity():
    return {'pythonExecutable':str(Path(sys.executable).resolve(strict=True)),
            'pythonVersion':sys.version,'sqliteVersion':sqlite3.sqlite_version,
            'sqliteVersionInfo':list(sqlite3.sqlite_version_info)}

def validate_synthetic_proof(raw, expected_sha):
    need(isinstance(raw,bytes) and len(raw)<=65536 and sha(raw)==expected_sha,
         'actual_synthetic_proof_original_bytes')
    proof=json.loads(raw)
    need(proof.get('schema')=='heptabao.mac-immutable-capture-synthetic.r1'
         and proof.get('ok') is True and proof.get('runtime')==runtime_identity(),
         'actual_same_runtime_synthetic_proof_required')
    need(proof.get('ownedDatabaseOnly') is True and proof.get('productionOpened') is False
         and proof.get('sameHeldFdUriCode') is True and proof.get('readonlyImmutableConnection') is True
         and proof.get('absentSidecarsStayedAbsent') is True
         and proof.get('emptyWalStayedEmpty') is True and proof.get('nonemptyWalRefusedBeforeConnect') is True
         and proof.get('journalRefusedBeforeConnect') is True
         and proof.get('oversizeRowRefused') is True and proof.get('driftRefused') is True
         and proof.get('allOwnedDescriptorsClosed') is True,'synthetic_negative_boundaries_required')

def immutable_query(inputs,main,query):
    inputs.verify()
    until=min(inputs.until,time.monotonic()+MAX_QUERY_SECONDS)
    inputs.remaining(until)
    need(hasattr(sqlite3.Connection,'setlimit') and hasattr(sqlite3,'SQLITE_LIMIT_LENGTH'),
         'actual_sqlite_length_limit_support_required')
    # /dev/fd/N reopens the already held read-only inode. The same exact URI
    # and runtime must first pass the owned synthetic proof; there is no
    # named-path fallback and no initial production experiment.
    uri='file:/dev/fd/'+str(main['fd'])+'?mode=ro&immutable=1'
    with inputs.critical():
        db=sqlite3.connect(uri,uri=True,timeout=0.0,isolation_level=None)
        connection={'db':db,'closeAttempted':False,'closed':False}
        inputs.connections.append(connection)
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_ROW_BYTES+65536)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,8192)
        db.enable_load_extension(False)
        db.set_progress_handler(lambda:1 if time.monotonic()>=until else 0,1000)
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA temp_store=MEMORY')
        need(db.execute('PRAGMA query_only').fetchone()==(1,),'connection_query_only')
        db.execute('BEGIN')
        value=query(db,until)
        inputs.remaining(until)
        db.execute('ROLLBACK')
    finally:
        with inputs.critical():
            connection['closeAttempted']=True
            try:db.close();connection['closed']=True
            except BaseException as error:
                inputs.close_errors.append(type(error).__name__)
                raise
    inputs.remaining(until);inputs.verify()
    return value

def auth_rows(inputs,agent):
    path=inputs.live/'agents'/agent/'agent/openclaw-agent.sqlite'
    main=inputs.database(path)
    def query(db,until):
        result={}
        allowed_tables={x[1] for x in TABLES}
        allowed_columns={t:{k,c,'updated_at'} for _,t,k,c in TABLES}
        def authorize(action,arg1,arg2,_db,_trigger):
            if action==sqlite3.SQLITE_SELECT:return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_READ and arg1 in allowed_tables and arg2 in allowed_columns[arg1]:
                return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_TRANSACTION and arg1 in ('ROLLBACK',):return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        db.set_authorizer(authorize)
        for kind,table,key,column in TABLES:
            inputs.remaining(until)
            rows=db.execute('SELECT '+key+','+column+',updated_at FROM '+table+
                            ' WHERE '+key+'=? LIMIT 2',('primary',)).fetchall()
            need(len(rows)<=1,'fixed_primary_row_count')
            for row in rows:
                need(len(row)==3 and row[0]=='primary' and isinstance(row[1],str)
                     and type(row[2]) is int and 0<=row[2]<=9007199254740991,'fixed_primary_row_shape')
                raw=row[1].encode('utf-8')
                need(len(raw)<=MAX_ROW_BYTES,'auth_primary_payload_cap')
                parsed=json.loads(raw)
                need(isinstance(parsed,dict),'auth_primary_json_object')
                if kind=='store':
                    need(isinstance(parsed.get('profiles',{}),dict)
                         and len(parsed.get('profiles',{}))<=128,'bounded_local_profile_dictionary')
                inputs.account(len(raw)+len(encoded(row)))
            result[kind]=[list(row) for row in rows]
        return result
    rows=immutable_query(inputs,main,query)
    return {'schema':'heptabao.mac-current-primary-auth-rows.private.r1','agent':agent,
            'rows':rows,'sourceIdentity':list(main['expected']),
            'captureScope':'two_fixed_primary_keys_only','nonprimaryRowsCaptured':False}

def installed_registry(inputs):
    main=inputs.database(inputs.live/'state/openclaw.sqlite')
    def query(db,until):
        # A finite, named table and one fixed key. Physical column order is
        # retained explicitly, never compared against another SELECT ordering.
        schema_rows=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                               ('installed_plugin_index',)).fetchall()
        need(len(schema_rows)==1 and isinstance(schema_rows[0][0],str)
             and len(schema_rows[0][0].encode())<=16384,'bounded_actual_registry_schema')
        info=db.execute('PRAGMA table_info(installed_plugin_index)').fetchall()
        names=[x[1] for x in info]
        need(len(names)==len(set(names))==13 and all(re.fullmatch('[a-z_]+',x) for x in names)
             and 'index_key' in names,'actual_installed_registry_thirteen_named_columns')
        rows=db.execute('SELECT '+','.join('"'+x+'"' for x in names)+
                        ' FROM installed_plugin_index WHERE index_key=? LIMIT 2',
                        ('installed-plugin-index',)).fetchall()
        need(len(rows)==1 and len(rows[0])==13,'one_actual_installed_registry_row')
        need(all(x is None or type(x) in (str,int,float) for x in rows[0]),'registry_scalar_columns')
        record={'schema':schema_rows[0][0],'columns':names,'row':list(rows[0]),'tableInfo':[list(x) for x in info]}
        raw=encoded(record);need(len(raw)<=MIB,'registry_returned_byte_cap');inputs.account(len(raw))
        return record
    return immutable_query(inputs,main,query)

def current_models(cfg):
    declared=cfg.get('agents',{}).get('list')
    need(isinstance(declared,list) and tuple(x.get('id') for x in declared)==AGENTS,'actual_five_declared_agents')
    defaults=cfg.get('agents',{}).get('defaults',{})
    def primary(value):return value.get('primary') if isinstance(value,dict) else value
    models={}
    for item in declared:
        agent=item['id'];directory=LIVE/'agents'/agent/'agent'
        need(Path(item.get('agentDir',directory))==directory,'actual_agent_directory')
        origin='agent' if 'model' in item else 'defaults'
        selected=primary(item.get('model',defaults.get('model')))
        need(isinstance(selected,str) and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_./:-]+',selected),
             'actual_declared_or_default_model_shape')
        provider,model=selected.split('/',1)
        models[agent]={'provider':provider,'id':model,
            'origin':origin,'declaredModelSha256':sha(encoded(item.get('model',defaults.get('model')))),
            'sourceConfigSha256':CONFIG_SHA}
    return models

def capture_current(*,critical,synthetic_proof,synthetic_proof_sha,until):
    validate_synthetic_proof(synthetic_proof,synthetic_proof_sha)
    need(sys.platform=='darwin' and os.getuid()==501,'exact_current_mac')
    need(until<=time.monotonic()+NEW_CAPTURE_SECONDS,'one_capture_budget_no_reset')
    inputs=FixedInputs(until=until,critical=critical)
    document=None
    try:
        raw_config=inputs.read(LIVE/'openclaw.json')
        need(sha(raw_config)==CONFIG_SHA,'actual_current_config_pin')
        cfg=json.loads(raw_config);models=current_models(cfg)
        documents=[auth_rows(inputs,agent) for agent in AGENTS]
        caches={}
        cache_directory=inputs.directory(LIVE/'authbus',optional=True)
        for name in CACHE_NAMES:
            raw=None if cache_directory is None else inputs.read(LIVE/'authbus'/name,optional=True)
            caches[name]={'present':False} if raw is None else {
                'present':True,'mode':0o600,'bytes':len(raw),'sha256':sha(raw),
                'base64':base64.b64encode(raw).decode('ascii')}
        native={}
        for agent in AGENTS:
            directory=LIVE/'agents'/agent/'agent/codex-home';values={}
            native_directory=inputs.directory(directory,optional=True)
            values['directoryPresent']=native_directory is not None
            for name in ('config.toml','requirements.toml','auth.json'):
                raw=None if native_directory is None else inputs.read(directory/name,optional=True,
                      private=name=='auth.json')
                values[name]={'present':False} if raw is None else {
                    'present':True,'bytes':len(raw),'sha256':sha(raw)}
                if raw is not None and name!='auth.json':
                    values[name]['base64']=base64.b64encode(raw).decode('ascii')
            native[agent]=values
        registry=installed_registry(inputs)
        inputs.verify()
        document={'schema':'heptabao.mac-guarded-current-inputs.private.r1',
            'sourceConfigSha256':CONFIG_SHA,'configBase64':base64.b64encode(raw_config).decode('ascii'),
            'agentIds':list(AGENTS),'models':models,'authDocuments':documents,
            'authbusCaches':{'directoryPresent':cache_directory is not None,'files':caches},
            'nativeHomes':native,'registry':registry,
            'runtime':runtime_identity(),'syntheticProofSha256':synthetic_proof_sha,
            'scope':'bounded_point_in_time_observation_not_database_or_cross_agent_snapshot'}
        need(len(encoded(document))<=4*MIB,'combined_private_capsule_bound')
        inputs.verify()
    finally:inputs.close()
    public=inputs.public()
    need(public['allOwnedDescriptorsClosed'] and not public['closeErrors'],'current_input_descriptor_closure')
    return document,public
