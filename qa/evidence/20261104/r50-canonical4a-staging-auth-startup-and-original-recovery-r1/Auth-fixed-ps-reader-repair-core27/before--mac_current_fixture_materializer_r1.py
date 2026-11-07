#!/usr/bin/env python3
"""Create two independent auth-only Mac fixtures from an admitted bounded capsule.

Library only. No source database is opened here. All SQLite writes target new,
exclusive files below the two fixed phase roots. Effective auth is never a
materialization or inverse input. Models and flags come from captured config.
"""
from __future__ import annotations
import base64, copy, hashlib, json, math, os, re, sqlite3, stat, time
from pathlib import Path

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3')
LIVE=Path('/Users/qianqi/.openclaw')
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
CODEX=LIVE/'npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex'
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
PHASES=('initial','cold-new-process')
TABLES=(('store','auth_profile_store','store_key','store_json'),
        ('state','auth_profile_state','state_key','state_json'))
CACHE_NAMES=('applied-profiles.json','publish-baseline.json','bad-refresh-quarantine.json',
             'refresh-backoff.json','lease-epochs.json','status.json')
CONFIG_SHA='ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d'
MAX_ROW=1024*1024

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return sha(encoded(value))
def ident(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def no_nonfinite(value):
    if type(value) is float:need(math.isfinite(value),'finite_captured_json_number')
    elif isinstance(value,list):
        for item in value:no_nonfinite(item)
    elif isinstance(value,dict):
        need(all(isinstance(k,str) for k in value),'json_object_keys')
        for item in value.values():no_nonfinite(item)

def consumer_profile(phase,port,source_pins,ca_file,harness_roots,harness_bindings):
    need(phase in PHASES and type(port) is int and 1024<=port<=65535,'fixed_consumer_sandbox')
    root=ROOT/phase
    need(Path(ca_file)==ROOT/'credentials-consumer/ca.crt','only_owned_ca')
    # The exact installed code and the new phase are readable; production
    # current DB/config/auth/cache values and other phase/control roots are not.
    q=lambda value:json.dumps(str(value))
    lines=['(version 1)','(deny default)','(allow process*)',
        '(allow signal (target children))','(allow sysctl-read)','(allow mach-lookup)',
        '(allow file-read-metadata)']
    for path in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in (ROOT/'qa',ROOT/'installed-plugin-copy',root):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    # Installed immutable package roots are public code. Reading their package
    # modules is necessary for the real Node loader and its transitive imports.
    need(isinstance(harness_roots,list) and 1<=len(harness_roots)<=8
         and len(set(harness_roots))==len(harness_roots),'actual_finite_harness_root_set')
    need(isinstance(harness_bindings,list) and len(harness_bindings)==len(harness_roots)
         and all(isinstance(item,dict) for item in harness_bindings),
         'finite_admitted_harness_binding_list')
    by_root={item['rootDir']:item for item in harness_bindings}
    need(len(by_root)==len(harness_bindings) and set(by_root)==set(harness_roots),
         'exact_harness_roots_match_admitted_bindings')
    for value in sorted(set([str(CODEX),*harness_roots])):
        path=Path(value);binding=by_root.get(value)
        need(path.is_absolute() and path==Path(os.path.normpath(str(path))),
             'normalized_public_installed_harness_root')
        if path.is_relative_to(LIVE/'npm/projects'):
            need(binding is None if path==CODEX and value not in harness_roots
                 else binding is not None and binding.get('layout')=='npm',
                 'admitted_npm_harness_root')
        else:
            need(binding is not None and binding.get('layout')=='sdk-bundled'
                 and path.parent==SDK/'dist/extensions'
                 and path.name==binding.get('pluginId'),'exact_admitted_sdk_bundled_root')
            for field,name in (('manifest','openclaw.plugin.json'),('package','package.json')):
                metadata=binding.get(field)
                need(isinstance(metadata,dict) and metadata.get('path')==str(path/name)
                     and isinstance(metadata.get('sha256'),str)
                     and re.fullmatch('[0-9a-f]{64}',metadata['sha256'])
                     and source_pins.get(metadata['path'])==metadata['sha256'],
                     'bundled_root_has_whole_admitted_metadata')
            entries=binding.get('entries')
            need(isinstance(entries,list) and 1<=len(entries)<=8
                 and all(isinstance(item,dict) and isinstance(item.get('path'),str)
                         and Path(item['path']).is_absolute()
                         and Path(item['path'])==Path(os.path.normpath(item['path']))
                         and Path(item['path']).is_relative_to(path)
                         and isinstance(item.get('sha256'),str)
                         and re.fullmatch('[0-9a-f]{64}',item['sha256'])
                         and source_pins.get(item['path'])==item['sha256'] for item in entries),
                 'bundled_declared_entries_have_exact_source_pins')
        # SDK bundled code is already inside the original /opt/homebrew read
        # subtree; this does not add a new OS-readable private path.
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in sorted(source_pins):
        lines.append('(allow file-read* (literal '+q(path)+'))')
    for path in (ROOT/'credentials-consumer/ca.crt',
                 ROOT/'credentials-consumer/role_id',ROOT/'credentials-consumer/secret_id'):
        lines.append('(allow file-read* (literal '+q(path)+'))')
    lines.extend(['(allow file-read* (literal "/dev/urandom"))',
        '(allow file-read* (literal "/dev/random"))',
        '(allow file-write* (subpath '+q(root)+'))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow network-outbound (remote ip '+q('localhost:'+str(port))+'))'])
    return ('\n'.join(lines)+'\n').encode()

class Materializer:
    def __init__(self,guard,signals,until):
        need(guard.uuid_verified and not guard.closed,'held_t5_before_materialization')
        self.guard=guard;self.signals=signals;self.until=until
        self.connections=[];self.fds=[];self.started=False;self.completed=False
        self.created=[];self.phase_public=[];self.close_errors=[]

    def remaining(self,until=None):
        need(self.signals.pending is None,'materialization_cancelled')
        left=min(self.until,until if until is not None else self.until)-time.monotonic()
        need(left>0,'original_outer_or_owned_sqlite_deadline');return left

    def mkdir(self,path):
        self.remaining();self.guard.mkdir_new(path);self.created.append(str(path))

    def write(self,path,raw):
        self.remaining();result=self.guard.write_new(path,raw);self.remaining();return result

    def close_fd(self,row):
        if row['closeAttempted']:return
        with self.signals.critical():
            row['closeAttempted']=True
            try:os.close(row['fd']);row['closed']=True
            except BaseException as error:
                row['closeErrorType']=type(error).__name__;self.close_errors.append(type(error).__name__)

    def close_connection(self,row):
        if row['closeAttempted']:return
        with self.signals.critical():
            row['closeAttempted']=True
            try:row['db'].close();row['closed']=True
            except BaseException as error:
                row['closeErrorType']=type(error).__name__;self.close_errors.append(type(error).__name__)

    def owned_database(self,path,create_and_verify):
        self.remaining()
        need(any(path.is_relative_to(ROOT/phase/'state') for phase in PHASES),
             'only_new_phase_databases')
        fdrow=None;connection=None
        with self.guard.parent(path) as (parent,name):
            try:
                with self.signals.critical():
                    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                    fdrow={'fd':fd,'closeAttempted':False,'closed':False};self.fds.append(fdrow)
                before=os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
                     and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==0
                     and ident(before)==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                     'new_empty_owned_database')
                query_until=min(self.until,time.monotonic()+3.0)
                self.remaining(query_until)
                with self.signals.critical():
                    db=sqlite3.connect(str(path),timeout=0.0,isolation_level=None)
                    connection={'db':db,'closeAttempted':False,'closed':False}
                    self.connections.append(connection)
                db.enable_load_extension(False)
                need(hasattr(db,'setlimit'),'same_runtime_sqlite_limits_required')
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_ROW+65536)
                db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,32768)
                db.set_progress_handler(lambda:1 if time.monotonic()>=query_until else 0,1000)
                db.execute('PRAGMA journal_mode=DELETE')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA temp_store=MEMORY')
                db.execute('PRAGMA max_page_count=8192')
                db.execute('BEGIN IMMEDIATE')
                create_and_verify(db,query_until)
                self.remaining(query_until);db.execute('COMMIT')
                self.close_connection(connection);need(connection['closed'],'owned_database_connection_closed')
                self.remaining(query_until)
                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                need(ident(after)==ident(named) and ident(before)[:6]==ident(after)[:6]
                     and 512<=after.st_size<=32*1024*1024,'same_created_database_inode')
                os.fsync(fd);os.fsync(parent)
                for suffix in ('-wal','-shm','-journal'):
                    try:os.stat(name+suffix,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError:pass
                    else:raise Refused('owned_materialized_database_sidecar_remaining')
                self.remaining()
                return {'path':str(path),'bytes':after.st_size,'identity':list(ident(after))}
            finally:
                if connection is not None:self.close_connection(connection)
                if fdrow is not None:self.close_fd(fdrow)

    def auth_database(self,path,rows):
        need(isinstance(rows,dict) and set(rows)=={'store','state'},'two_primary_table_documents')
        for kind,_,_,_ in TABLES:
            values=rows[kind]
            need(isinstance(values,list) and len(values)<=1,'captured_primary_only')
            for row in values:
                need(isinstance(row,list) and len(row)==3 and row[0]=='primary'
                     and isinstance(row[1],str) and len(row[1].encode())<=MAX_ROW
                     and type(row[2]) is int and 0<=row[2]<=9007199254740991,
                     'exact_auth_row_shape_and_timestamp')
                need(isinstance(json.loads(row[1]),dict),'auth_payload_object')
        def create(db,until):
            for kind,table,key,column in TABLES:
                self.remaining(until)
                db.execute('CREATE TABLE '+table+' ('+key+' TEXT PRIMARY KEY,'+
                           column+' TEXT NOT NULL,updated_at INTEGER NOT NULL)')
                db.executemany('INSERT INTO '+table+' VALUES (?,?,?)',rows[kind])
                actual=[list(row) for row in db.execute('SELECT '+key+','+column+
                    ',updated_at FROM '+table+' ORDER BY '+key)]
                need(actual==rows[kind],'original_primary_payload_and_timestamp_exact')
        return self.owned_database(path,create)

    def registry_database(self,path,registry):
        need(isinstance(registry,dict) and set(registry)=={'schema','columns','row','tableInfo'},
             'complete_captured_registry_shape')
        columns=registry['columns'];row=registry['row'];ddl=registry['schema']
        need(isinstance(columns,list) and len(columns)==len(set(columns))==13
             and all(isinstance(x,str) and re.fullmatch('[a-z_]+',x) for x in columns)
             and 'index_key' in columns and isinstance(row,list) and len(row)==13
             and row[columns.index('index_key')]=='installed-plugin-index'
             and isinstance(ddl,str) and len(ddl.encode())<=16384
             and re.match(r'(?is)^\s*CREATE\s+TABLE\s+(?:"installed_plugin_index"|installed_plugin_index)\s*\(',ddl),
             'one_actual_thirteen_column_registry')
        no_nonfinite(registry)
        def create(db,until):
            self.remaining(until)
            # execute accepts one statement. No ATTACH, virtual table, extension,
            # function invocation or second statement is authorized.
            forbidden={sqlite3.SQLITE_ATTACH,sqlite3.SQLITE_DETACH,sqlite3.SQLITE_FUNCTION,
                       sqlite3.SQLITE_CREATE_VTABLE,sqlite3.SQLITE_DROP_VTABLE}
            db.set_authorizer(lambda action,*_args:sqlite3.SQLITE_DENY if action in forbidden else sqlite3.SQLITE_OK)
            db.execute(ddl)
            names=','.join('"'+name+'"' for name in columns)
            db.execute('INSERT INTO installed_plugin_index ('+names+') VALUES ('+
                       ','.join('?' for _ in columns)+')',row)
            actual=db.execute('SELECT '+names+' FROM installed_plugin_index WHERE index_key=?',
                              ('installed-plugin-index',)).fetchall()
            need([list(x) for x in actual]==[row],'whole_captured_registry_row')
            need([list(x) for x in db.execute('PRAGMA table_info(installed_plugin_index)')]
                 ==registry['tableInfo'],'whole_registry_column_contract')
            stored=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='installed_plugin_index'").fetchall()
            need(stored==[(ddl,)],'registry_ddl_preserved_exact')
            self.remaining(until)
        return self.owned_database(path,create)

    def validate_capsule(self,document):
        need(isinstance(document,dict) and document.get('schema')=='heptabao.mac-guarded-current-inputs.private.r1'
             and document.get('sourceConfigSha256')==CONFIG_SHA and document.get('agentIds')==list(AGENTS)
             and document.get('scope')=='bounded_point_in_time_observation_not_database_or_cross_agent_snapshot',
             'admitted_current_capsule_shape')
        no_nonfinite(document)
        config_raw=base64.b64decode(document['configBase64'],validate=True)
        need(len(config_raw)<=MAX_ROW and sha(config_raw)==CONFIG_SHA,'captured_config_whole_pin')
        cfg=json.loads(config_raw)
        declared=cfg.get('agents',{}).get('list')
        need(isinstance(declared,list) and [x.get('id') for x in declared]==list(AGENTS),
             'all_actual_five_agents')
        docs=document['authDocuments']
        need(isinstance(docs,list) and len(docs)==5 and [x.get('agent') for x in docs]==list(AGENTS),
             'five_ordered_current_primary_documents')
        for item in docs:
            need(item.get('captureScope')=='two_fixed_primary_keys_only'
                 and item.get('nonprimaryRowsCaptured') is False,'honest_primary_materialization_scope')
        cache=document['authbusCaches']
        need(isinstance(cache,dict) and set(cache)=={'directoryPresent','files'}
             and type(cache['directoryPresent']) is bool and set(cache['files'])==set(CACHE_NAMES),
             'all_six_current_cache_bytes_or_absence')
        for value in cache['files'].values():
            need(isinstance(value,dict) and type(value.get('present')) is bool,'typed_cache_presence')
            if value['present']:
                raw=base64.b64decode(value['base64'],validate=True)
                need(cache['directoryPresent'] and value['mode']==0o600
                     and type(value['bytes']) is int and len(raw)==value['bytes']<=MAX_ROW
                     and sha(raw)==value['sha256'],'current_cache_whole_bytes')
        return cfg,{item['agent']:item for item in docs}

    def materialize(self,document,*,plugin_config,managed_profiles,runtime,source_pins,
                    qa_pins,port,server_certificate_sha256):
        need(not self.started,'materialization_once')
        self.started=True
        cfg,documents=self.validate_capsule(document)
        need(set(document['nativeHomes'])==set(AGENTS)
             and set(document['models'])==set(AGENTS),'all_current_model_native_inputs')
        original_plugin=cfg['plugins']['entries']['openclaw-authbus']['config']
        without=lambda obj:{k:v for k,v in obj.items() if k not in ('address','caFile','roleIdFile','secretIdFile')}
        need(without(plugin_config)==without(original_plugin)
             and original_plugin.get('hostId')=='mac' and original_plugin.get('leader') is False
             and original_plugin.get('publishNew') is True and original_plugin.get('manageOrder') is True,
             'complete_actual_authbus_flags_preserved')
        need(isinstance(managed_profiles,list) and len(managed_profiles)==2
             and len({x['profileId'] for x in managed_profiles})==2,'two_same_identity_managed_generations')
        need(runtime['sdkRoot']==str(SDK) and runtime['codexRoot']==str(CODEX)
             and runtime['pluginEntry']==str(ROOT/'installed-plugin-copy/index.js')
             and isinstance(runtime['harnessOwnerPluginIds'],list)
             and runtime['harnessOwnerPluginIds'],'fixed_installed_runtime_paths')
        need(all(isinstance(path,str) and isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin)
                 for path,pin in source_pins.items()),'fixed_installed_source_pins')
        plans=[]
        for phase in PHASES:
            self.remaining();work=ROOT/phase;state=work/'state'
            for path in (work,state,state/'agents',state/'oauth',state/'home',state/'state',
                         work/'tmp',work/'workers',work/'inverse',work/'native-tmp',work/'workspaces'):
                self.mkdir(path)
            scoped=copy.deepcopy(cfg)
            scoped['agents']['defaults']['workspace']=str(work/'workspaces/main')
            phase_pins=dict(source_pins);native_workers={};database_records=[]
            for item in scoped['agents']['list']:
                agent=item['id'];directory=state/'agents'/agent/'agent'
                for path in (state/'agents'/agent,directory,directory/'codex-home',
                             work/'native-tmp'/agent,work/'workspaces'/agent):
                    self.mkdir(path)
                item['agentDir']=str(directory);item['workspace']=str(work/'workspaces'/agent)
                database_records.append(self.auth_database(directory/'openclaw-agent.sqlite',
                                                           documents[agent]['rows']))
                native=document['nativeHomes'][agent]
                for name in ('config.toml','requirements.toml'):
                    value=native[name]
                    if value['present']:
                        raw=base64.b64decode(value['base64'],validate=True)
                        need(len(raw)==value['bytes']<=MAX_ROW and sha(raw)==value['sha256'],
                             'actual_native_config_bytes')
                        destination=directory/'codex-home'/name
                        self.write(destination,raw);phase_pins[str(destination)]=sha(raw)
                need(not (directory/'codex-home/auth.json').exists(),'no_production_native_auth_copy')
                declared=next(x for x in cfg['agents']['list'] if x['id']==agent)
                selected=declared.get('model',cfg['agents']['defaults'].get('model'))
                model_string=selected.get('primary') if isinstance(selected,dict) else selected
                need(isinstance(model_string,str) and '/' in model_string,'actual_agent_model')
                provider,model_id=model_string.split('/',1)
                model={'provider':provider,'id':model_id,'api':cfg['models']['providers'][provider]['api']}
                captured=document['models'][agent]
                need(captured['provider']==provider and captured['id']==model_id
                     and captured['sourceConfigSha256']==CONFIG_SHA
                     and captured['declaredModelSha256']==sha(encoded(selected)+b'\n'),'actual_per_agent_model_binding')
                prefix=work/'workers'/('native-'+agent)
                native_workers[agent]={
                    'model':model,'nativeHome':str(directory/'codex-home'),
                    'nativeTmp':str(work/'native-tmp'/agent),'workspace':str(work/'workspaces'/agent),
                    'selectionOutput':str(prefix)+'.selection.private.json',
                    'nativeDiagnosticOutput':str(prefix)+'.diagnostic.private.json',
                    'nativeErrorOutput':str(prefix)+'.error.private.json',
                    'nativeIdentityOutput':str(prefix)+'.identity.private.json',
                    'nativeAccountOutput':str(prefix)+'.account.private.json'}
            scoped['plugins']['entries']['openclaw-authbus']['config']=copy.deepcopy(plugin_config)
            self.write(state/'openclaw.json',encoded(scoped))
            self.registry_database(state/'state/openclaw.sqlite',document['registry'])
            if document['authbusCaches']['directoryPresent']:
                self.mkdir(state/'authbus')
                for name,value in document['authbusCaches']['files'].items():
                    if value['present']:self.write(state/'authbus'/name,base64.b64decode(value['base64'],validate=True))
            sandbox=work/'consumer.sb'
            policy=consumer_profile(phase,port,phase_pins,plugin_config['caFile'],
                runtime['harnessCodeRoots'],runtime['harnessOwnerBindings'])
            self.write(sandbox,policy);phase_pins[str(sandbox)]=sha(policy)
            common={**runtime,'workRoot':str(ROOT),'phaseRoot':str(work),'stateRoot':str(state),
                'pluginConfig':copy.deepcopy(plugin_config),'originalPluginConfig':copy.deepcopy(original_plugin),
                'serverCertificateSha256':server_certificate_sha256,'managedProfiles':copy.deepcopy(managed_profiles),
                'model':native_workers['main']['model'],'sourcePins':phase_pins,
                'originalAuthRowsDigestByAgent':{agent:digest(documents[agent]['rows']) for agent in AGENTS},
                'originalCacheContentSha256':digest(document['authbusCaches']),
                'baselineOutput':str(work/'baseline.private.json'),
                'candidateOutput':str(work/'candidate.private.json'),
                'rollbackCheckpointOutput':str(work/'candidate.private.json'),
                'rollbackOnce':str(work/'inverse/rollback-once.private.json'),
                'parentSandbox':str(sandbox)}
            for mode,generation in (('consume',phase),('inverse',phase+'-inverse')):
                plan={'schema':'heptabao.mac-five-agent-phase-plan.private.r1','generation':generation,
                    'phase':phase,'mode':mode,'agentIds':list(AGENTS),'phaseSeconds':120,
                    'phaseRoot':str(work),'stateRoot':str(state),
                    'expectedVolumeDevice':self.guard.expected['expectedVolumeDevice'],
                    'qaPins':dict(qa_pins),'workerCommon':copy.deepcopy(common),
                    'nativeWorkers':copy.deepcopy(native_workers)}
                binding=self.write(ROOT/'launchd'/(generation+'.private.json'),encoded(plan))
                plans.append({'generation':generation,**binding})
            self.phase_public.append({'phase':phase,'agents':list(AGENTS),'authOnlyDatabases':database_records,
                'rawRowsDigests':common['originalAuthRowsDigestByAgent'],
                'originalCacheContentSha256':common['originalCacheContentSha256'],
                'originalConfigSha256':CONFIG_SHA,'ownedConfigSha256':sha(encoded(scoped)),
                'perAgentModelsBoundToActualConfig':True,'inheritedEffectiveProfilesMaterialized':False,
                'productionNativeAuthCopied':False,'nonprimaryDatabaseTablesCopied':False})
        self.remaining();self.guard.check()
        need(not self.close_errors and all(x['closed'] for x in self.fds)
             and all(x['closed'] for x in self.connections),'all_materialization_descriptors_closed')
        self.completed=True
        return {'plans':plans,'phases':self.phase_public,'sameCapturedBaselineForBothIndependentPhases':True,
                'crossAgentAtomicSnapshotClaimed':False}

    def close(self):
        for row in reversed(self.connections):self.close_connection(row)
        for row in reversed(self.fds):self.close_fd(row)

    def public(self):
        return {'started':self.started,'completed':self.completed,'createdDirectoryCount':len(self.created),
            'ownedDatabaseConnections':len(self.connections),
            'allOwnedDescriptorsClosed':all(x['closed'] for x in self.fds)
                and all(x['closed'] for x in self.connections),
            'closeErrors':list(self.close_errors),'productionDatabaseOpened':False}
