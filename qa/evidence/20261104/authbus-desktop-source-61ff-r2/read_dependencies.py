#!/usr/bin/env python3
"""Read-only projection of Desktop's existing provider/client dependency and source ownership."""
import base64,datetime,hashlib,json,os,pathlib,re,shlex,sqlite3,stat,subprocess,sys,time,urllib.parse,zlib
HOME=pathlib.Path('/home/qian-qi');LIVE=HOME/'.openclaw'
EXPECTED='7dc5e5412ddc6da4977d44743261376e24c0d644dabd3b082c8c57f3647ed1d3'
PINS={};STATIC={};NOTES=[];PRIVATE=[]
sha=lambda b:hashlib.sha256(b).hexdigest()
canon=lambda o:json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def meta(p):
    p=pathlib.Path(p);s=p.lstat()
    return {'path':str(p),'bytes':s.st_size,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777,'inode':s.st_ino,'device':s.st_dev,'mtimeNs':s.st_mtime_ns,'symlink':p.is_symlink(),'regular':stat.S_ISREG(s.st_mode)}
def read(p,limit=2097152,private=False,static=False):
    p=pathlib.Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=limit
        if private:assert a.st_uid==os.getuid() and a.st_mode&0o077==0
        out=bytearray()
        while len(out)<=limit:
            b=os.read(fd,min(1048576,limit+1-len(out)))
            if not b:break
            out.extend(b)
        b=os.fstat(fd);c=p.lstat();stamp=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        assert len(out)==a.st_size and stamp(a)==stamp(b)==stamp(c)
    finally:os.close(fd)
    PINS[str(p)]=sha(out)
    if static:STATIC[str(p)]=sha(out)
    return bytes(out)
def url(v):
    if not isinstance(v,str):return None
    u=urllib.parse.urlsplit(v)
    return {'scheme':u.scheme,'hostname':u.hostname,'port':u.port,'path':u.path,'queryOmitted':bool(u.query),'userinfoOmitted':u.username is not None or u.password is not None}
def db_snapshot(p,fn):
    p=pathlib.Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()
    assert not pathlib.Path(str(p)+'-wal').exists() or pathlib.Path(str(p)+'-shm').exists()
    c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3)
    try:
        c.execute('PRAGMA query_only=ON');c.execute('PRAGMA temp_store=MEMORY');c.execute('BEGIN')
        out=fn(c);c.rollback()
    finally:c.close()
    after=p.lstat();assert (s.st_dev,s.st_ino,s.st_uid,s.st_mode)==(after.st_dev,after.st_ino,after.st_uid,after.st_mode)
    return out
def jwt(v):
    try:
        part=v.split('.')[1];o=json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
        return {'parseable':True,'expiresUnixSeconds':o.get('exp') if isinstance(o.get('exp'),(int,float)) else None,'issuedUnixSeconds':o.get('iat') if isinstance(o.get('iat'),(int,float)) else None,'embeddedAccountSha256':sha(str(o.get('https://api.openai.com/auth',{}).get('chatgpt_account_id','')).encode())}
    except Exception:return {'parseable':False}
def profile(p_id,c,ordinal):
    PRIVATE.append(p_id)
    for k in ['access','refresh','key','apiKey','token','accountId','email']:
        if isinstance(c.get(k),str):PRIVATE.append(c[k])
    out={'ordinal':ordinal,'profileIdSha256':sha(p_id.encode()),'credentialSha256':sha(canon(c)),
         'provider':c.get('provider') if c.get('provider')in ['openai','openai-codex','codex','anthropic','google','deepseek','zai','minimax'] else None,
         'type':c.get('type') if c.get('type')in ['oauth','api_key','token']else None,
         'accessPresent':bool(c.get('access')),'refreshPresent':bool(c.get('refresh')),'accountIdPresent':bool(c.get('accountId'))}
    if isinstance(c.get('expires'),(int,float)):out['storedExpiresUnixMs']=c['expires']
    if isinstance(c.get('accountId'),str):out['accountIdSha256']=sha(c['accountId'].encode())
    if isinstance(c.get('access'),str):out['jwt']=jwt(c['access']);out['accessSha256']=sha(c['access'].encode())
    if isinstance(c.get('refresh'),str):out['refreshSha256']=sha(c['refresh'].encode())
    return out
def manager(unit,user=False):
    args=['/usr/bin/systemctl']+(['--user']if user else[])+['show',unit,'--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState,FragmentPath,DropInPaths','--no-pager']
    p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','HOME':str(HOME),'XDG_RUNTIME_DIR':'/run/user/'+str(os.getuid())})
    result={'unit':unit,'userScope':user,'exitCode':p.returncode,'stderrSha256':sha(p.stderr)}
    if p.returncode==0:result['properties']=dict(x.split('=',1)for x in p.stdout.decode().splitlines()if '='in x)
    return result
config_candidates=set()
def unit_projection(p):
    b=read(p,262144,static=True);section='';projected=[];executables=[]
    safe={'User','Group','WorkingDirectory','StateDirectory','RuntimeDirectory','ConfigurationDirectory','ProtectSystem','PrivateTmp','NoNewPrivileges','Restart','ReadOnlyPaths','ReadWritePaths','OnCalendar','OnUnitActiveSec','OnBootSec','Unit','After','Requires','Wants'}
    for line in b.decode().splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        if line.startswith('['):section=line;continue
        if '='not in line:continue
        k,v=line.split('=',1)
        if k in safe:projected.append({'section':section,'key':k,'value':v})
        elif k.startswith('Exec'):
            try:a=shlex.split(v)
            except ValueError:a=[]
            item={'section':section,'key':k,'argumentCount':len(a),'commandSha256':sha(v.encode()),'executable':a[0].lstrip('-+!:@')if a and a[0].lstrip('-+!:@').startswith('/')else None,'flagNames':[t.split('=',1)[0]for t in a[1:]if t.startswith('-')and re.match(r'^--?[A-Za-z][A-Za-z0-9_-]*(=|$)',t)]}
            if item['executable']:executables.append(item['executable'])
            configs=[]
            for i,t in enumerate(a):
                if t.startswith(('-config=','--config=')):configs.append(t.split('=',1)[1])
                elif t in ['-config','--config']and i+1<len(a):configs.append(a[i+1])
            item['configurationPaths']=[x for x in configs if x.startswith('/')and pathlib.Path(x).suffix in ['.hcl','.json','.toml']]
            config_candidates.update(item['configurationPaths']);projected.append(item)
        elif k in ['Environment','EnvironmentFile','LoadCredential','SetCredential']:
            projected.append({'section':section,'key':k,'valueSha256':sha(v.encode()),'variableNames':sorted(set(re.findall(r'\b([A-Z_][A-Z0-9_]*)=',v)))})
    return {'file':meta(p),'sha256':sha(b),'fields':projected,'executablePaths':executables}
report={'schema':'heptabao.desktop-existing-provider-client-readonly.v1','ok':False,'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'productionChanged':False,'providerCalled':False,'authbusNetworkRequests':0,'modelCalled':False,'refreshAttempted':False,'serviceActions':[],'credentialValuesPublished':False,'rawProfileIdsPublished':False,'crossAgentAtomicSnapshot':False,'liveRefreshOwnershipQualified':False}
try:
    assert os.statvfs('/').f_flag & os.ST_RDONLY
    cfgb=read(LIVE/'openclaw.json',private=True,static=True);assert sha(cfgb)==EXPECTED;cfg=json.loads(cfgb)
    entries=cfg.get('plugins',{}).get('entries',{});bus=entries.get('openclaw-authbus',{});bc=bus.get('config',{})
    report['configurationSha256']=sha(cfgb);report['defaultModel']=cfg.get('agents',{}).get('defaults',{}).get('model')
    agents=cfg['agents']['list'];assert len(agents)==8
    report['agents']=[{'id':a['id'],'model':a.get('model',report['defaultModel']),'explicitModel':a.get('model')is not None}for a in agents]
    report['authbus']={'enabled':bus.get('enabled'),'address':url(bc.get('address')),'configuration':{k:bc.get(k)for k in ['hostId','leader','publishNew','manageOrder','pollIntervalMs','releaseGeneration','schedulerMode','enforceRefreshLeases','orderExcludeAgentIds','caFile','roleIdFile','secretIdFile']}}
    report['providers']={k:{'api':v.get('api'),'baseUrl':url(v.get('baseUrl')),'agentRuntime':v.get('agentRuntime'),'modelIds':[m.get('id')for m in v.get('models',[])],'apiKeyConfigured':v.get('apiKey')is not None}for k,v in cfg.get('models',{}).get('providers',{}).items()}
    codex=entries.get('codex',{});cc=codex.get('config',{});app=cc.get('appServer',{})
    report['codexConfiguration']={'enabled':codex.get('enabled'),'allowed':'codex'in cfg.get('plugins',{}).get('allow',[]),'configKeys':sorted(cc),'appServer':{k:app[k]for k in ['transport','homeScope','command','socketPath']if k in app},'appServerUrl':url(app.get('url')),'environmentNames':sorted(app.get('env',{}))}
    credential_files=[]
    for key in ['caFile','roleIdFile','secretIdFile']:
        value=bc.get(key);assert isinstance(value,str)and pathlib.Path(value).is_relative_to(LIVE/'credentials/authbus')
        m=meta(value);m['kind']=key;m['contentsRead']=key=='caFile'
        if key=='caFile':m['sha256']=sha(read(value,131072,static=True))
        credential_files.append(m)
    report['authbusCredentialFiles']=credential_files
    units=[('hepta-openbao-private-ci.service',False),('hepta-openbao-leaf-renewal.service',False),('hepta-openbao-leaf-renewal.timer',False),('openclaw-gateway.service',True),('ai-max-codex-responses.service',True),('openclaw-authbus-accept-after-restart.service',True),('openclaw-authbus-restart-when-idle.service',True)]
    report['managerBefore']=[manager(*u)for u in units]
    unitpaths=set()
    for unit,user in units:
        p=HOME/'.config/systemd/user'/unit if user else pathlib.Path('/etc/systemd/system')/unit
        if p.is_file()and not p.is_symlink():unitpaths.add(p)
        d=pathlib.Path(str(p)+'.d')
        if d.is_dir():
            for f in sorted(d.iterdir()):
                if f.suffix=='.conf'and f.is_file()and not f.is_symlink():unitpaths.add(f)
    report['unitFiles']=[unit_projection(p)for p in sorted(unitpaths)]
    configs=[]
    for name in sorted(config_candidates):
        p=pathlib.Path(name);item={'path':name,'read':False}
        try:
            b=read(p,1048576,static=True);item['read']=True;item['sha256']=sha(b);item['metadata']=meta(p)
            if p.suffix=='.hcl':
                txt=b.decode();item['blockKinds']=re.findall(r'^\s*(storage|listener|seal)\s+"([A-Za-z0-9_-]+)"\s*\{',txt,re.M)
                item['safeFields']=[{'name':k,'value':v}for k,v in re.findall(r'^\s*(path|address|cluster_address|api_addr|cluster_addr|tls_cert_file|tls_key_file|tls_client_ca_file|log_level)\s*=\s*"([^"\r\n]+)"',txt,re.M)]
                item['booleanFields']={k:v=='true'for k,v in re.findall(r'^\s*(disable_mlock|ui|tls_disable|tls_require_and_verify_client_cert)\s*=\s*(true|false)',txt,re.M)}
            elif p.suffix=='.json':
                j=json.loads(b);item['topLevelKeys']=[k for k in ['storage','listener','api_addr','cluster_addr','disable_mlock','data_dir','bind','port','tls']if k in j];item['configStructureSha256']=sha(canon({k:type(v).__name__ for k,v in j.items()}))
        except Exception as e:item['errorClass']=type(e).__name__
        configs.append(item)
    report['providerConfigurationFiles']=configs
    def registry(c):
        r=c.execute("SELECT install_records_json,plugins_json FROM installed_plugin_index WHERE index_key='installed-plugin-index'").fetchone();assert r
        installs,registered=json.loads(r[0]),json.loads(r[1]);out=[]
        for v in registered:
            if v.get('pluginId')not in ['codex','openclaw-authbus']:continue
            root=pathlib.Path(v['rootDir']);assert root.is_relative_to(LIVE)or root.is_relative_to(HOME/'.npm-global/lib/node_modules')
            item={k:v.get(k)for k in ['pluginId','rootDir','enabled','origin','startup']};item['installedVersion']=installs.get(v['pluginId'],{}).get('version');item['publicSourcePins']={}
            for rel in ['package.json','openclaw.plugin.json','dist/shared-client-4ICy3U6d.js','dist/config-CYEDnLJ2.js','index.js','runtime-refresh-policy.js','codex-client-recycler.js']:
                p=root/rel
                if p.is_file()and not p.is_symlink():item['publicSourcePins'][rel]={'sha256':sha(read(p,16777216,static=True)),'bytes':p.stat().st_size}
            out.append(item)
        return out
    report['registry']=db_snapshot(LIVE/'state/openclaw.sqlite',registry)
    plugin=LIVE/'extensions/openclaw-authbus'
    report['authbusInstalledSourcePins']={}
    for name in ['index.js','runtime-refresh-policy.js','codex-client-recycler.js','order-policy.js','lease-assignments.js','provider-error-classifier.js','bad-refresh-quarantine.js','package.json']:
        p=plugin/name
        if p.is_file()and not p.is_symlink():report['authbusInstalledSourcePins'][name]={'sha256':sha(read(p,16777216,static=True)),'bytes':p.stat().st_size}
    agent_sources=[]
    for a in agents:
        p=LIVE/'agents'/a['id']/'agent/openclaw-agent.sqlite';assert re.fullmatch(r'[A-Za-z0-9_-]{1,100}',a['id'])
        item={'agentId':a['id'],'database':str(p),'present':p.is_file()}
        if p.is_file():
            def collect(c):
                rows=c.execute("SELECT store_json FROM auth_profile_store WHERE store_key='primary'").fetchall();assert len(rows)==1
                o=json.loads(rows[0][0]);ps=o.get('profiles',{});return {'rawStoreSha256':sha(rows[0][0].encode()),'canonicalStoreSha256':sha(canon(o)),'profileCount':len(ps),'profiles':[profile(k,v,n)for n,(k,v)in enumerate(ps.items(),1)],'orderSha256':sha(canon(o.get('order'))),'usageStatsSha256':sha(canon(o.get('usageStats')))}
            item.update(db_snapshot(p,collect))
        agent_sources.append(item)
    report['agentSources']=agent_sources
    states=[]
    for name in ['status.json','applied-profiles.json','publish-baseline.json','refresh-backoff.json','bad-refresh-quarantine.json','lease-epochs.json']:
        p=LIVE/'authbus'/name;item={'name':name,'present':p.is_file()}
        if p.is_file():
            b=read(p,2097152,private=True);o=json.loads(b);item['fileSha256']=sha(b)
            if name=='status.json':
                item['status']={k:v for k,v in o.items()if isinstance(v,(bool,int,float))or k in ['hostId','schedulerMode']}
                if isinstance(o.get('error'),str):item['errorSha256']=sha(o['error'].encode())
                rr=o.get('codexAppServerRecycle')
                if isinstance(rr,dict):item['codexAppServerRecycle']={k:v for k,v in rr.items()if isinstance(v,(int,bool))}
            elif name in ['applied-profiles.json','publish-baseline.json']:
                ps=o.get('profiles',{});item['profiles']=[{'profileIdSha256':sha(k.encode()),'credentialDigest':v if isinstance(v,str)and re.fullmatch('[0-9a-f]{64}',v)else None}for k,v in ps.items()]
            else:
                entries=o.get('entries',o.get('profiles',{}));item['entryCount']=len(entries);item['entries']=[]
                for k,v in entries.items():
                    if not isinstance(v,dict):continue
                    row={'entryKeySha256':sha(k.encode()),'valueSha256':sha(canon(v))}
                    row.update({x:v[x]for x in ['epoch','failures','nextAttemptAt','firstDetectedAt','lastDetectedAt','expiresAt','leaseExpiresAt']if isinstance(v.get(x),(int,float))})
                    if v.get('status')in ['active','expired','shadow','unassigned','accepted','revoked']:row['status']=v['status']
                    item['entries'].append(row)
            states.append(item)
    report['authbusLocalState']=states
    p=HOME/'.codex/auth.json'
    report['nativeUserAuth']={'present':p.is_file()}
    if p.is_file():
        b=read(p,2097152,private=True);o=json.loads(b);t=o.get('tokens',{});token=t.get('access_token');refresh=t.get('refresh_token');account=t.get('account_id')
        PRIVATE.extend(v for v in [token,refresh,account]if isinstance(v,str))
        n={'present':True,'fileSha256':sha(b),'authMode':o.get('auth_mode')if o.get('auth_mode')in ['chatgpt','apikey']else None,'accessPresent':isinstance(token,str),'refreshPresent':isinstance(refresh,str),'accountPresent':isinstance(account,str)}
        if all(isinstance(x,str)for x in [token,refresh,account]):
            n.update({'nativeGenerationSha256':sha(canon({'access':token,'refresh':refresh,'accountId':account})),'accessSha256':sha(token.encode()),'refreshSha256':sha(refresh.encode()),'accountIdSha256':sha(account.encode()),'jwt':jwt(token)})
            n['matchingSdkProfiles']=[{'agentId':a['agentId'],'ordinal':p['ordinal'],'profileIdSha256':p['profileIdSha256']}for a in agent_sources for p in a.get('profiles',[])if p.get('accessSha256')==n['accessSha256']and p.get('refreshSha256')==n['refreshSha256']and p.get('accountIdSha256')==n['accountIdSha256']]
        report['nativeUserAuth']=n
    report['managerAfter']=[manager(*u)for u in units];report['managerObservationsEqual']=report['managerBefore']==report['managerAfter']
    report['allStaticFilesUnchanged']=all(sha(pathlib.Path(p).read_bytes())==h for p,h in STATIC.items());assert report['allStaticFilesUnchanged']
    report['readFilePins']=PINS;report['ok']=True
except Exception as e:
    import traceback
    report['errorClass']=type(e).__name__;report['frames']=[{'file':pathlib.Path(f.filename).name,'line':f.lineno}for f in traceback.extract_tb(e.__traceback__)[-4:]]
report['notes']=NOTES
raw=canon(report)
assert all(not isinstance(v,str)or len(v)<8 or v.encode()not in raw for v in PRIVATE)
z=zlib.compress(raw,9)
print(json.dumps({'schema':'heptabao.public-readonly-compressed-envelope.v1','ok':report['ok'],'bytes':len(raw),'sha256':sha(raw),'zlibBytes':len(z),'zlibSha256':sha(z),'dataBase64':base64.b64encode(z).decode()},sort_keys=True,separators=(',',':')))
raise SystemExit(0 if report['ok']else 1)
