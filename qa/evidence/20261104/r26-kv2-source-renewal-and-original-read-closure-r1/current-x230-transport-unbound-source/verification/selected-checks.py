import ast,copy,hashlib,json,types
from pathlib import Path
root=Path('/tmp/heptabao_current_x230_source_r1')
d=json.loads((root/'input.json').read_text())
checks=[]
def need(n,b):
    checks.append({'name':n,'passed':bool(b)})
    if not b: raise AssertionError(n)
def constants(text):
    out={}
    for n in ast.parse(text).body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            try: out[n.targets[0].id]=ast.literal_eval(n.value)
            except (ValueError,TypeError): pass
    return out
def selected(text,names,env):
    tree=ast.parse(text)
    defs=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    need('selected exact '+','.join(names),len(defs)==len(names))
    exec(compile(ast.Module(body=defs,type_ignores=[]),'<actual-selected>','exec'),env)
def defined(text):
    return [(n.name,ast.get_source_segment(text,n)) for n in ast.walk(ast.parse(text)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
def negative(name,fn):
    try: fn()
    except (AssertionError,RuntimeError,PermissionError,OSError): need(name,True)
    else: need(name,False)
for name,text in {**d['source'],**d['wrappers']}.items():
    compile(ast.parse(text),name,'exec')
    need(name+' explicitly unbound',constants(text).get('BINDING_READY') is False)
for name,text in d['source'].items():
    c=constants(text)
    need(name+' exact seven unresolved records',c['FILES']==d['table'] and len(c['FILES'])==7 and all(x['bytes'] is None and x['sha256'] is None and x['version'] is None for x in c['FILES']))
    need(name+' current product canonical',c.get('HEAD',c.get('CANONICAL'))==d['layout']['canonical']['commit'] and c['TREE']==d['layout']['canonical']['tree'])
for name in d['wrappers']:
    c=constants(d['wrappers'][name])
    need(name+' all actual receive pins remain unresolved',all(c[x] is None for x in ['NORMAL61_SHA','NORMAL_NATIVE_SHA','NORMAL_RELEASE_SHA','TRANSFER_SHA']))
    need(name+' admission before fixture creation',d['wrappers'][name].index(' normal61_admission()')<d['wrappers'][name].index("OUT.parent.mkdir"))
    before_main=[v for n,v in defined(d['before'][name]) if n=='main'][0]
    after_main=[v for n,v in defined(d['wrappers'][name]) if n=='main'][0]
    need(name+' original runtime body identical after explicit name/schema mapping',after_main.replace('normal61_admission','normal60_admission').replace('heptabao.4e808-','heptabao.df026-')==before_main)
receiver=d['source']['receiver']
env={'json':json,'CANONICAL':d['layout']['canonical']['commit'],'TREE':d['layout']['canonical']['tree'],'digest':lambda b:hashlib.sha256(b).hexdigest(),'result':{}}
selected(receiver,['need','verify_normal61'],env)
base={'normal61-result.public.json':d['normal'].encode(),'native-build.public.json':d['native'].encode(),'groups.json':d['groups'].encode()}
env['verify_normal61'](base)
need('actual ROG 4e808 61 accepted',env['result']['normal61_qualification_verified'] is True)
normal=json.loads(d['normal'])
mutations=[
 ('old selected60 rejected',lambda n:n.__setitem__('selected_test_total',60)),
 ('old product source rejected',lambda n:n.__setitem__('source_commit','df026fe323dd7cf0f0ec57d7d2d9c5a79897053c')),
 ('old normal60 driver rejected',lambda n:n.__setitem__('controller_sha256','1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40')),
 ('original60 failure rejected',lambda n:n.__setitem__('original_60_status','failed')),
 ('missing new1 rejected',lambda n:n.pop('same_root_publication_regression')),
 ('new1 wrong name rejected',lambda n:n['same_root_publication_regression'].__setitem__('actual_test_names',['wrong'])),
 ('new1 group budget 601 rejected',lambda n:n['same_root_publication_regression'].__setitem__('new_total_group_cap_seconds',601)),
 ('new1 not clipped rejected',lambda n:n['same_root_publication_regression'].__setitem__('clamped_to_original_outer_deadline',False)),
 ('new1 changed original denominator rejected',lambda n:n['same_root_publication_regression'].__setitem__('original_44_7_9_denominators_unchanged',False)),
 ('owned survivor rejected',lambda n:n['cleanup'][0].__setitem__('remaining',[{'pid':123}])),
]
for label,change in mutations:
    n=copy.deepcopy(normal);change(n);inp=dict(base);inp['normal61-result.public.json']=json.dumps(n).encode()
    negative(label,lambda:env['verify_normal61'](inp))
relay=d['source']['relay'];c=constants(relay)
need('fence pins bind original actual bytes',len(d['marker'].encode())==2709 and hashlib.sha256(d['marker'].encode()).hexdigest()==c['OLD_FENCE_SHA256'])
need('fence root remains old and transport root fresh',"OLD_FENCE_ROOT=BASE/'normal-cold-h2-x230-transfer-r1'" in relay and "ROOT=BASE/'normal-same-root-publication-x230-transfer-r1'" in relay)
need('fence before any new root creation',relay.index("result['effect_fence_before']=acquire_effect_fence()")<relay.index(" ROOT.mkdir("))
need('named fence check before actual endpoints',relay.index("result['effect_fence_before_endpoints']=verify_effect_fence()")<relay.index(" receiver=start_child("))
need('cleanup final fence required before success publication',"not (fence_verified_before and fence_verified_after_cleanup and fence_closed)" in relay)
need('old relay remains unknown and not terminated',"result['original_relay_state']='UNKNOWN';result['original_relay_termination_proven']=False" in relay)
fields=['st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns']
class Cancelled(BaseException): pass
class FakePath:
    def __init__(self,s,fs): self.s,self.fs=s,fs
    def __str__(self): return self.s
    @property
    def name(self): return self.s.rsplit('/',1)[-1]
    def __truediv__(self,x): return FakePath(self.s+'/'+x,self.fs)
    def lstat(self): return self.fs.statof('parent')
class FakeOS:
    O_RDONLY=0;O_DIRECTORY=1;O_NOFOLLOW=2;O_NONBLOCK=4;SEEK_SET=0
    def __init__(self):
        self.records={};self.opened=[];self.close_calls=[];self.opens=0;self.fail_open=None;self.fail_close=None;self.signal_open=None;self.bad_named=None
        self.rows={'parent':list(c['OLD_FENCE_BASE_ID'])+[200,20480,1,2],'root':list(c['OLD_FENCE_ROOT_ID']),'marker':list(c['OLD_FENCE_MARKER_ID'])}
        self.payload=d['marker'].encode();self.env=None
    def statof(self,label):
        return types.SimpleNamespace(**dict(zip(fields,self.rows[label])))
    def open(self,name,flags,*,dir_fd=None):
        assert self.env['protected']>0
        self.opens+=1
        if self.fail_open==self.opens: raise PermissionError('fake open')
        label=['parent','root','marker'][len(self.opened)]
        assert flags & self.O_NOFOLLOW
        if label!='marker': assert flags & self.O_DIRECTORY
        if label=='parent': assert dir_fd is None
        else: assert dir_fd==self.opened[-1]
        fd=10+len(self.opened);self.opened.append(fd);self.records[fd]={'label':label,'offset':0,'closed':False}
        if self.signal_open==self.opens:self.env['pending_signal']=15
        return fd
    def fstat(self,fd):
        r=self.records[fd];assert not r['closed'];return self.statof(r['label'])
    def stat(self,name,*,dir_fd,follow_symlinks):
        assert follow_symlinks is False
        parent=self.records[dir_fd]['label']
        label='root' if parent=='parent' else 'marker'
        row=copy.copy(self.rows[label])
        if self.bad_named==label:row[1]+=1
        return types.SimpleNamespace(**dict(zip(fields,row)))
    def lseek(self,fd,offset,whence):assert offset==0 and whence==0;self.records[fd]['offset']=0;return 0
    def read(self,fd,n):
        r=self.records[fd];assert r['label']=='marker' and not r['closed'] and n>0
        out=self.payload[r['offset']:r['offset']+n];r['offset']+=len(out);return out
    def close(self,fd):
        assert self.env['protected']>0
        self.close_calls.append(fd)
        if self.records[fd]['label']==self.fail_close: raise OSError('fake close')
        assert not self.records[fd]['closed'];self.records[fd]['closed']=True
def fresh():
    fs=FakeOS();env={'os':fs,'hashlib':hashlib,'protected':0,'pending_signal':None,'Cancelled':Cancelled,'fence_descriptors':[],'remaining':lambda:300}
    env.update({k:v for k,v in c.items() if k.startswith('OLD_FENCE_')})
    env['BASE']=FakePath('/fixed/base',fs);env['OLD_FENCE_ROOT']=FakePath('/fixed/base/normal-cold-h2-x230-transfer-r1',fs);fs.env=env
    selected(relay,['identity','fence_open_fd','verify_effect_fence','acquire_effect_fence','close_effect_fence'],env)
    return fs,env
fs,e=fresh();first=e['acquire_effect_fence']();need('three real selected opens use fake descriptors',len(fs.opened)==3 and first['original_relay_state']=='UNKNOWN')
fs.rows['parent'][5:]=[300,99999,123,456];e['verify_effect_fence']();need('only shared-parent mutable suffix can change',True)
need('all three close once',e['close_effect_fence']() and len(fs.close_calls)==3 and len(set(fs.close_calls))==3)
for label,mutation in [
 ('root named replacement rejected',lambda fs:setattr(fs,'bad_named','root')),
 ('marker named replacement rejected',lambda fs:setattr(fs,'bad_named','marker')),
 ('shared parent inode drift rejected',lambda fs:fs.rows['parent'].__setitem__(1,999)),
 ('marker content drift rejected',lambda fs:setattr(fs,'payload',b'X'+fs.payload[1:])),
 ('extra marker byte rejected',lambda fs:setattr(fs,'payload',fs.payload+b'X')),
 ('owned root metadata drift rejected',lambda fs:fs.rows['root'].__setitem__(7,1)),
]:
    fs,e=fresh();e['acquire_effect_fence']();mutation(fs)
    negative(label,e['verify_effect_fence']);need(label+' still closes all once',e['close_effect_fence']() and len(fs.close_calls)==3)
fs,e=fresh();fs.fail_open=2;negative('second open failure preserved',e['acquire_effect_fence']);need('partial acquisition closes only owned fd',e['close_effect_fence']() and len(fs.close_calls)==1 and len(e['fence_descriptors'])==1)
fs,e=fresh();fs.signal_open=2
try:e['acquire_effect_fence']()
except Cancelled:need('cancellation after second acquisition observed',True)
else:need('cancellation after second acquisition observed',False)
need('cancelled acquisition registered before close',len(e['fence_descriptors'])==2 and e['close_effect_fence']() and len(fs.close_calls)==2)
fs,e=fresh();e['acquire_effect_fence']();fs.fail_close='marker';need('close failure is not green',e['close_effect_fence']() is False);before=len(fs.close_calls);need('failed close never retried',e['close_effect_fence']() is False and len(fs.close_calls)==before)
need('close error explicit ledger',e['fence_descriptors'][2]['close_attempted'] and not e['fence_descriptors'][2]['closed'] and e['fence_descriptors'][2]['error_type']=='OSError')
fs,e=fresh()
def expired():raise RuntimeError('original 300 exhausted')
e['remaining']=expired;negative('expired before acquisition opens no fd',e['acquire_effect_fence']);need('expired no resources fake',not fs.opened and e['close_effect_fence']())
result={'schema':'heptabao.current4e808-x230-source-selected-checks.v1','status':'passed','checks':checks,'check_count':len(checks),'python_sources_compiled_only':5,'actual_candidate_modules_executed':0,'selected_actual_functions_only':True,'fake_os':True,'actual_native_descriptors':0,'remote_host_calls':0,'children':0,'product_calls':0,'test_denominators_31_69_preserved':True,'old_unknown_replayed':False}
(root/'result.public.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='checks'},sort_keys=True))
