import ast,hashlib,json,pathlib,sys,types,copy,re,base64,time,math
root=pathlib.Path("/tmp/authbus-complete-outer-r3-sb6o2f4e")
sources={}
rows=[]
for p in sorted(root.iterdir()):
 if p.suffix=='.py':
  raw=p.read_bytes();s=raw.decode();ast.parse(s,filename=p.name);compile(s,p.name,'exec')
  rows.append({'file':p.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()})
  sources[p.name]=s
source=sources['mac_current_outer_r3.py'];tree=ast.parse(source)
assert hashlib.sha256(source.encode()).hexdigest()=='986194f0da2d278986589d5ec757fb50a040182db6f610addba9469ee97e1be5'
defs={node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
selected=[defs[n] for n in ('Refused','need','sha','encoded','canonical','digest','exact_json','seed_documents')]
response=next(n for n in defs['LoopbackHTTP'].body if isinstance(n,ast.FunctionDef) and n.name=='response')
capture=defs['capture_once']
ns={'hashlib':hashlib,'json':json,'re':re,'copy':copy,'time':time,'base64':base64,
    'MAX_HTTP_BODY':2*1024*1024,'Path':pathlib.Path}
events=[]
def audit(event,args):
 if event in ('open','os.system','os.posix_spawn','subprocess.Popen','socket.__new__','socket.connect','socket.bind') or event.startswith(('socket.','subprocess.')):
  events.append(event);raise AssertionError('unexpected_component_io_'+event)
sys.addaudithook(audit)
exec(compile(ast.Module(body=selected,type_ignores=[]),'selected-pure-defs','exec'),ns)
exec(compile(ast.Module(body=[response],type_ignores=[]),'selected-http-response','exec'),ns)
tests=[]
def record(name,passed):
 assert passed,name;tests.append({'case':name,'passed':True})
class Fake:
 def __init__(self,chunks):self.chunks=list(chunks)
 def recv(self,_sock,_until):return self.chunks.pop(0) if self.chunks else b''
 def left(self,_until):return 1
def check_response(name,chunks,expected=None,refuse=False):
 try:
  result=ns['response'](Fake(chunks),None,10)
  record(name,not refuse and result==expected)
 except ns['Refused']:
  record(name,refuse)
check_response('content_length_object',[b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'],(200,b'{}','content-length'))
check_response('split_head_and_payload',[b'HTTP/1.1 200 OK\r',b'\nContent-Length: 2\r\n\r',b'\n{',b'}'],(200,b'{}','content-length'))
check_response('chunked_split',[b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r',b'\n{}\r\n0\r\n',b'\r\n'],(200,b'{}','chunked'))
check_response('nobody_204',[b'HTTP/1.1 204 No Content\r\n\r\n'],(204,b'','no-body'))
check_response('close_delimited',[b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}',b''],(200,b'{}','tls-close-notify'))
for name,data in [
 ('duplicate_length',b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}'),
 ('length_and_chunk',b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}'),
 ('short_body',b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}'),
 ('surplus_body',b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}'),
 ('oversize',b'HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n'),
 ('bad_chunk_end',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}xx0\r\n\r\n'),
 ('unreviewed_trailer',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-X: x\r\n\r\n'),
 ('nobody_payload',b'HTTP/1.1 204 No Content\r\n\r\n{}'),
 ('compression',b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}'),
 ('short_header',b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'),
 ('folded_header',b'HTTP/1.1 200 OK\r\n X-a: 2\r\nContent-Length: 2\r\n\r\n{}')
]:check_response(name,[data],refuse=True)
for value in (b'{"a":1,"a":2}',b'{"a":NaN}'):
 try:ns['exact_json'](value);record('invalid_json_rejected',False)
 except ns['Refused']:record('duplicate_or_nonfinite_rejected',True)
packet={'targetProfileIds':['p1','p2'],'credentials':{'p1':{'provider':'openai','type':'oauth','accountId':'a1','access':'fake-only-1','refresh':'fake-only-r1','expires':1},
'p2':{'provider':'openai','type':'oauth','accountId':'a2','email':'fake@example.invalid','access':'fake-only-2','refresh':'fake-only-r2','expires':1}}}
docs,managed=ns['seed_documents'](packet)
record('exact_two_profile_payloads_and_two_identities',len(docs)==5 and len(managed)==2 and len(docs['manifest']['profiles'])==2)
record('optional_email_matches_js_undefined_omission',managed[0]['identityDigest']==ns['digest']({'provider':'openai','type':'oauth','accountId':'a1'}))
record('persistent_order_not_enforced_or_copied',docs['order-policy']['providers']['openai']['enforceManagedOrder'] is False and [p['profileId'] for p in docs['order-policy']['providers']['openai']['candidates']]==['p2','p1'])
# Invoke the unchanged actual capture_once function with in-memory dependencies.
# No module entrypoint, SQLite, fd, socket, sandbox or child is executed.
fake_entry=types.ModuleType('mac_current_capture_entry_r1')
fake_entry.capture_profile=lambda _stage:b'fake-only-sandbox\n'
sys.modules['mac_current_capture_entry_r1']=fake_entry
ns.update(ROOT=pathlib.Path('/owned/synthetic'),QA=pathlib.Path('/owned/synthetic/qa'),
          ENTRY_NAMES=('entry.py',),SYNTHETIC={'stdoutSha256':'fake-proof'},CAPTURE_SECONDS=45)
exec(compile(ast.Module(body=[capture],type_ignores=[]),'selected-capture-caller','exec'),ns)
class Ctx:
 def __init__(self):self.until=time.monotonic()+900;self.unknown=False
 def remaining(self,_until=None):return 1
class Guard:
 def mkdir_new(self,_p):pass
 def write_new(self,_p,_raw):return {}
class Commands:
 def __init__(self,raw):self.raw=raw
 def run(self,*_a,**_kw):return {'exitCode':1,'completeBeforeDeadline':True,'outcomeUnknown':False},self.raw,b''
for name,raw,unknown in [('array',b'[]',True),('null',b'null',True),
 ('malformed',b'broken',True),('failed_unknown',b'{"ok":false,"outcomeUnknown":true}',True),
 ('failed_known',b'{"ok":false,"outcomeUnknown":false}',False)]:
 ctx=Ctx()
 try:ns['capture_once'](ctx,Guard(),Commands(raw),'before',{'entry.py':'0'*64},b'{}','0'*64);record(name,False)
 except Exception:record('capture_report_'+name,ctx.unknown is unknown)
record('no_io_events',events==[])
print(json.dumps({'schema':'heptabao.mac-complete-outer-offline-source-check.r1','ok':True,
 'pythonSourcesAstCompiled':len(rows),'sources':rows,'pureComponentCount':len(tests),'checks':tests,
 'completeModulesExecuted':False,'productionInputsOpened':False,'hostContacted':False,
 'sqliteConnectionsOpened':0,'socketsCreated':0,'childrenStarted':0,
 'scope':'AST of complete public source; selected actual pure functions with explicit in-memory dependencies only'},
 sort_keys=True))
