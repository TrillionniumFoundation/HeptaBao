#!/usr/bin/env python3
"""Single synthetic two-case observation of the unchanged original SDK wire."""
import ast,hashlib,json,os,socket,ssl,stat,sys,threading,time,types
from pathlib import Path
OLD=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3')
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-wire-sequence-20261106-r1')
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PINS={'mac_owned_unreaped_r1.py':'d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
 'mac_owned_commands_r1.py':'71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
 'main3_sdk_phase.py':'ea8c5ad8abf252568bae5ca20c34ebf96152bd0822f27b2cb412f1e0e0838f76',
 'main3_sdk_wire_r2.mjs':'2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'}
FIXED={NODE:'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
 '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
START=time.monotonic();UNTIL=START+60
opened=closed=0;commands=None;peers=[]
class Refused(RuntimeError):pass
def need(value,code):
 if not value:raise Refused(code)
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,maximum=2097152,pin=None,system=False):
 global opened,closed
 need(time.monotonic()<UNTIL,'original_outer_deadline')
 path=Path(path);before=path.lstat()
 need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,'regular_bounded_file')
 if system:need(before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o755,'fixed_system_executable_custody')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);opened+=1
 try:
  need(identity(before)==identity(os.fstat(fd)),'same_open_named_file')
  raw=bytearray()
  while True:
   need(time.monotonic()<UNTIL,'original_outer_deadline')
   part=os.read(fd,min(65536,maximum+1-len(raw)))
   if not part:break
   raw.extend(part);need(len(raw)<=maximum,'file_bound')
  need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'unchanged_file_namespace')
  if pin:need(hashlib.sha256(raw).hexdigest()==pin,'exact_public_source_pin')
  return bytes(raw)
 finally:os.close(fd);closed+=1
def create(path,raw):
 global opened,closed
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);opened+=1
 try:
  view=memoryview(raw)
  while view:
   need(time.monotonic()<UNTIL,'original_outer_deadline')
   n=os.write(fd,view);need(n>0,'write_progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd);closed+=1
 need(read(path)==raw,'create_only_readback')
def command(label,argv,maximum=65536):
 need(UNTIL-time.monotonic()>20,'room_for_original_command_and_cleanup')
 row,out,err=commands.run(label,argv,until=min(UNTIL-10,time.monotonic()+10),maximum=maximum)
 row.pop('stdoutSha256',None);row.pop('stderrSha256',None);row['streamDigestsWithheld']=True
 need(not row['outcomeUnknown'] and row['streamsClosed'] and row['cleanup'].get('ok') is True,
  'original_child_custody_unknown_no_successor')
 return row,out,err

PROBE="import fs from 'node:fs';\nimport https from 'node:https';\nimport {createHash} from 'node:crypto';\nimport {installWireFence} from './main3_sdk_wire_r2.mjs';\nconst p=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));\nconst until=performance.now()+7000;\nconst originalRequest=https.request;\nconst observations=[],socketIds=new WeakMap();let nextSocket=0,activeRequests=0,fence=null;\nconst report={schema:'heptabao.synthetic-original-wire-two-request-node.r1',ok:false,\n case:p.case,platform:process.platform,node:process.version,\n originalWireByteUnchanged:true,pinVerifiedDirectLocalVariableRead:false,\n pinVerifiedDerivedFromExactOriginalCallbackReturn:true,providerCalled:false,\n productionCredentialsRead:false,observations,wire:[],closures:null,hooksRestored:false};\nconst check=(v,c)=>{if(!v)throw Object.assign(new Error(c),{safeCode:c});};\nconst fixedError=e=>typeof e?.safeCode==='string'&&/^sdk_wire_[a-z_]+$/.test(e.safeCode)?e.safeCode:\n ['ECONNRESET','ECONNREFUSED','EPIPE','ETIMEDOUT','EPERM','EACCES'].includes(e?.code)?e.code:'UNPROJECTED';\nconst hash=b=>createHash('sha256').update(b).digest('hex');\nfunction socketSnapshot(socket){\n const snapshot={connecting:socket.connecting===true,secureConnecting:socket.secureConnecting===true,\n  destroyed:socket.destroyed===true,readableEnded:socket.readableEnded===true,writableEnded:socket.writableEnded===true,\n  authorized:socket.authorized===true,sessionReused:null,certificateRawAvailable:false,certificateLeafMatches:false,\n  peerCertificateGetterThrew:false,actualRemoteEndpointMatches:socket.remoteAddress==='127.0.0.1'&&socket.remotePort===p.port};\n try{snapshot.sessionReused=socket.isSessionReused()===true;}catch{snapshot.sessionReuseGetterThrew=true;}\n try{const raw=socket.getPeerCertificate()?.raw;snapshot.certificateRawAvailable=Buffer.isBuffer(raw);\n  snapshot.certificateLeafMatches=snapshot.certificateRawAvailable&&hash(raw)===p.leafSha256;\n }catch{snapshot.peerCertificateGetterThrew=true;}\n return snapshot;\n}\nfunction observedRequest(options,callback){\n const record={ordinal:observations.length+1,pinCallbackCalls:0,pinCallbackUndefinedReturns:0,\n  pinCallbackThrew:false,secureConnectEvents:0,requestClosed:false,requestErrors:0,\n  socketObserved:false,socketClosed:false,responseObserved:false};\n observations.push(record);\n const originalPin=options.checkServerIdentity;\n check(typeof originalPin==='function','synthetic_original_pin_callback_present');\n const observedOptions={...options,checkServerIdentity:function(...args){\n  record.pinCallbackCalls++;\n  record.pinHostIsExactTarget=args[0]==='127.0.0.1';\n  const raw=args[1]?.raw;record.pinCertificateRawAvailable=Buffer.isBuffer(raw);\n  record.pinCertificateLeafMatches=Buffer.isBuffer(raw)&&hash(raw)===p.leafSha256;\n  try{const returned=Reflect.apply(originalPin,this,args);\n   if(returned===undefined)record.pinCallbackUndefinedReturns++;\n   return returned;\n  }catch(error){record.pinCallbackThrew=true;throw error;}\n }};\n let request;\n request=Reflect.apply(originalRequest,https,[observedOptions,function(response){\n  record.responseObserved=true;record.status=response.statusCode;\n  record.reqReusedSocketAtResponse=request.reusedSocket===true;\n  record.pinVerifiedDerivedAtResponse=record.pinCallbackUndefinedReturns>0;\n  record.pinDerivationIsDirectVariableRead=false;\n  record.responseSocket=socketSnapshot(response.socket);\n  return Reflect.apply(callback,this,[response]);\n }]);\n activeRequests++;\n request.once('socket',socket=>{\n  if(!socketIds.has(socket))socketIds.set(socket,++nextSocket);\n  record.socketOrdinal=socketIds.get(socket);record.socketObserved=true;\n  record.reqReusedSocketAtAssignment=request.reusedSocket===true;\n  record.assignedSocket=socketSnapshot(socket);\n  socket.once('secureConnect',()=>{record.secureConnectEvents++;record.secureSocket=socketSnapshot(socket);});\n  socket.once('close',()=>{record.socketClosed=true;});\n });\n request.once('error',error=>{record.requestErrors++;record.fixedRequestError=fixedError(error);});\n request.once('close',()=>{record.requestClosed=true;activeRequests--;});\n return request;\n}\nfunction request(path,method,body){\n return new Promise((resolve,reject)=>{\n  const headers={Accept:'application/json'};\n  if(body!==undefined){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(body);}\n  const req=https.request({protocol:'https:',hostname:'127.0.0.1',port:p.port,path,method,\n   ca:fs.readFileSync(p.certificate),rejectUnauthorized:true,timeout:15000,headers},res=>{\n    let count=0;\n    res.on('data',part=>{count+=part.length;});\n    res.once('end',()=>resolve({status:res.statusCode,responseBytes:count,complete:res.complete===true}));\n   });\n  req.once('error',reject);\n  req.end(body);\n });\n}\ntry{\n check(p.case==='canonical-close'||p.case==='keep-alive-control','synthetic_fixed_case');\n https.request=observedRequest;\n fence=installWireFence({address:'https://127.0.0.1:'+p.port,ca:fs.readFileSync(p.certificate),\n  certificateSha256:p.leafSha256,hostId:'synthetic-mac',managed:[{key:'synthetic-1'},{key:'synthetic-2'},{key:'synthetic-3'}],\n  remainingMs:cap=>{const left=Math.floor(until-performance.now());check(left>0,'synthetic_original_deadline');return Math.min(cap,left);}});\n report.requests=[];\n for(const [path,method,body]of[\n  ['/v1/auth/approle/login','POST',JSON.stringify({role_id:'synthetic-role',secret_id:'synthetic-secret'})],\n  ['/v1/openclaw-auth/data/manifest','GET',undefined]]){\n  try{report.requests.push({complete:true,result:await request(path,method,body)});}\n  catch(error){report.requests.push({complete:false,fixedError:fixedError(error)});break;}\n }\n report.observationCompleted=observations.length===2&&observations.every(row=>row.responseObserved);\n}catch(error){report.fixedError=fixedError(error);}\nfinally{\n try{if(fence){await fence.close();report.closures=fence.publicClosure();report.wire=fence.rows;fence.restoreHooks();}}\n catch(error){report.closureError=fixedError(error);}\n report.observerStillInstalledAfterFenceRestore=https.request===observedRequest;\n https.request=originalRequest;report.hooksRestored=https.request===originalRequest;\n report.remainingObservedRequests=activeRequests;\n report.sourceDerivedSameSocket=observations.length===2&&observations[0].socketOrdinal===observations[1].socketOrdinal;\n report.totalObservedSocketObjects=nextSocket;\n report.originalWireRejectedSecond=report.requests?.length===2&&report.requests[1].complete===false;\n report.ok=report.observationCompleted===true&&report.hooksRestored&&report.observerStillInstalledAfterFenceRestore&&\n  activeRequests===0&&observations.every(row=>row.requestClosed&&row.socketClosed)&&\n  report.closures?.ownedHttpsAgentClosed===true&&report.closures.remainingRequestCount===0&&report.closures.remainingSocketCount===0;\n}\nprocess.stdout.write(JSON.stringify(report)+'\\n');process.exitCode=report.ok?0:1;\n"
report={'schema':'heptabao.mac-main3-sdk-original-wire-sequence-observation.r1','ok':False,
 'originalFailedJobId':'1a1b28a4d4c-fc05-7e81','newSyntheticRoot':str(ROOT),
 'originalWireSha256':PINS['main3_sdk_wire_r2.mjs'],'originalWireByteUnchanged':True,
 'originalFailedBusinessAttemptRepeated':False,'originalFailureCauseClaimed':False,
 'sourceCredentialFilesRead':False,'actualSdkOrPluginImported':False,'productServiceStarted':False,
 'providerCalled':False,'productionChanged':False,'privateValuesOrDigestsPublished':False,
 'tccOrAccessControlsChanged':False,'originalNodeMaximumSeconds':10,'outerSeconds':60,'cases':[]}

class Peer:
 def __init__(self,kind,context):
  self.kind=kind;self.context=context;self.stop=threading.Event();self.thread=None
  self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  self.listener.bind(('127.0.0.1',0));self.listener.listen(3);self.listener.settimeout(.1)
  self.port=self.listener.getsockname()[1];self.until=min(UNTIL-5,time.monotonic()+12)
  need(1024<=self.port<=65535,'one_owned_unprivileged_loopback_listener')
  self.result={'case':kind,'connections':0,'requests':0,'acceptedSockets':0,'closedAcceptedSockets':0,
   'requestConnectionOrdinals':[],'sessionReused':[],'listenerClosed':False,'threadJoined':False,
   'allRequestsSyntheticAndExact':False,'errorType':None,'errorCode':None}
 def start(self):
  self.thread=threading.Thread(target=self.serve,name='synthetic-original-wire-peer',daemon=False);self.thread.start()
 def serve(self):
  raw=tls=None
  try:
   while self.result['requests']<2 and not self.stop.is_set() and time.monotonic()<self.until:
    try:raw,_=self.listener.accept()
    except socket.timeout:continue
    self.result['acceptedSockets']+=1;raw.settimeout(min(2,max(.001,self.until-time.monotonic())))
    try:
     tls=self.context.wrap_socket(raw,server_side=True)
     self.result['connections']+=1;connection_ordinal=self.result['connections']
     self.result['sessionReused'].append(bool(tls.session_reused))
     buffered=b''
     while self.result['requests']<2 and not self.stop.is_set() and time.monotonic()<self.until:
      while b'\r\n\r\n' not in buffered:
       part=tls.recv(16384)
       if not part:break
       buffered+=part;need(len(buffered)<=32768,'bounded_synthetic_request')
      if b'\r\n\r\n' not in buffered:break
      header_end=buffered.index(b'\r\n\r\n')
      lines=buffered[:header_end].split(b'\r\n')
      expected=b'POST /v1/auth/approle/login HTTP/1.1' if self.result['requests']==0 else b'GET /v1/openclaw-auth/data/manifest HTTP/1.1'
      need(lines[0]==expected,'exact_ordered_synthetic_route')
      headers={}
      for line in lines[1:]:
       name,sep,value=line.partition(b':')
       need(sep and name.lower() not in headers,'one_bounded_synthetic_header')
       headers[name.lower()]=value.strip()
      need(b'transfer-encoding' not in headers,'synthetic_request_content_length')
      value=headers.get(b'content-length',b'0')
      need(value.isdigit() and len(value)<=5 and int(value)<=1024,'bounded_synthetic_request_body')
      length=int(value)
      while len(buffered)<header_end+4+length:
       part=tls.recv(16384);need(part,'complete_synthetic_request_body')
       buffered+=part;need(len(buffered)<=32768,'bounded_synthetic_request')
      body=buffered[header_end+4:header_end+4+length]
      buffered=buffered[header_end+4+length:]
      if self.result['requests']==0:
       need(json.loads(body)=={'role_id':'synthetic-role','secret_id':'synthetic-secret'},'only_synthetic_login_bytes')
       payload=json.dumps({'auth':{'client_token':'synthetic-only-token-sequence','lease_duration':3600}},separators=(',',':')).encode()
       framing=b'Content-Length: '+str(len(payload)).encode()+b'\r\n'
       response_body=payload
      else:
       need(not body,'empty_synthetic_manifest_get')
       payload=json.dumps({'data':{'data':{'synthetic':True,'padding':'x'*3072},'metadata':{'version':1}}},separators=(',',':')).encode()
       need(len(payload)>2048,'large_synthetic_chunked_body')
       first,second=payload[:137],payload[137:]
       framing=b'Transfer-Encoding: chunked\r\n'
       response_body=(format(len(first),'x').encode()+b';synthetic=one\r\n'+first+b'\r\n'+
        format(len(second),'x').encode()+b'\r\n'+second+b'\r\n0\r\nX-Synthetic-Trailer: done\r\n\r\n')
      self.result['requests']+=1;self.result['requestConnectionOrdinals'].append(connection_ordinal)
      connection=b'close' if self.kind=='canonical-close' else b'keep-alive'
      response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'+framing+b'Connection: '+connection+b'\r\n\r\n'+response_body
      tls.sendall(response)
      if self.kind=='canonical-close':break
    finally:
     if tls is not None:tls.close()
     elif raw is not None:raw.close()
     need(raw.fileno()==-1 and (tls is None or tls.fileno()==-1),'closed_original_accepted_socket')
     self.result['closedAcceptedSockets']+=1;raw=tls=None
   self.result['allRequestsSyntheticAndExact']=self.result['requests']==2
  except BaseException as error:
   self.result['errorType']=type(error).__name__
   self.result['errorCode']=str(error) if isinstance(error,Refused) else None
  finally:
   if tls is not None:tls.close()
   elif raw is not None:raw.close()
 def finish(self):
  self.stop.set();self.listener.close()
  if self.thread is not None:self.thread.join(timeout=min(3,max(.001,UNTIL-time.monotonic())))
  self.result['threadJoined']=self.thread is None or not self.thread.is_alive()
  self.result['listenerClosed']=self.listener.fileno()==-1
  return self.result

try:
 need(sys.platform=='darwin' and os.getuid()==os.geteuid()==501 and Path.cwd()==Path('/Users/qianqi'),
  'exact_original_mac_caller_and_cwd')
 os.umask(0o077)
 sources={name:read(OLD/'qa'/name,pin=pin) for name,pin in PINS.items()}
 for filename,pin in FIXED.items():read(filename,pin=pin)
 openssl_sha=hashlib.sha256(read('/usr/bin/openssl',system=True)).hexdigest()
 report['systemOpenSslWholeFileSha256']=openssl_sha
 nodes=[n for n in ast.parse(sources['main3_sdk_phase.py']).body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
 need(len(nodes)==1,'one_original_profile_function')
 ns={'ROOT':ROOT,'STATE':ROOT/'state','LIVE':Path('/Users/qianqi/.openclaw'),'Path':Path,'json':json,'need':need}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-r3-profile>','exec'),ns)
 for name in ('mac_owned_unreaped_r1','mac_owned_commands_r1'):
  module=types.ModuleType(name);module.__file__=str(OLD/'qa'/(name+'.py'));sys.modules[name]=module
  exec(compile(sources[name+'.py'],module.__file__,'exec'),module.__dict__)
 owned=sys.modules['mac_owned_commands_r1'];signals=owned.Signals();signals.install();commands=owned.Commands(signals)
 os.mkdir(ROOT,0o700)
 for relative in ('qa','plugin','input','private','state','initial','cold-new-process','server','server/tls','server/private'):
  os.mkdir(ROOT/relative,0o700)
 create(ROOT/'qa/observe_original_wire_sequence_r1.mjs',PROBE.encode())
 create(ROOT/'qa/main3_sdk_wire_r2.mjs',sources['main3_sdk_wire_r2.mjs'])
 config=b'[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\nCN = localhost\n[v3]\nsubjectAltName = DNS:localhost,IP:127.0.0.1\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage = serverAuth\n'
 create(ROOT/'server/tls/openssl.cnf',config)
 row,out,err=command('new-synthetic-tls-material',['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-config',str(ROOT/'server/tls/openssl.cnf'),'-keyout',str(ROOT/'server/tls/server.key'),'-out',str(ROOT/'server/tls/server.crt')])
 report['tlsMaterialCommand']=row;need(row['exitCode']==0,'new_synthetic_tls_material_known_zero')
 need(hashlib.sha256(read('/usr/bin/openssl',system=True)).hexdigest()==openssl_sha,'unchanged_system_openssl')
 key_info=(ROOT/'server/tls/server.key').lstat()
 need(stat.S_ISREG(key_info.st_mode) and key_info.st_uid==501 and key_info.st_nlink==1
  and stat.S_IMODE(key_info.st_mode)==0o600,'new_synthetic_key_custody')
 cert=read(ROOT/'server/tls/server.crt',65536)
 leaf=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.decode())).hexdigest()
 for kind in ('canonical-close','keep-alive-control'):
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
  context.load_cert_chain(str(ROOT/'server/tls/server.crt'),str(ROOT/'server/tls/server.key'))
  peer=Peer(kind,context);peers.append(peer)
  plan={'case':kind,'port':peer.port,'certificate':str(ROOT/'server/tls/server.crt'),'leafSha256':leaf}
  plan_path=ROOT/'initial'/(kind+'.public.json');create(plan_path,(json.dumps(plan,sort_keys=True)+'\n').encode())
  profile=ns['sandbox_profile'](peer.port);profile_path=ROOT/'initial'/(kind+'.sb');create(profile_path,profile)
  peer.start()
  row,out,err=command(kind,['/usr/bin/sandbox-exec','-f',str(profile_path),NODE,'--no-warnings',str(ROOT/'qa/observe_original_wire_sequence_r1.mjs'),str(plan_path)])
  create(ROOT/'private'/(kind+'.stdout.private.json'),out);create(ROOT/'private'/(kind+'.stderr.private'),err)
  result=json.loads(out) if out else None
  peer_result=peer.finish()
  report['cases'].append({'case':kind,'profileSha256':hashlib.sha256(profile).hexdigest(),
   'command':row,'node':result,'peer':peer_result})
  need(row['exitCode']==0 and not err and type(result) is dict and result.get('ok') is True
   and result.get('schema')=='heptabao.synthetic-original-wire-two-request-node.r1',
   'synthetic_original_wire_observation_completed')
  need(peer_result['allRequestsSyntheticAndExact'] and peer_result['requests']==2
   and peer_result['acceptedSockets']==peer_result['closedAcceptedSockets']
   and peer_result['threadJoined'] and peer_result['listenerClosed'] and peer_result['errorType'] is None,
   'all_original_synthetic_peer_handles_closed')
 for filename,pin in FIXED.items():read(filename,pin=pin)
 for name,pin in PINS.items():read(OLD/'qa'/name,pin=pin)
 need(read(ROOT/'qa/main3_sdk_wire_r2.mjs',pin=PINS['main3_sdk_wire_r2.mjs'])==sources['main3_sdk_wire_r2.mjs'],
  'original_wire_byte_unchanged_after_both_cases')
 report['publicSourcesUnchangedBeforeAfter']=True;report['ok']=True
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if isinstance(error,Refused) else None
finally:
 for peer in peers:peer.finish()
 report['commands']=commands.public() if commands else None
 report['openedParentDescriptors']=opened;report['closedParentDescriptors']=closed
 report['allParentDescriptorsClosed']=opened==closed
 report['allPeerThreadsAndListenersClosed']=all(p.result['threadJoined'] and p.result['listenerClosed'] for p in peers)
 report['elapsedSeconds']=time.monotonic()-START
 if not report['allParentDescriptorsClosed'] or not report['allPeerThreadsAndListenersClosed']:report['ok']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
