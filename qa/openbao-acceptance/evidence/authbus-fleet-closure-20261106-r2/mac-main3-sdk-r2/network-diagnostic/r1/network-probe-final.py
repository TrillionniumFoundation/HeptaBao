#!/usr/bin/env python3
"""New synthetic SBPL/TLS qualification; no provider, SDK, or product service."""
import ast, hashlib, json, os, socket, ssl, stat, sys, threading, time, types
from pathlib import Path

OLD=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-network-probe-20261106-r1')
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
PINS={'mac_owned_unreaped_r1.py':'d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
      'mac_owned_commands_r1.py':'71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
      'main3_sdk_phase.py':'2ae860ba7fbfef5c48254cd74f0800fcd5ddc341653a7965c1d31c889397a910'}
FIXED={NODE:'a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e',
       '/usr/bin/sandbox-exec':'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'}
START=time.monotonic();UNTIL=START+60;opened=closed=0;commands=None
listener=other_listener=v6_listener=None;peer=None;stop=threading.Event()
peer_result={'connections':0,'requests':0,'listenerClosed':False,'acceptedSocketClosed':False,
             'threadJoined':False,'errorType':None}
report={'schema':'heptabao.mac-main3-sdk-worker-network-qualification.r1','ok':False,
 'originalFailedJobId':'1a1b263a649-fc05-7dda','originalWorkerPid':54346,
 'newSyntheticRoot':str(ROOT),'sourceCredentialFilesRead':False,'actualSdkOrPluginImported':False,
 'productServiceStarted':False,'providerCalled':False,'productionChanged':False,
 'privateValuesOrDigestsPublished':False,'tccOrAccessControlsChanged':False,
 'originalNodeMaximumSeconds':10,'outerSeconds':60,'cases':[],'selectedRule':None,
 'negativeLanAddressProvenance':'previously observed Mac en0 192.168.0.8; no new network discovery'}

def need(value,code):
 if not value:raise RuntimeError(code)
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,maximum=2*1048576,pin=None,system=False):
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
def command(label,argv,maximum=16384):
 need(UNTIL-time.monotonic()>20,'room_for_original_command_and_cleanup')
 row,out,err=commands.run(label,argv,until=min(UNTIL-10,time.monotonic()+10),maximum=maximum)
 row.pop('stdoutSha256',None);row.pop('stderrSha256',None);row['streamDigestsWithheld']=True
 need(not row['outcomeUnknown'] and row['streamsClosed'] and row['cleanup'].get('ok') is True,
      'original_child_custody_unknown_no_successor')
 return row,out,err

PROBE=r'''import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
const p=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const result={schema:'heptabao.synthetic-worker-network-node.r1',ok:false,entryReached:true,
 providerCalled:false,sourceCredentialFilesRead:false,openProbeFds:0,closedProbeFds:0,denials:[],tls:null};
const safe=e=>['EPERM','EACCES','ECONNREFUSED','ETIMEDOUT','EAFNOSUPPORT'].includes(e?.code)?e.code:'UNPROJECTED';
function denied(path,flag){let fd;try{fd=fs.openSync(path,flag);result.openProbeFds++;return {denied:false};}
 catch(e){return {denied:['EPERM','EACCES'].includes(e?.code),code:safe(e)};}
 finally{if(fd!==undefined){fs.closeSync(fd);result.closedProbeFds++;}}}
async function connection(host,port,kind){return await new Promise(resolve=>{let socket,settled=false,error=null,connected=false,timedOut=false;
 const done=()=>{if(settled)return;settled=true;clearTimeout(timer);resolve({kind,denied:['EPERM','EACCES'].includes(error),code:error,connected,timedOut,socketClosed:true});};
 const timer=setTimeout(()=>{timedOut=true;if(socket)socket.destroy();},750);
 try{socket=net.createConnection({host,port});socket.once('connect',()=>{connected=true;socket.destroy();});
 socket.once('error',e=>{error=safe(e);socket.destroy();});socket.once('close',done);}
 catch(e){clearTimeout(timer);settled=true;resolve({kind,denied:['EPERM','EACCES'].includes(e?.code),code:safe(e),connected:false,timedOut:false,socketClosed:true,constructorThrew:true});}
 });}
async function positive(){return await new Promise(resolve=>{let socket,settled=false,error=null,authorized=false,leaf=false,requests=0;
 const chunks=[];let bytes=0;const timer=setTimeout(()=>{error='TLS_PROBE_DEADLINE';socket?.destroy();},3000);
 const done=()=>{if(settled)return;settled=true;clearTimeout(timer);const response=Buffer.concat(chunks);
  resolve({authorized,leafMatched:leaf,requests,responseExact:response.equals(Buffer.from(p.expectedResponse)),
   socketClosed:true,errorCode:error,ok:authorized&&leaf&&requests===1&&response.equals(Buffer.from(p.expectedResponse))&&error===null});};
 try{socket=tls.connect({host:'127.0.0.1',port:p.port,servername:'localhost',ca:fs.readFileSync(p.certificate),rejectUnauthorized:true,minVersion:'TLSv1.2'});
  socket.once('secureConnect',()=>{authorized=socket.authorized===true;
   const raw=socket.getPeerCertificate(true)?.raw;leaf=Buffer.isBuffer(raw)&&crypto.createHash('sha256').update(raw).digest('hex')===p.leafSha256;
   if(!authorized||!leaf||socket.remoteAddress!=='127.0.0.1'||socket.remotePort!==p.port){error='TLS_OR_ENDPOINT_BINDING';socket.destroy();return;}
   requests++;socket.write(p.request);});
  socket.on('data',part=>{bytes+=part.length;if(bytes>4096){error='BOUNDED_SYNTHETIC_RESPONSE';socket.destroy();}else chunks.push(part);});
  socket.once('end',()=>socket.destroy());socket.once('error',e=>{error=safe(e);socket.destroy();});socket.once('close',done);
 }catch(e){error=safe(e);clearTimeout(timer);if(socket)socket.destroy();else done();}
 });}
try{
 result.syntheticRead=denied(p.root+'/protected-read',fs.constants.O_RDONLY);
 result.syntheticWrite=denied(p.root+'/protected-write',fs.constants.O_WRONLY);
 result.denials.push(await connection('127.0.0.1',p.otherPort,'other-owned-loopback-listener'));
 result.denials.push(await connection('192.168.0.8',p.port,'previously-observed-mac-lan-address'));
 result.denials.push(await connection('192.0.2.1',p.port,'documentation-address'));
 if(p.ipv6ListenerPresent)result.ipv6SamePort=await connection('::1',p.port,'owned-ipv6-same-port-listener');
 result.tls=await positive();
 result.ok=result.syntheticRead.denied&&result.syntheticWrite.denied&&result.denials.every(x=>x.denied&&x.socketClosed&&!x.connected&&!x.timedOut)
  &&result.tls.ok&&result.openProbeFds===result.closedProbeFds;
}catch(e){result.errorType=String(e?.name??'Error');result.errorCode=safe(e);}
process.stdout.write(JSON.stringify(result)+'\n');process.exitCode=result.ok?0:1;
'''

try:
 need(os.getuid()==os.geteuid()==501 and Path.cwd()==Path('/Users/qianqi'),'exact_original_caller_and_cwd')
 os.umask(0o077)
 sources={name:read(OLD/'qa'/name,pin=pin) for name,pin in PINS.items()}
 for filename,pin in FIXED.items():read(filename,pin=pin)
 openssl_raw=read('/usr/bin/openssl',system=True);openssl_sha=hashlib.sha256(openssl_raw).hexdigest()
 report['systemOpenSslWholeFileSha256']=openssl_sha
 nodes=[n for n in ast.parse(sources['main3_sdk_phase.py']).body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
 need(len(nodes)==1,'one_original_profile_function')
 def profile(root,port):
  ns={'ROOT':root,'STATE':root/'state','LIVE':Path('/Users/qianqi/.openclaw'),'Path':Path,'json':json,'need':need}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-r2-profile>','exec'),ns)
  return ns['sandbox_profile'](port)
 original=read(OLD/'initial/worker.sb',65536,pin='7f1fb79be147d9772d735a060e26a104231b220b3958f9172feda78462378096')
 need(original==profile(OLD,63907),'original_worker_profile_exact')
 for name in ('mac_owned_unreaped_r1','mac_owned_commands_r1'):
  module=types.ModuleType(name);module.__file__=str(OLD/'qa'/(name+'.py'));sys.modules[name]=module
  exec(compile(sources[name+'.py'],module.__file__,'exec'),module.__dict__)
 owned=sys.modules['mac_owned_commands_r1'];signals=owned.Signals();signals.install();commands=owned.Commands(signals)
 os.mkdir(ROOT,0o700)
 for relative in ('qa','plugin','input','private','state','initial','cold-new-process','server','server/tls','server/private'):
  os.mkdir(ROOT/relative,0o700)
 create(ROOT/'protected-read',b'owned synthetic protected read probe\n')
 create(ROOT/'protected-write',b'owned synthetic protected write probe\n')
 create(ROOT/'qa/network-probe.mjs',PROBE.encode())
 openssl_config=b'[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\nCN = localhost\n[v3]\nsubjectAltName = DNS:localhost,IP:127.0.0.1\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage = serverAuth\n'
 create(ROOT/'server/tls/openssl.cnf',openssl_config)
 row,out,err=command('new-synthetic-tls-material',['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-config',str(ROOT/'server/tls/openssl.cnf'),'-keyout',str(ROOT/'server/tls/server.key'),'-out',str(ROOT/'server/tls/server.crt')])
 report['tlsMaterialCommand']=row;need(row['exitCode']==0,'new_synthetic_tls_material_known_zero')
 need(hashlib.sha256(read('/usr/bin/openssl',system=True)).hexdigest()==openssl_sha,'same_fixed_system_openssl_after_child')
 cert=read(ROOT/'server/tls/server.crt',65536)
 keyinfo=(ROOT/'server/tls/server.key').lstat()
 need(stat.S_ISREG(keyinfo.st_mode) and keyinfo.st_uid==501 and keyinfo.st_nlink==1 and stat.S_IMODE(keyinfo.st_mode)==0o600,'new_private_synthetic_key_custody')
 leaf=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.decode())).hexdigest()
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
 context.load_cert_chain(str(ROOT/'server/tls/server.crt'),str(ROOT/'server/tls/server.key'))
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0));listener.listen(2);listener.settimeout(.1)
 port=listener.getsockname()[1];need(1024<=port<=65535,'one_owned_ephemeral_listener')
 other_listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);other_listener.bind(('127.0.0.1',0));other_listener.listen(2)
 other_port=other_listener.getsockname()[1];need(other_port!=port,'distinct_owned_negative_listener')
 try:
  v6_listener=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);v6_listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  v6_listener.bind(('::1',port));v6_listener.listen(2)
 except OSError as error:
  if v6_listener is not None:v6_listener.close();v6_listener=None
  need(error.errno in (47,48,49,97,98,99),'bounded_optional_ipv6_bind_result')
  report['ipv6SamePortListenerUnavailableErrno']=error.errno
 request=b'GET /synthetic-policy HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
 body=b'{"synthetic":true,"scope":"owned-loopback"}'
 response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
 plan={'root':str(ROOT),'port':port,'otherPort':other_port,'certificate':str(ROOT/'server/tls/server.crt'),
       'leafSha256':leaf,'ipv6ListenerPresent':v6_listener is not None,'request':request.decode(),'expectedResponse':response.decode()}
 create(ROOT/'initial/probe-plan.public.json',(json.dumps(plan,sort_keys=True)+'\n').encode())
 def serve():
  raw=tls=None
  try:
   while not stop.is_set() and time.monotonic()<UNTIL-2:
    try:raw,_=listener.accept();break
    except socket.timeout:continue
   if raw is None:return
   peer_result['connections']+=1;raw.settimeout(3)
   tls=context.wrap_socket(raw,server_side=True);received=b''
   while b'\r\n\r\n' not in received:
    part=tls.recv(4096)
    if not part:break
    received+=part;need(len(received)<=4096,'bounded_synthetic_peer_request')
   need(received==request,'one_exact_synthetic_get');peer_result['requests']+=1;tls.sendall(response)
  except BaseException as error:
   peer_result['errorType']=type(error).__name__
  finally:
   if tls is not None:tls.close()
   elif raw is not None:raw.close()
   peer_result['acceptedSocketClosed']=raw is not None and raw.fileno()==-1 and (tls is None or tls.fileno()==-1)
 peer=threading.Thread(target=serve,name='owned-synthetic-network-peer',daemon=False);peer.start()
 baseline=profile(ROOT,port)
 old_rule='(allow network-outbound (remote ip '+json.dumps('127.0.0.1:'+str(port))+'))'
 need(baseline.decode().count(old_rule)==1,'one_original_network_rule')
 variants=[('original-ip-numeric',old_rule),
           ('tcp-numeric','(allow network-outbound (remote tcp '+json.dumps('127.0.0.1:'+str(port))+'))'),
           ('tcp-localhost','(allow network-outbound (remote tcp '+json.dumps('localhost:'+str(port))+'))')]
 for label,rule in variants:
  sb=baseline.decode().replace(old_rule,rule).encode()
  need(sb.decode().replace(rule,old_rule)==baseline.decode(),'only_one_network_rule_changes')
  sb_path=ROOT/'initial'/(label+'.sb');create(sb_path,sb)
  argv=['/usr/bin/sandbox-exec','-f',str(sb_path),NODE,'--no-warnings',str(ROOT/'qa/network-probe.mjs'),str(ROOT/'initial/probe-plan.public.json')]
  row,out,err=command(label,argv)
  create(ROOT/'private'/(label+'.stdout.private'),out);create(ROOT/'private'/(label+'.stderr.private'),err)
  value=json.loads(out) if out else None
  compiler_host_refusal=(row['exitCode']==65 and not out and err.startswith(b'sandbox-exec:') and b'host must be * or localhost in network address' in err)
  case={'name':label,'rule':rule,'profileSha256':hashlib.sha256(sb).hexdigest(),'command':row,
        'fixedCompilerHostRefusal':compiler_host_refusal,'nodeResult':value,'rawUnexpectedDiagnosticPublished':False}
  report['cases'].append(case)
  if label=='original-ip-numeric':need(compiler_host_refusal,'original_numeric_ip_rule_not_reproduced');continue
  if compiler_host_refusal:continue
  need(row['exitCode']==0 and not err and isinstance(value,dict) and value.get('schema')=='heptabao.synthetic-worker-network-node.r1' and value.get('ok') is True,'candidate_profile_full_qualification_required')
  report['selectedRule']=rule;report['selectedCase']=label;report['qualifiedNodeResult']=value;break
 need(report['selectedRule'] is not None,'no_supported_narrow_candidate')
 stop.set();peer.join(timeout=min(3,max(.001,UNTIL-time.monotonic())))
 peer_result['threadJoined']=not peer.is_alive()
 need(peer_result['threadJoined'] and peer_result['connections']==1 and peer_result['requests']==1
      and peer_result['acceptedSocketClosed'] and peer_result['errorType'] is None,'original_tls_peer_known_closed')
 other_listener.setblocking(False)
 try:
  unexpected,_=other_listener.accept();unexpected.close();raise RuntimeError('other_loopback_listener_received_connection')
 except BlockingIOError:report['otherLoopbackListenerReceivedNoConnection']=True
 if v6_listener is not None:
  v6_listener.setblocking(False);accepted=0
  try:
   connection,_=v6_listener.accept();accepted+=1;connection.close()
  except BlockingIOError:pass
  report['ownedIpv6SamePortAcceptedConnections']=accepted
  observed=report['qualifiedNodeResult'].get('ipv6SamePort',{})
  need(accepted==int(observed.get('connected') is True) and observed.get('socketClosed') is True,
       'explicit_ipv6_granularity_observation_matches_owned_listener')
 report['kernelIpv4OnlyDestinationClaimed']=(report['selectedCase']=='tcp-numeric' and v6_listener is not None
  and observed.get('denied') is True and observed.get('connected') is False
  and observed.get('timedOut') is False and accepted==0)
 report['actualSdkWireStillRequiresExactIpv4Endpoint']=True
 need(read(ROOT/'protected-read')==b'owned synthetic protected read probe\n' and read(ROOT/'protected-write')==b'owned synthetic protected write probe\n','protected_files_unchanged')
 for filename,pin in FIXED.items():read(filename,pin=pin)
 for name,pin in PINS.items():read(OLD/'qa'/name,pin=pin)
 report['publicSourcesUnchangedBeforeAfter']=True;report['ok']=True
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if type(error) is RuntimeError else None
finally:
 stop.set()
 for s in (listener,other_listener,v6_listener):
  if s is not None:s.close()
 if peer is not None:peer.join(timeout=3);peer_result['threadJoined']=not peer.is_alive()
 peer_result['listenerClosed']=listener is None or listener.fileno()==-1
 report['peer']=peer_result
 report['allParentListenersClosed']=all(s is None or s.fileno()==-1 for s in (listener,other_listener,v6_listener))
 report['commands']=commands.public() if commands else None
 report['openedParentDescriptors']=opened;report['closedParentDescriptors']=closed
 report['allParentDescriptorsClosed']=opened==closed
 report['elapsedSeconds']=time.monotonic()-START
 if peer is not None and peer.is_alive():report['ok']=False;report['peerThreadOutcomeUnknown']=True
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] and opened==closed and report['allParentListenersClosed'] else 1)
