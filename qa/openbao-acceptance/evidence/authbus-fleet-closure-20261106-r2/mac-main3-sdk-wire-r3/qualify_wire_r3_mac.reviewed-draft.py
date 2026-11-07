#!/usr/bin/env python3
"""Single synthetic two-case observation of the unchanged original SDK wire."""
import ast,hashlib,json,os,socket,ssl,stat,sys,threading,time,types
from pathlib import Path
OLD=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3')
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-wire-qualification-20261106-r1')
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

CANDIDATE_WIRE="/** One current AuthBus cycle, with bounded verified HTTPS and public ordinals.\n * The outer Mac sandbox admits one port across local machine addresses. This\n * adapter separately pins exact IPv4, CA, host, and leaf on each response and\n * never publishes request paths, response bodies, identifiers or hashes.\n */\nimport https from 'node:https';\nimport http from 'node:http';\nimport tls from 'node:tls';\nimport {createHash} from 'node:crypto';\n\nconst MAX_BYTES=1048576;\nconst need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{safeCode:code});};\nconst hash=raw=>createHash('sha256').update(raw).digest('hex');\n\nexport function classifyRoute(method,route,hostId,managed){\n  need(typeof route==='string'&&route.length<=2048,'sdk_wire_route_shape');\n  if(method==='POST'&&route==='/v1/auth/approle/login')return {routeCategory:'approle-login',slotOrdinal:0};\n  if(method==='GET'){\n    const control={\n      '/v1/openclaw-auth/data/manifest':'manifest-read',\n      '/v1/openclaw-auth/data/order-policy':'order-policy-read',\n      '/v1/openclaw-auth/data/scheduler-assignments':'scheduler-assignments-read'};\n    if(Object.hasOwn(control,route))return {routeCategory:control[route],slotOrdinal:0};\n    const index=managed.findIndex(item=>route==='/v1/openclaw-auth/data/profiles/'+encodeURIComponent(item.key));\n    if(index>=0)return {routeCategory:'profile-read',slotOrdinal:index+1};\n  }\n  const prefix='/v1/openclaw-auth/data/inbox/'+encodeURIComponent(hostId)+'/';\n  if(method==='POST'&&route.startsWith(prefix)&&\n     /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(route.slice(prefix.length)))\n    return {routeCategory:'inbox-write',slotOrdinal:0};\n  need(false,'sdk_wire_unregistered_route');\n}\n\nexport function responseLength(headers,status){\n  need(headers['content-encoding']===undefined,'sdk_wire_uncompressed_response');\n  const transfer=headers['transfer-encoding'];\n  const length=headers['content-length'];\n  if(status===204){\n    need(transfer===undefined&&(length===undefined||length==='0'),'sdk_wire_empty_204');\n    return 0;\n  }\n  if(transfer!==undefined){\n    need(typeof transfer==='string'&&/^chunked$/i.test(transfer)&&length===undefined,\n      'sdk_wire_unambiguous_chunked_response');\n    // IncomingMessage is decoded by Node's strict HTTP parser. Only its end\n    // event with complete=true proves the terminal chunk/trailer terminator;\n    // the decoded body is still bounded independently below.\n    return null;\n  }\n  need(typeof length==='string'&&/^[0-9]{1,9}$/.test(length)&&Number(length)<=MAX_BYTES,\n       'sdk_wire_bounded_content_length');\n  return Number(length);\n}\n\nexport function installWireFence({address,ca,certificateSha256,hostId,managed,remainingMs}){\n  const target=new URL(address);\n  need(target.protocol==='https:'&&target.hostname==='127.0.0.1'&&/^\\d{4,5}$/.test(target.port)&&\n       Number(target.port)>=1024&&Number(target.port)<=65535&&\n       target.username===''&&target.password===''&&target.pathname==='/'&&!target.search&&!target.hash,\n       'sdk_wire_one_loopback_https');\n  need(Buffer.isBuffer(ca)&&ca.length>0&&ca.length<=65536&&/^[0-9a-f]{64}$/.test(certificateSha256),\n       'sdk_wire_actual_ca_and_leaf_pin');\n  const originals={request:https.request,get:https.get,httpRequest:http.request,httpGet:http.get,fetch:globalThis.fetch};\n  const rows=[],sockets=new Set(),requests=new Map(),tokens=[];\n  let blocked=false,enabled=true,closed=false,denials=0;\n  const agent=new https.Agent({keepAlive:false,maxCachedSessions:0,maxSockets:1,maxTotalSockets:1});\n  const deny=()=>{blocked=true;denials++;need(false,'sdk_wire_other_network_forbidden');};\n  const safeError=code=>Object.assign(new Error(code),{safeCode:code});\n  function boundedRequest(options,callback){\n    need(enabled&&!blocked&&rows.length<192,'sdk_wire_no_dispatch_after_unknown_or_close');\n    need(options&&typeof options==='object'&&!(options instanceof URL)&&typeof callback==='function',\n         'sdk_wire_exact_request_shape');\n    need(options.protocol==='https:'&&(options.hostname||options.host)===target.hostname&&\n         String(options.port||443)===target.port&&options.rejectUnauthorized===true&&\n         options.timeout===15000&&Buffer.isBuffer(options.ca)&&options.ca.equals(ca)&&\n         options.agent===undefined&&options.checkServerIdentity===undefined&&options.createConnection===undefined,\n         'sdk_wire_exact_endpoint_trust_and_original_timeout');\n    const category=classifyRoute(options.method,options.path,hostId,managed);\n    const budget=remainingMs(15000);\n    const row={ordinal:rows.length+1,...category,method:options.method,dispatched:false,\n      requestCount:0,requestBytes:0,responseBytes:0,responseComplete:false,requestClosed:false,\n      socketObserved:false,socketClosed:false,tlsVerified:false,outcomeUnknown:false,\n      originalHttpMaximumMs:15000,allocatedHttpMs:budget};\n    rows.push(row);\n    let req,timer=null,ended=false,received=false,failureDelivered=false;\n    const deadline=process.hrtime.bigint()+BigInt(budget)*1000000n;\n    const fail=code=>{\n      if(failureDelivered)return;\n      failureDelivered=true;\n      blocked=true;row.errorCode=code;\n      row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);\n      if(timer){clearTimeout(timer);timer=null;}\n      const error=safeError(code);\n      req?.destroy(error);\n      // Node may already have closed ClientRequest before an incomplete\n      // IncomingMessage reports aborted. The installed plugin listens only to\n      // request/error; forward that observed failure once when destroy can no\n      // longer deliver it. This is adapter behavior, never a fabricated reply.\n      if(req&&row.requestClosed&&!row.requestError){\n        row.closedRequestResponseFailureForwarded=true;req.emit('error',error);\n      }\n    };\n    try{\n      req=originals.request({...options,agent,timeout:budget,\n        checkServerIdentity(host,certificate){\n          const normal=tls.checkServerIdentity(host,certificate);\n          if(normal)return normal;\n          if(host!==target.hostname||!certificate?.raw||hash(certificate.raw)!==certificateSha256)\n            return safeError('sdk_wire_tls_leaf_pin');\n          return undefined;\n        }},response=>{\n        received=true;row.status=response.statusCode;\n        const socket=response.socket;\n        try{\n          // A TLS callback is a connection verification hook, not a request-local\n          // completion marker. The Mac synthetic reproduction observed a valid\n          // new connection without invoking this request's callback closure.\n          row.tlsSocketAuthorized=socket.authorized===true;\n          row.tlsEndpointMatched=socket.remoteAddress===target.hostname&&socket.remotePort===Number(target.port);\n          row.tlsPeerCertificateAvailable=false;row.tlsHostMatched=false;row.tlsLeafMatched=false;\n          const peer=socket.getPeerCertificate();\n          row.tlsPeerCertificateAvailable=Boolean(peer&&Buffer.isBuffer(peer.raw)&&peer.raw.length>0);\n          if(row.tlsPeerCertificateAvailable){\n            row.tlsHostMatched=tls.checkServerIdentity(target.hostname,peer)===undefined;\n            row.tlsLeafMatched=hash(peer.raw)===certificateSha256;\n          }\n          need(row.tlsSocketAuthorized&&row.tlsEndpointMatched&&row.tlsPeerCertificateAvailable&&\n               row.tlsHostMatched&&row.tlsLeafMatched,'sdk_wire_verified_exact_peer');\n          row.tlsVerified=true;row.tlsVersion=socket.getProtocol();\n          const expected=responseLength(response.headers,response.statusCode);\n          row.responseFraming=response.statusCode===204?'no-body':expected===null?'chunked':'content-length';\n          const chunks=[];\n          response.on('data',part=>{\n            row.responseBytes+=part.length;\n            if((expected!==null&&row.responseBytes>expected)||row.responseBytes>MAX_BYTES){fail('sdk_wire_response_bound');return;}\n            if(category.routeCategory==='approle-login')chunks.push(part);\n          });\n          response.once('aborted',()=>{row.responseAborted=true;fail('sdk_wire_response_aborted');});\n          response.once('error',()=>{row.responseError=true;fail('sdk_wire_response_error');});\n          response.once('end',()=>{\n            if(response.complete!==true||(expected!==null&&row.responseBytes!==expected)||process.hrtime.bigint()>=deadline){\n              fail('sdk_wire_complete_response_deadline');return;\n            }\n            row.responseComplete=true;\n            if(timer){clearTimeout(timer);timer=null;}\n            if(category.routeCategory==='approle-login'&&response.statusCode===200){\n              try{\n                const value=JSON.parse(Buffer.concat(chunks));\n                need(typeof value.auth?.client_token==='string'&&value.auth.client_token.length>=8,\n                     'sdk_wire_private_login_token_shape');\n                tokens.push(value.auth.client_token);row.privateTokenCaptured=true;\n              }catch{blocked=true;row.errorCode='sdk_wire_login_payload_invalid';}\n            }\n          });\n          callback(response);\n        }catch{response.resume();fail('sdk_wire_response_admission');}\n      });\n      requests.set(req,row);\n      req.once('socket',socket=>{\n        sockets.add(socket);row.socketObserved=true;\n        socket.once('close',()=>{row.socketClosed=true;sockets.delete(socket);});\n      });\n      req.once('close',()=>{\n        row.requestClosed=true;requests.delete(req);\n        if(failureDelivered&&row.errorCode&&!row.requestError){\n          row.closedRequestResponseFailureForwarded=true;req.emit('error',safeError(row.errorCode));\n        }\n      });\n      req.once('timeout',()=>fail('sdk_wire_request_timeout'));\n      req.once('error',()=>{\n        blocked=true;row.requestError=true;row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);\n        if(timer){clearTimeout(timer);timer=null;}\n      });\n      const write=req.write.bind(req),end=req.end.bind(req);\n      const count=data=>{\n        if(data===undefined||data===null)return;\n        const bytes=Buffer.isBuffer(data)?data:Buffer.from(data);\n        row.requestBytes+=bytes.length;need(row.requestBytes<=MAX_BYTES,'sdk_wire_request_bound');\n      };\n      req.write=function(data,...args){\n        try{\n          need(enabled&&!blocked&&!ended,'sdk_wire_one_request_write_context');count(data);\n          return write(data,...args);\n        }catch{denials++;fail('sdk_wire_request_write_refused');throw safeError('sdk_wire_request_write_refused');}\n      };\n      req.end=function(data,...args){\n        try{\n          need(enabled&&!blocked&&!ended,'sdk_wire_one_request_end');count(data);ended=true;\n          row.dispatched=true;row.requestCount=1;\n          return end(data,...args);\n        }catch{denials++;fail('sdk_wire_request_end_refused');throw safeError('sdk_wire_request_end_refused');}\n      };\n      timer=setTimeout(()=>fail('sdk_wire_absolute_http_deadline'),budget);\n      return req;\n    }catch(error){\n      blocked=true;row.errorCode='sdk_wire_request_setup_failed';\n      row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);\n      if(timer)clearTimeout(timer);\n      req?.destroy(safeError('sdk_wire_request_setup_failed'));\n      throw safeError('sdk_wire_request_setup_failed');\n    }\n  }\n  const guardedRequest=(...args)=>{\n    try{return boundedRequest(...args);}catch{blocked=true;denials++;throw safeError('sdk_wire_dispatch_refused');}\n  };\n  https.request=guardedRequest;https.get=deny;http.request=deny;http.get=deny;globalThis.fetch=deny;\n  return Object.freeze({rows,tokens,\n    stopNetwork(){enabled=false;},\n    deniedCount(){return denials;},\n    unknown(){return rows.some(row=>row.outcomeUnknown||row.dispatched&&!row.responseComplete);},\n    async close(){\n      enabled=false;\n      for(const [req,row]of requests)if(!row.responseComplete)req.destroy(safeError('sdk_wire_owned_worker_closing'));\n      agent.destroy();\n      const waits=[...[...sockets].map(socket=>new Promise(resolve=>socket.once('close',resolve))),\n        ...[...requests.keys()].map(req=>new Promise(resolve=>req.once('close',resolve)))];\n      if(waits.length){\n        let timer;\n        try{await Promise.race([Promise.all(waits),new Promise((_,reject)=>{\n          timer=setTimeout(()=>reject(safeError('sdk_wire_socket_closure_deadline')),remainingMs(1000));\n        })]);}finally{if(timer)clearTimeout(timer);}\n      }\n      need(requests.size===0&&sockets.size===0,'sdk_wire_owned_connections_not_closed');\n      closed=true;\n    },\n    publicClosure(){return {ownedHttpsAgentClosed:closed,remainingRequestCount:requests.size,\n      remainingSocketCount:sockets.size,otherNetworkDenials:denials,\n      allDispatchedResponsesComplete:rows.every(row=>!row.dispatched||row.responseComplete),\n      unknownOutcomeCount:rows.filter(row=>row.outcomeUnknown).length,\n      allObservedSocketsClosed:rows.every(row=>!row.socketObserved||row.socketClosed)};},\n    restoreHooks(){\n      const same=https.request===guardedRequest&&https.get===deny&&http.request===deny&&\n        http.get===deny&&globalThis.fetch===deny;\n      https.request=originals.request;https.get=originals.get;http.request=originals.httpRequest;\n      http.get=originals.httpGet;globalThis.fetch=originals.fetch;\n      need(same,'sdk_wire_network_hook_changed');\n    }\n  });\n}\n"
CANDIDATE_WIRE_SHA='e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c'
PROBE="import fs from 'node:fs';\nimport https from 'node:https';\nimport {createHash} from 'node:crypto';\nimport {installWireFence} from './main3_sdk_wire_r3.mjs';\nconst p=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));\nconst until=performance.now()+7000;\nconst originalRequest=https.request;\nlet pendingMutation=null;\nconst observations=[],socketIds=new WeakMap();let nextSocket=0,activeRequests=0,fence=null;\nconst report={schema:'heptabao.synthetic-candidate-wire-qualified-node.r1',ok:false,\n case:p.case,platform:process.platform,node:process.version,\n pinnedCandidateWireByteUnchanged:true,requestLocalCallbackSideEffectRequired:false,\n callbackCountersAreObservationsOnly:true,providerCalled:false,\n productionCredentialsRead:false,observations,wire:[],closures:null,hooksRestored:false};\nconst check=(v,c)=>{if(!v)throw Object.assign(new Error(c),{safeCode:c});};\nconst fixedError=e=>typeof e?.safeCode==='string'&&/^sdk_wire_[a-z_]+$/.test(e.safeCode)?e.safeCode:\n ['ECONNRESET','ECONNREFUSED','EPIPE','ETIMEDOUT','EPERM','EACCES'].includes(e?.code)?e.code:'UNPROJECTED';\nconst hash=b=>createHash('sha256').update(b).digest('hex');\nfunction socketSnapshot(socket){\n const snapshot={connecting:socket.connecting===true,secureConnecting:socket.secureConnecting===true,\n  destroyed:socket.destroyed===true,readableEnded:socket.readableEnded===true,writableEnded:socket.writableEnded===true,\n  authorized:socket.authorized===true,sessionReused:null,certificateRawAvailable:false,certificateLeafMatches:false,\n  peerCertificateGetterThrew:false,actualRemoteEndpointMatches:socket.remoteAddress==='127.0.0.1'&&socket.remotePort===p.port};\n try{snapshot.sessionReused=socket.isSessionReused()===true;}catch{snapshot.sessionReuseGetterThrew=true;}\n try{const raw=socket.getPeerCertificate()?.raw;snapshot.certificateRawAvailable=Buffer.isBuffer(raw);\n  snapshot.certificateLeafMatches=snapshot.certificateRawAvailable&&hash(raw)===p.leafSha256;\n }catch{snapshot.peerCertificateGetterThrew=true;}\n return snapshot;\n}\nfunction observedRequest(options,callback){\n const record={ordinal:observations.length+1,pinCallbackCalls:0,pinCallbackUndefinedReturns:0,\n  pinCallbackThrew:false,secureConnectEvents:0,requestClosed:false,requestErrors:0,\n  socketObserved:false,socketClosed:false,responseObserved:false};\n observations.push(record);\n const originalPin=options.checkServerIdentity,mutation=pendingMutation;\n check(typeof originalPin==='function','synthetic_original_pin_callback_present');\n const observedOptions={...options,checkServerIdentity:function(...args){\n  record.pinCallbackCalls++;\n  (record.pinCallbackContextObservations??=[]).push({observedRequestCount:observations.length,responseObservedForOwner:record.responseObserved});\n  record.pinHostIsExactTarget=args[0]==='127.0.0.1';\n  const raw=args[1]?.raw;record.pinCertificateRawAvailable=Buffer.isBuffer(raw);\n  record.pinCertificateLeafMatches=Buffer.isBuffer(raw)&&hash(raw)===p.leafSha256;\n  try{const returned=Reflect.apply(originalPin,this,args);\n   if(returned===undefined)record.pinCallbackUndefinedReturns++;\n   return returned;\n  }catch(error){record.pinCallbackThrew=true;throw error;}\n }};\n let request;\n request=Reflect.apply(originalRequest,https,[observedOptions,function(response){\n  record.responseObserved=true;record.status=response.statusCode;\n  record.reqReusedSocketAtResponse=request.reusedSocket===true;\n  record.thisRequestCallbackReturnedUndefinedAtResponse=record.pinCallbackUndefinedReturns>0;\n  record.pinCallbackCallsAtResponse=record.pinCallbackCalls;\n  if(mutation){record.actualPeerBeforeSyntheticMutation=socketSnapshot(response.socket);mutation(response.socket);record.syntheticResponseMutationApplied=true;}\n  record.responseSocket=socketSnapshot(response.socket);\n  return Reflect.apply(callback,this,[response]);\n }]);\n activeRequests++;\n request.once('socket',socket=>{\n  if(!socketIds.has(socket))socketIds.set(socket,++nextSocket);\n  record.socketOrdinal=socketIds.get(socket);record.socketObserved=true;\n  record.reqReusedSocketAtAssignment=request.reusedSocket===true;\n  record.assignedSocket=socketSnapshot(socket);\n  socket.once('secureConnect',()=>{record.secureConnectEvents++;record.pinCallbackCallsAtSecureConnect=record.pinCallbackCalls;record.secureSocket=socketSnapshot(socket);});\n  socket.once('close',()=>{record.socketClosed=true;});\n });\n request.once('error',error=>{record.requestErrors++;record.fixedRequestError=fixedError(error);});\n request.once('close',()=>{record.requestClosed=true;activeRequests--;});\n return request;\n}\nfunction request(path,method,body){\n return new Promise((resolve,reject)=>{\n  const headers={Accept:'application/json'};\n  if(body!==undefined){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(body);}\n  const req=https.request({protocol:'https:',hostname:'127.0.0.1',port:p.port,path,method,\n   ca:fs.readFileSync(p.certificate),rejectUnauthorized:true,timeout:15000,headers},res=>{\n    let count=0;\n    res.on('data',part=>{count+=part.length;});\n    res.once('end',()=>resolve({status:res.statusCode,responseBytes:count,complete:res.complete===true}));\n   });\n  req.once('error',reject);\n  req.end(body);\n });\n}\n\nfunction newFence(){\n return installWireFence({address:'https://127.0.0.1:'+p.port,ca:fs.readFileSync(p.certificate),\n  certificateSha256:p.leafSha256,hostId:'synthetic-mac',managed:[{key:'synthetic-1'},{key:'synthetic-2'},{key:'synthetic-3'}],\n  remainingMs:cap=>{const left=Math.floor(until-performance.now());check(left>0,'synthetic_original_deadline');return Math.min(cap,left);}});\n}\nasync function closeCurrentFence(){\n const current=fence;check(current!==null,'synthetic_current_fence');\n await current.close();const closure=current.publicClosure();\n current.restoreHooks();check(https.request===observedRequest,'synthetic_observer_hook_restore');\n fence=null;return closure;\n}\nconst loginBody=JSON.stringify({role_id:'synthetic-role',secret_id:'synthetic-secret'});\ntry{\n check(p.case==='canonical-close'||p.case==='keep-alive-control','synthetic_fixed_case');\n https.request=observedRequest;fence=newFence();report.requests=[];\n for(const [path,method,body]of[\n  ['/v1/auth/approle/login','POST',loginBody],\n  ['/v1/openclaw-auth/data/manifest','GET',undefined]]){\n  report.requests.push({complete:true,result:await request(path,method,body)});\n }\n report.wire=fence.rows;\n report.closures=await closeCurrentFence();\n report.positiveSequenceQualified=report.wire.length===2&&report.requests.length===2&&\n  report.requests.every(row=>row.complete&&row.result.complete&&row.result.status===200)&&\n  report.wire.every(row=>row.requestCount===1&&row.responseComplete&&!row.outcomeUnknown&&row.tlsVerified&&\n   row.tlsSocketAuthorized&&row.tlsEndpointMatched&&row.tlsPeerCertificateAvailable&&row.tlsHostMatched&&row.tlsLeafMatched)&&\n  report.closures.allDispatchedResponsesComplete&&report.closures.unknownOutcomeCount===0&&report.closures.allObservedSocketsClosed;\n check(report.positiveSequenceQualified,'synthetic_two_once_responses_qualified');\n report.negativeCases=[];\n if(p.case==='canonical-close'){\n  for(const [name,field,mutate]of [\n   ['unauthorized','tlsSocketAuthorized',socket=>{socket.authorized=false;}],\n   ['actual-ip-mismatch','tlsEndpointMatched',socket=>{Object.defineProperty(socket,'remoteAddress',{value:'192.0.2.1',configurable:true});}],\n   ['actual-port-mismatch','tlsEndpointMatched',socket=>{Object.defineProperty(socket,'remotePort',{value:9,configurable:true});}],\n   ['peer-unavailable','tlsPeerCertificateAvailable',socket=>{socket.getPeerCertificate=()=>({});}],\n   ['hostname-mismatch','tlsHostMatched',socket=>{const peer=socket.getPeerCertificate();socket.getPeerCertificate=()=>({...peer,subjectaltname:'DNS:unrelated.invalid',subject:{CN:'unrelated.invalid'}});}],\n   ['leaf-mismatch','tlsLeafMatched',socket=>{const peer=socket.getPeerCertificate();socket.getPeerCertificate=()=>({...peer,raw:Buffer.from('synthetic-mismatching-leaf')});}],\n   ['peer-getter-throws','tlsPeerCertificateAvailable',socket=>{socket.getPeerCertificate=()=>{throw new Error('synthetic-peer-getter-failure');};}]\n  ]){\n   // Each deliberate fault is a new synthetic case/fence, never a retry of a\n   // failed business request. Only the response-time JS observation is altered.\n   fence=newFence();pendingMutation=mutate;let error=null,returned=false;\n   try{await request('/v1/auth/approle/login','POST',loginBody);returned=true;}\n   catch(e){error=fixedError(e);}finally{pendingMutation=null;}\n   const rows=fence.rows,tokenCount=fence.tokens.length;\n   let nextDispatchRefused=false;\n   try{https.request({},()=>{});}catch(e){nextDispatchRefused=e?.safeCode==='sdk_wire_dispatch_refused';}\n   const closure=await closeCurrentFence();\n   const passed=!returned&&error==='sdk_wire_response_admission'&&rows.length===1&&rows[0][field]===false&&\n    rows[0].dispatched&&rows[0].requestCount===1&&rows[0].responseBytes===0&&!rows[0].responseComplete&&\n    !rows[0].tlsVerified&&rows[0].outcomeUnknown&&tokenCount===0&&nextDispatchRefused&&\n    closure.ownedHttpsAgentClosed&&closure.remainingRequestCount===0&&closure.remainingSocketCount===0&&\n    closure.allObservedSocketsClosed&&closure.unknownOutcomeCount===1;\n   report.negativeCases.push({case:name,injectedResponseObservationOnly:true,passed,errorCode:error,\n    nextDispatchRefused,tokenCount,wire:rows,closure});\n   check(passed,'synthetic_response_fault_refused_and_closed');\n  }\n }\n report.observationCompleted=observations.length===(p.case==='canonical-close'?9:2)&&\n  observations.every(row=>row.responseObserved);\n}catch(error){report.fixedError=fixedError(error);}\nfinally{\n pendingMutation=null;\n try{if(fence){report.failedCurrentWire=fence.rows;report.failedCurrentClosure=await closeCurrentFence();}}\n catch(error){report.closureError=fixedError(error);}\n report.observerStillInstalledAfterFenceRestore=https.request===observedRequest;\n https.request=originalRequest;report.hooksRestored=https.request===originalRequest;\n report.remainingObservedRequests=activeRequests;\n report.positiveSequenceSameSocket=observations.length>=2&&observations[0].socketOrdinal===observations[1].socketOrdinal;\n report.totalObservedSocketObjects=nextSocket;\n report.syntheticNegativeCount=report.negativeCases?.length??0;\n report.ok=report.positiveSequenceQualified===true&&report.observationCompleted===true&&\n  report.syntheticNegativeCount===(p.case==='canonical-close'?7:0)&&report.negativeCases.every(row=>row.passed)&&\n  report.hooksRestored&&report.observerStillInstalledAfterFenceRestore&&\n  activeRequests===0&&observations.every(row=>row.requestClosed&&row.socketClosed)&&\n  report.closures?.ownedHttpsAgentClosed===true&&report.closures.remainingRequestCount===0&&report.closures.remainingSocketCount===0;\n}\nprocess.stdout.write(JSON.stringify(report)+'\\n');process.exitCode=report.ok?0:1;\n"
report={'schema':'heptabao.mac-main3-sdk-candidate-wire-qualification.r1','ok':False,
 'originalFailedJobId':'1a1b28a4d4c-fc05-7e81','newSyntheticRoot':str(ROOT),
 'priorWireSha256':PINS['main3_sdk_wire_r2.mjs'],'candidateWireSha256':CANDIDATE_WIRE_SHA,
 'pinnedCandidateWireByteUnchanged':True,'priorOriginalWireUnchanged':True,
 'priorWireDiagnosticJob':'1a1b29bacf3-fc05-7ee7','syntheticPositiveRequests':4,'syntheticResponseFaultCases':7,
 'originalFailedBusinessAttemptRepeated':False,'originalFailureCauseClaimed':False,
 'sourceCredentialFilesRead':False,'actualSdkOrPluginImported':False,'productServiceStarted':False,
 'providerCalled':False,'productionChanged':False,'privateValuesOrDigestsPublished':False,
 'tccOrAccessControlsChanged':False,'originalNodeMaximumSeconds':10,'outerSeconds':60,'cases':[]}

class Peer:
 def __init__(self,kind,context):
  self.kind=kind;self.context=context;self.stop=threading.Event();self.thread=None
  self.expected_requests=9 if kind=='canonical-close' else 2
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
   while self.result['requests']<self.expected_requests and not self.stop.is_set() and time.monotonic()<self.until:
    try:raw,_=self.listener.accept()
    except socket.timeout:continue
    self.result['acceptedSockets']+=1;raw.settimeout(min(2,max(.001,self.until-time.monotonic())))
    try:
     tls=self.context.wrap_socket(raw,server_side=True)
     self.result['connections']+=1;connection_ordinal=self.result['connections']
     self.result['sessionReused'].append(bool(tls.session_reused))
     buffered=b''
     while self.result['requests']<self.expected_requests and not self.stop.is_set() and time.monotonic()<self.until:
      while b'\r\n\r\n' not in buffered:
       part=tls.recv(16384)
       if not part:break
       buffered+=part;need(len(buffered)<=32768,'bounded_synthetic_request')
      if b'\r\n\r\n' not in buffered:break
      header_end=buffered.index(b'\r\n\r\n')
      lines=buffered[:header_end].split(b'\r\n')
      expected=b'POST /v1/auth/approle/login HTTP/1.1' if self.result['requests']!=1 else b'GET /v1/openclaw-auth/data/manifest HTTP/1.1'
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
      if self.result['requests']!=1:
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
   self.result['allRequestsSyntheticAndExact']=self.result['requests']==self.expected_requests
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
 create(ROOT/'qa/qualify_wire_r3_mac_node.mjs',PROBE.encode())
 need(hashlib.sha256(CANDIDATE_WIRE.encode()).hexdigest()==CANDIDATE_WIRE_SHA,'fixed_candidate_wire_source')
 create(ROOT/'qa/main3_sdk_wire_r3.mjs',CANDIDATE_WIRE.encode())
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
  row,out,err=command(kind,['/usr/bin/sandbox-exec','-f',str(profile_path),NODE,'--no-warnings',str(ROOT/'qa/qualify_wire_r3_mac_node.mjs'),str(plan_path)])
  create(ROOT/'private'/(kind+'.stdout.private.json'),out);create(ROOT/'private'/(kind+'.stderr.private'),err)
  result=json.loads(out) if out else None
  peer_result=peer.finish()
  report['cases'].append({'case':kind,'profileSha256':hashlib.sha256(profile).hexdigest(),
   'command':row,'node':result,'peer':peer_result})
  need(row['exitCode']==0 and not err and type(result) is dict and result.get('ok') is True
   and result.get('schema')=='heptabao.synthetic-candidate-wire-qualified-node.r1',
   'synthetic_original_wire_observation_completed')
  need(peer_result['allRequestsSyntheticAndExact'] and peer_result['requests']==peer.expected_requests
   and peer_result['acceptedSockets']==peer_result['closedAcceptedSockets']
   and peer_result['threadJoined'] and peer_result['listenerClosed'] and peer_result['errorType'] is None,
   'all_original_synthetic_peer_handles_closed')
 for filename,pin in FIXED.items():read(filename,pin=pin)
 for name,pin in PINS.items():read(OLD/'qa'/name,pin=pin)
 need(read(ROOT/'qa/main3_sdk_wire_r3.mjs',pin=CANDIDATE_WIRE_SHA)==CANDIDATE_WIRE.encode(),
  'pinned_candidate_wire_byte_unchanged_after_both_cases')
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
