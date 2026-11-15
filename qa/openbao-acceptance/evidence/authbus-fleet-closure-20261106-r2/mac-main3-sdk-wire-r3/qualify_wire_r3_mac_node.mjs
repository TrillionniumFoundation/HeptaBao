import fs from 'node:fs';
import https from 'node:https';
import {createHash} from 'node:crypto';
import {installWireFence} from './main3_sdk_wire_r3.mjs';
const p=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const until=performance.now()+7000;
const originalRequest=https.request;
let pendingMutation=null;
const observations=[],socketIds=new WeakMap();let nextSocket=0,activeRequests=0,fence=null;
const report={schema:'heptabao.synthetic-candidate-wire-qualified-node.r1',ok:false,
 case:p.case,platform:process.platform,node:process.version,
 pinnedCandidateWireByteUnchanged:true,requestLocalCallbackSideEffectRequired:false,
 callbackCountersAreObservationsOnly:true,providerCalled:false,
 productionCredentialsRead:false,observations,wire:[],closures:null,hooksRestored:false};
const check=(v,c)=>{if(!v)throw Object.assign(new Error(c),{safeCode:c});};
const fixedError=e=>typeof e?.safeCode==='string'&&/^sdk_wire_[a-z_]+$/.test(e.safeCode)?e.safeCode:
 ['ECONNRESET','ECONNREFUSED','EPIPE','ETIMEDOUT','EPERM','EACCES'].includes(e?.code)?e.code:'UNPROJECTED';
const hash=b=>createHash('sha256').update(b).digest('hex');
function socketSnapshot(socket){
 const snapshot={connecting:socket.connecting===true,secureConnecting:socket.secureConnecting===true,
  destroyed:socket.destroyed===true,readableEnded:socket.readableEnded===true,writableEnded:socket.writableEnded===true,
  authorized:socket.authorized===true,sessionReused:null,certificateRawAvailable:false,certificateLeafMatches:false,
  peerCertificateGetterThrew:false,actualRemoteEndpointMatches:socket.remoteAddress==='127.0.0.1'&&socket.remotePort===p.port};
 try{snapshot.sessionReused=socket.isSessionReused()===true;}catch{snapshot.sessionReuseGetterThrew=true;}
 try{const raw=socket.getPeerCertificate()?.raw;snapshot.certificateRawAvailable=Buffer.isBuffer(raw);
  snapshot.certificateLeafMatches=snapshot.certificateRawAvailable&&hash(raw)===p.leafSha256;
 }catch{snapshot.peerCertificateGetterThrew=true;}
 return snapshot;
}
function observedRequest(options,callback){
 const record={ordinal:observations.length+1,pinCallbackCalls:0,pinCallbackUndefinedReturns:0,
  pinCallbackThrew:false,secureConnectEvents:0,requestClosed:false,requestErrors:0,
  socketObserved:false,socketClosed:false,responseObserved:false};
 observations.push(record);
 const originalPin=options.checkServerIdentity,mutation=pendingMutation;
 check(typeof originalPin==='function','synthetic_original_pin_callback_present');
 const observedOptions={...options,checkServerIdentity:function(...args){
  record.pinCallbackCalls++;
  (record.pinCallbackContextObservations??=[]).push({observedRequestCount:observations.length,responseObservedForOwner:record.responseObserved});
  record.pinHostIsExactTarget=args[0]==='127.0.0.1';
  const raw=args[1]?.raw;record.pinCertificateRawAvailable=Buffer.isBuffer(raw);
  record.pinCertificateLeafMatches=Buffer.isBuffer(raw)&&hash(raw)===p.leafSha256;
  try{const returned=Reflect.apply(originalPin,this,args);
   if(returned===undefined)record.pinCallbackUndefinedReturns++;
   return returned;
  }catch(error){record.pinCallbackThrew=true;throw error;}
 }};
 let request;
 request=Reflect.apply(originalRequest,https,[observedOptions,function(response){
  record.responseObserved=true;record.status=response.statusCode;
  record.reqReusedSocketAtResponse=request.reusedSocket===true;
  record.thisRequestCallbackReturnedUndefinedAtResponse=record.pinCallbackUndefinedReturns>0;
  record.pinCallbackCallsAtResponse=record.pinCallbackCalls;
  if(mutation){record.actualPeerBeforeSyntheticMutation=socketSnapshot(response.socket);mutation(response.socket);record.syntheticResponseMutationApplied=true;}
  record.responseSocket=socketSnapshot(response.socket);
  return Reflect.apply(callback,this,[response]);
 }]);
 activeRequests++;
 request.once('socket',socket=>{
  if(!socketIds.has(socket))socketIds.set(socket,++nextSocket);
  record.socketOrdinal=socketIds.get(socket);record.socketObserved=true;
  record.reqReusedSocketAtAssignment=request.reusedSocket===true;
  record.assignedSocket=socketSnapshot(socket);
  socket.once('secureConnect',()=>{record.secureConnectEvents++;record.pinCallbackCallsAtSecureConnect=record.pinCallbackCalls;record.secureSocket=socketSnapshot(socket);});
  socket.once('close',()=>{record.socketClosed=true;});
 });
 request.once('error',error=>{record.requestErrors++;record.fixedRequestError=fixedError(error);});
 request.once('close',()=>{record.requestClosed=true;activeRequests--;});
 return request;
}
function request(path,method,body){
 return new Promise((resolve,reject)=>{
  const headers={Accept:'application/json'};
  if(body!==undefined){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(body);}
  const req=https.request({protocol:'https:',hostname:'127.0.0.1',port:p.port,path,method,
   ca:fs.readFileSync(p.certificate),rejectUnauthorized:true,timeout:15000,headers},res=>{
    let count=0;
    res.on('data',part=>{count+=part.length;});
    res.once('end',()=>resolve({status:res.statusCode,responseBytes:count,complete:res.complete===true}));
   });
  req.once('error',reject);
  req.end(body);
 });
}

function newFence(){
 return installWireFence({address:'https://127.0.0.1:'+p.port,ca:fs.readFileSync(p.certificate),
  certificateSha256:p.leafSha256,hostId:'synthetic-mac',managed:[{key:'synthetic-1'},{key:'synthetic-2'},{key:'synthetic-3'}],
  remainingMs:cap=>{const left=Math.floor(until-performance.now());check(left>0,'synthetic_original_deadline');return Math.min(cap,left);}});
}
async function closeCurrentFence(){
 const current=fence;check(current!==null,'synthetic_current_fence');
 await current.close();const closure=current.publicClosure();
 current.restoreHooks();check(https.request===observedRequest,'synthetic_observer_hook_restore');
 fence=null;return closure;
}
const loginBody=JSON.stringify({role_id:'synthetic-role',secret_id:'synthetic-secret'});
try{
 check(p.case==='canonical-close'||p.case==='keep-alive-control','synthetic_fixed_case');
 https.request=observedRequest;fence=newFence();report.requests=[];
 for(const [path,method,body]of[
  ['/v1/auth/approle/login','POST',loginBody],
  ['/v1/openclaw-auth/data/manifest','GET',undefined]]){
  report.requests.push({complete:true,result:await request(path,method,body)});
 }
 report.wire=fence.rows;
 report.closures=await closeCurrentFence();
 report.positiveSequenceQualified=report.wire.length===2&&report.requests.length===2&&
  report.requests.every(row=>row.complete&&row.result.complete&&row.result.status===200)&&
  report.wire.every(row=>row.requestCount===1&&row.responseComplete&&!row.outcomeUnknown&&row.tlsVerified&&
   row.tlsSocketAuthorized&&row.tlsEndpointMatched&&row.tlsPeerCertificateAvailable&&row.tlsHostMatched&&row.tlsLeafMatched)&&
  report.closures.allDispatchedResponsesComplete&&report.closures.unknownOutcomeCount===0&&report.closures.allObservedSocketsClosed;
 check(report.positiveSequenceQualified,'synthetic_two_once_responses_qualified');
 report.negativeCases=[];
 if(p.case==='canonical-close'){
  for(const [name,field,mutate]of [
   ['unauthorized','tlsSocketAuthorized',socket=>{socket.authorized=false;}],
   ['actual-ip-mismatch','tlsEndpointMatched',socket=>{Object.defineProperty(socket,'remoteAddress',{value:'192.0.2.1',configurable:true});}],
   ['actual-port-mismatch','tlsEndpointMatched',socket=>{Object.defineProperty(socket,'remotePort',{value:9,configurable:true});}],
   ['peer-unavailable','tlsPeerCertificateAvailable',socket=>{socket.getPeerCertificate=()=>({});}],
   ['hostname-mismatch','tlsHostMatched',socket=>{const peer=socket.getPeerCertificate();socket.getPeerCertificate=()=>({...peer,subjectaltname:'DNS:unrelated.invalid',subject:{CN:'unrelated.invalid'}});}],
   ['leaf-mismatch','tlsLeafMatched',socket=>{const peer=socket.getPeerCertificate();socket.getPeerCertificate=()=>({...peer,raw:Buffer.from('synthetic-mismatching-leaf')});}],
   ['peer-getter-throws','tlsPeerCertificateAvailable',socket=>{socket.getPeerCertificate=()=>{throw new Error('synthetic-peer-getter-failure');};}]
  ]){
   // Each deliberate fault is a new synthetic case/fence, never a retry of a
   // failed business request. Only the response-time JS observation is altered.
   fence=newFence();pendingMutation=mutate;let error=null,returned=false;
   try{await request('/v1/auth/approle/login','POST',loginBody);returned=true;}
   catch(e){error=fixedError(e);}finally{pendingMutation=null;}
   const rows=fence.rows,tokenCount=fence.tokens.length;
   let nextDispatchRefused=false;
   try{https.request({},()=>{});}catch(e){nextDispatchRefused=e?.safeCode==='sdk_wire_dispatch_refused';}
   const closure=await closeCurrentFence();
   const passed=!returned&&error==='sdk_wire_response_admission'&&rows.length===1&&rows[0][field]===false&&
    rows[0].dispatched&&rows[0].requestCount===1&&rows[0].responseBytes===0&&!rows[0].responseComplete&&
    !rows[0].tlsVerified&&rows[0].outcomeUnknown&&tokenCount===0&&nextDispatchRefused&&
    closure.ownedHttpsAgentClosed&&closure.remainingRequestCount===0&&closure.remainingSocketCount===0&&
    closure.allObservedSocketsClosed&&closure.unknownOutcomeCount===1;
   report.negativeCases.push({case:name,injectedResponseObservationOnly:true,passed,errorCode:error,
    nextDispatchRefused,tokenCount,wire:rows,closure});
   check(passed,'synthetic_response_fault_refused_and_closed');
  }
 }
 report.observationCompleted=observations.length===(p.case==='canonical-close'?9:2)&&
  observations.every(row=>row.responseObserved);
}catch(error){report.fixedError=fixedError(error);}
finally{
 pendingMutation=null;
 try{if(fence){report.failedCurrentWire=fence.rows;report.failedCurrentClosure=await closeCurrentFence();}}
 catch(error){report.closureError=fixedError(error);}
 report.observerStillInstalledAfterFenceRestore=https.request===observedRequest;
 https.request=originalRequest;report.hooksRestored=https.request===originalRequest;
 report.remainingObservedRequests=activeRequests;
 report.positiveSequenceSameSocket=observations.length>=2&&observations[0].socketOrdinal===observations[1].socketOrdinal;
 report.totalObservedSocketObjects=nextSocket;
 report.syntheticNegativeCount=report.negativeCases?.length??0;
 report.ok=report.positiveSequenceQualified===true&&report.observationCompleted===true&&
  report.syntheticNegativeCount===(p.case==='canonical-close'?7:0)&&report.negativeCases.every(row=>row.passed)&&
  report.hooksRestored&&report.observerStillInstalledAfterFenceRestore&&
  activeRequests===0&&observations.every(row=>row.requestClosed&&row.socketClosed)&&
  report.closures?.ownedHttpsAgentClosed===true&&report.closures.remainingRequestCount===0&&report.closures.remainingSocketCount===0;
}
process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
