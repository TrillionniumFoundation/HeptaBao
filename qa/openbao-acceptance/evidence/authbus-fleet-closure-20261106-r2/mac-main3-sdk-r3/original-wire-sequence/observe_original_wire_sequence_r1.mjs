import fs from 'node:fs';
import https from 'node:https';
import {createHash} from 'node:crypto';
import {installWireFence} from './main3_sdk_wire_r2.mjs';
const p=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const until=performance.now()+7000;
const originalRequest=https.request;
const observations=[],socketIds=new WeakMap();let nextSocket=0,activeRequests=0,fence=null;
const report={schema:'heptabao.synthetic-original-wire-two-request-node.r1',ok:false,
 case:p.case,platform:process.platform,node:process.version,
 originalWireByteUnchanged:true,pinVerifiedDirectLocalVariableRead:false,
 pinVerifiedDerivedFromExactOriginalCallbackReturn:true,providerCalled:false,
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
 const originalPin=options.checkServerIdentity;
 check(typeof originalPin==='function','synthetic_original_pin_callback_present');
 const observedOptions={...options,checkServerIdentity:function(...args){
  record.pinCallbackCalls++;
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
  record.pinVerifiedDerivedAtResponse=record.pinCallbackUndefinedReturns>0;
  record.pinDerivationIsDirectVariableRead=false;
  record.responseSocket=socketSnapshot(response.socket);
  return Reflect.apply(callback,this,[response]);
 }]);
 activeRequests++;
 request.once('socket',socket=>{
  if(!socketIds.has(socket))socketIds.set(socket,++nextSocket);
  record.socketOrdinal=socketIds.get(socket);record.socketObserved=true;
  record.reqReusedSocketAtAssignment=request.reusedSocket===true;
  record.assignedSocket=socketSnapshot(socket);
  socket.once('secureConnect',()=>{record.secureConnectEvents++;record.secureSocket=socketSnapshot(socket);});
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
try{
 check(p.case==='canonical-close'||p.case==='keep-alive-control','synthetic_fixed_case');
 https.request=observedRequest;
 fence=installWireFence({address:'https://127.0.0.1:'+p.port,ca:fs.readFileSync(p.certificate),
  certificateSha256:p.leafSha256,hostId:'synthetic-mac',managed:[{key:'synthetic-1'},{key:'synthetic-2'},{key:'synthetic-3'}],
  remainingMs:cap=>{const left=Math.floor(until-performance.now());check(left>0,'synthetic_original_deadline');return Math.min(cap,left);}});
 report.requests=[];
 for(const [path,method,body]of[
  ['/v1/auth/approle/login','POST',JSON.stringify({role_id:'synthetic-role',secret_id:'synthetic-secret'})],
  ['/v1/openclaw-auth/data/manifest','GET',undefined]]){
  try{report.requests.push({complete:true,result:await request(path,method,body)});}
  catch(error){report.requests.push({complete:false,fixedError:fixedError(error)});break;}
 }
 report.observationCompleted=observations.length===2&&observations.every(row=>row.responseObserved);
}catch(error){report.fixedError=fixedError(error);}
finally{
 try{if(fence){await fence.close();report.closures=fence.publicClosure();report.wire=fence.rows;fence.restoreHooks();}}
 catch(error){report.closureError=fixedError(error);}
 report.observerStillInstalledAfterFenceRestore=https.request===observedRequest;
 https.request=originalRequest;report.hooksRestored=https.request===originalRequest;
 report.remainingObservedRequests=activeRequests;
 report.sourceDerivedSameSocket=observations.length===2&&observations[0].socketOrdinal===observations[1].socketOrdinal;
 report.totalObservedSocketObjects=nextSocket;
 report.originalWireRejectedSecond=report.requests?.length===2&&report.requests[1].complete===false;
 report.ok=report.observationCompleted===true&&report.hooksRestored&&report.observerStillInstalledAfterFenceRestore&&
  activeRequests===0&&observations.every(row=>row.requestClosed&&row.socketClosed)&&
  report.closures?.ownedHttpsAgentClosed===true&&report.closures.remainingRequestCount===0&&report.closures.remainingSocketCount===0;
}
process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
