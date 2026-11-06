/** One current AuthBus cycle, with bounded verified HTTPS and public ordinals.
 * The outer Mac sandbox admits only the one owned loopback listener. This
 * adapter never publishes request paths, response bodies, identifiers or hashes.
 */
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import {createHash} from 'node:crypto';

const MAX_BYTES=1048576;
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{safeCode:code});};
const hash=raw=>createHash('sha256').update(raw).digest('hex');

export function classifyRoute(method,route,hostId,managed){
  need(typeof route==='string'&&route.length<=2048,'sdk_wire_route_shape');
  if(method==='POST'&&route==='/v1/auth/approle/login')return {routeCategory:'approle-login',slotOrdinal:0};
  if(method==='GET'){
    const control={
      '/v1/openclaw-auth/data/manifest':'manifest-read',
      '/v1/openclaw-auth/data/order-policy':'order-policy-read',
      '/v1/openclaw-auth/data/scheduler-assignments':'scheduler-assignments-read'};
    if(Object.hasOwn(control,route))return {routeCategory:control[route],slotOrdinal:0};
    const index=managed.findIndex(item=>route==='/v1/openclaw-auth/data/profiles/'+encodeURIComponent(item.key));
    if(index>=0)return {routeCategory:'profile-read',slotOrdinal:index+1};
  }
  const prefix='/v1/openclaw-auth/data/inbox/'+encodeURIComponent(hostId)+'/';
  if(method==='POST'&&route.startsWith(prefix)&&
     /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(route.slice(prefix.length)))
    return {routeCategory:'inbox-write',slotOrdinal:0};
  need(false,'sdk_wire_unregistered_route');
}

export function responseLength(headers,status){
  need(headers['content-encoding']===undefined,'sdk_wire_uncompressed_response');
  const transfer=headers['transfer-encoding'];
  const length=headers['content-length'];
  if(status===204){
    need(transfer===undefined&&(length===undefined||length==='0'),'sdk_wire_empty_204');
    return 0;
  }
  if(transfer!==undefined){
    need(typeof transfer==='string'&&/^chunked$/i.test(transfer)&&length===undefined,
      'sdk_wire_unambiguous_chunked_response');
    // IncomingMessage is decoded by Node's strict HTTP parser. Only its end
    // event with complete=true proves the terminal chunk/trailer terminator;
    // the decoded body is still bounded independently below.
    return null;
  }
  need(typeof length==='string'&&/^[0-9]{1,9}$/.test(length)&&Number(length)<=MAX_BYTES,
       'sdk_wire_bounded_content_length');
  return Number(length);
}

export function installWireFence({address,ca,certificateSha256,hostId,managed,remainingMs}){
  const target=new URL(address);
  need(target.protocol==='https:'&&target.hostname==='127.0.0.1'&&/^\d{4,5}$/.test(target.port)&&
       Number(target.port)>=1024&&Number(target.port)<=65535&&
       target.username===''&&target.password===''&&target.pathname==='/'&&!target.search&&!target.hash,
       'sdk_wire_one_loopback_https');
  need(Buffer.isBuffer(ca)&&ca.length>0&&ca.length<=65536&&/^[0-9a-f]{64}$/.test(certificateSha256),
       'sdk_wire_actual_ca_and_leaf_pin');
  const originals={request:https.request,get:https.get,httpRequest:http.request,httpGet:http.get,fetch:globalThis.fetch};
  const rows=[],sockets=new Set(),requests=new Map(),tokens=[];
  let blocked=false,enabled=true,closed=false,denials=0;
  const agent=new https.Agent({keepAlive:false,maxCachedSessions:0,maxSockets:1,maxTotalSockets:1});
  const deny=()=>{blocked=true;denials++;need(false,'sdk_wire_other_network_forbidden');};
  const safeError=code=>Object.assign(new Error(code),{safeCode:code});
  function boundedRequest(options,callback){
    need(enabled&&!blocked&&rows.length<192,'sdk_wire_no_dispatch_after_unknown_or_close');
    need(options&&typeof options==='object'&&!(options instanceof URL)&&typeof callback==='function',
         'sdk_wire_exact_request_shape');
    need(options.protocol==='https:'&&(options.hostname||options.host)===target.hostname&&
         String(options.port||443)===target.port&&options.rejectUnauthorized===true&&
         options.timeout===15000&&Buffer.isBuffer(options.ca)&&options.ca.equals(ca)&&
         options.agent===undefined&&options.checkServerIdentity===undefined&&options.createConnection===undefined,
         'sdk_wire_exact_endpoint_trust_and_original_timeout');
    const category=classifyRoute(options.method,options.path,hostId,managed);
    const budget=remainingMs(15000);
    const row={ordinal:rows.length+1,...category,method:options.method,dispatched:false,
      requestCount:0,requestBytes:0,responseBytes:0,responseComplete:false,requestClosed:false,
      socketObserved:false,socketClosed:false,tlsVerified:false,outcomeUnknown:false,
      originalHttpMaximumMs:15000,allocatedHttpMs:budget};
    rows.push(row);
    let req,timer=null,ended=false,received=false,pinVerified=false,failureDelivered=false;
    const deadline=process.hrtime.bigint()+BigInt(budget)*1000000n;
    const fail=code=>{
      if(failureDelivered)return;
      failureDelivered=true;
      blocked=true;row.errorCode=code;
      row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);
      if(timer){clearTimeout(timer);timer=null;}
      const error=safeError(code);
      req?.destroy(error);
      // Node may already have closed ClientRequest before an incomplete
      // IncomingMessage reports aborted. The installed plugin listens only to
      // request/error; forward that observed failure once when destroy can no
      // longer deliver it. This is adapter behavior, never a fabricated reply.
      if(req&&row.requestClosed&&!row.requestError){
        row.closedRequestResponseFailureForwarded=true;req.emit('error',error);
      }
    };
    try{
      req=originals.request({...options,agent,timeout:budget,
        checkServerIdentity(host,certificate){
          const normal=tls.checkServerIdentity(host,certificate);
          if(normal)return normal;
          if(host!==target.hostname||!certificate?.raw||hash(certificate.raw)!==certificateSha256)
            return safeError('sdk_wire_tls_leaf_pin');
          pinVerified=true;return undefined;
        }},response=>{
        received=true;row.status=response.statusCode;
        const socket=response.socket;
        try{
          need(pinVerified&&socket.authorized===true&&
               hash(socket.getPeerCertificate().raw)===certificateSha256,'sdk_wire_verified_exact_peer');
          row.tlsVerified=true;row.tlsVersion=socket.getProtocol();
          const expected=responseLength(response.headers,response.statusCode);
          row.responseFraming=response.statusCode===204?'no-body':expected===null?'chunked':'content-length';
          const chunks=[];
          response.on('data',part=>{
            row.responseBytes+=part.length;
            if((expected!==null&&row.responseBytes>expected)||row.responseBytes>MAX_BYTES){fail('sdk_wire_response_bound');return;}
            if(category.routeCategory==='approle-login')chunks.push(part);
          });
          response.once('aborted',()=>{row.responseAborted=true;fail('sdk_wire_response_aborted');});
          response.once('error',()=>{row.responseError=true;fail('sdk_wire_response_error');});
          response.once('end',()=>{
            if(response.complete!==true||(expected!==null&&row.responseBytes!==expected)||process.hrtime.bigint()>=deadline){
              fail('sdk_wire_complete_response_deadline');return;
            }
            row.responseComplete=true;
            if(timer){clearTimeout(timer);timer=null;}
            if(category.routeCategory==='approle-login'&&response.statusCode===200){
              try{
                const value=JSON.parse(Buffer.concat(chunks));
                need(typeof value.auth?.client_token==='string'&&value.auth.client_token.length>=8,
                     'sdk_wire_private_login_token_shape');
                tokens.push(value.auth.client_token);row.privateTokenCaptured=true;
              }catch{blocked=true;row.errorCode='sdk_wire_login_payload_invalid';}
            }
          });
          callback(response);
        }catch{response.resume();fail('sdk_wire_response_admission');}
      });
      requests.set(req,row);
      req.once('socket',socket=>{
        sockets.add(socket);row.socketObserved=true;
        socket.once('close',()=>{row.socketClosed=true;sockets.delete(socket);});
      });
      req.once('close',()=>{
        row.requestClosed=true;requests.delete(req);
        if(failureDelivered&&row.errorCode&&!row.requestError){
          row.closedRequestResponseFailureForwarded=true;req.emit('error',safeError(row.errorCode));
        }
      });
      req.once('timeout',()=>fail('sdk_wire_request_timeout'));
      req.once('error',()=>{
        blocked=true;row.requestError=true;row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);
        if(timer){clearTimeout(timer);timer=null;}
      });
      const write=req.write.bind(req),end=req.end.bind(req);
      const count=data=>{
        if(data===undefined||data===null)return;
        const bytes=Buffer.isBuffer(data)?data:Buffer.from(data);
        row.requestBytes+=bytes.length;need(row.requestBytes<=MAX_BYTES,'sdk_wire_request_bound');
      };
      req.write=function(data,...args){
        try{
          need(enabled&&!blocked&&!ended,'sdk_wire_one_request_write_context');count(data);
          return write(data,...args);
        }catch{denials++;fail('sdk_wire_request_write_refused');throw safeError('sdk_wire_request_write_refused');}
      };
      req.end=function(data,...args){
        try{
          need(enabled&&!blocked&&!ended,'sdk_wire_one_request_end');count(data);ended=true;
          row.dispatched=true;row.requestCount=1;
          return end(data,...args);
        }catch{denials++;fail('sdk_wire_request_end_refused');throw safeError('sdk_wire_request_end_refused');}
      };
      timer=setTimeout(()=>fail('sdk_wire_absolute_http_deadline'),budget);
      return req;
    }catch(error){
      blocked=true;row.errorCode='sdk_wire_request_setup_failed';
      row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);
      if(timer)clearTimeout(timer);
      req?.destroy(safeError('sdk_wire_request_setup_failed'));
      throw safeError('sdk_wire_request_setup_failed');
    }
  }
  const guardedRequest=(...args)=>{
    try{return boundedRequest(...args);}catch{blocked=true;denials++;throw safeError('sdk_wire_dispatch_refused');}
  };
  https.request=guardedRequest;https.get=deny;http.request=deny;http.get=deny;globalThis.fetch=deny;
  return Object.freeze({rows,tokens,
    stopNetwork(){enabled=false;},
    deniedCount(){return denials;},
    unknown(){return rows.some(row=>row.outcomeUnknown||row.dispatched&&!row.responseComplete);},
    async close(){
      enabled=false;
      for(const [req,row]of requests)if(!row.responseComplete)req.destroy(safeError('sdk_wire_owned_worker_closing'));
      agent.destroy();
      const waits=[...[...sockets].map(socket=>new Promise(resolve=>socket.once('close',resolve))),
        ...[...requests.keys()].map(req=>new Promise(resolve=>req.once('close',resolve)))];
      if(waits.length){
        let timer;
        try{await Promise.race([Promise.all(waits),new Promise((_,reject)=>{
          timer=setTimeout(()=>reject(safeError('sdk_wire_socket_closure_deadline')),remainingMs(1000));
        })]);}finally{if(timer)clearTimeout(timer);}
      }
      need(requests.size===0&&sockets.size===0,'sdk_wire_owned_connections_not_closed');
      closed=true;
    },
    publicClosure(){return {ownedHttpsAgentClosed:closed,remainingRequestCount:requests.size,
      remainingSocketCount:sockets.size,otherNetworkDenials:denials,
      allDispatchedResponsesComplete:rows.every(row=>!row.dispatched||row.responseComplete),
      unknownOutcomeCount:rows.filter(row=>row.outcomeUnknown).length,
      allObservedSocketsClosed:rows.every(row=>!row.socketObserved||row.socketClosed)};},
    restoreHooks(){
      const same=https.request===guardedRequest&&https.get===deny&&http.request===deny&&
        http.get===deny&&globalThis.fetch===deny;
      https.request=originals.request;https.get=originals.get;http.request=originals.httpRequest;
      http.get=originals.httpGet;globalThis.fetch=originals.fetch;
      need(same,'sdk_wire_network_hook_changed');
    }
  });
}
