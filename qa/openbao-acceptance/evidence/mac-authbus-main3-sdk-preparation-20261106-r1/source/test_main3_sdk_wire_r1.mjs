#!/usr/bin/env node
/** Independent real TLS peers exercise the wire fence; all bytes are synthetic.
 * This Linux/local test is not evidence that the Mac sandbox or SDK ran.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {once} from 'node:events';
import {classifyRoute,responseLength,installWireFence} from './main3_sdk_wire_r1.mjs';

const started=process.hrtime.bigint(),checks=[];
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'heptabao-main3-wire-'));
fs.chmodSync(temporary,0o700);
const keyFile=path.join(temporary,'synthetic-key.pem'),certFile=path.join(temporary,'synthetic-cert.pem');
const slots=[1,2,3].map(n=>({key:'selected-main-'+n}));
const original={request:https.request,get:https.get,httpRequest:http.request,httpGet:http.get,fetch:globalThis.fetch};
let totalConnections=0,totalHttp=0,allPeersClosed=true,failedPeer=null;
const check=(name,fn)=>{fn();checks.push({case:name,passed:true});};
function options(port,ca,route='/v1/auth/approle/login',method='POST'){
  return {protocol:'https:',hostname:'127.0.0.1',port,path:route,method,ca,rejectUnauthorized:true,
    timeout:15000,headers:{Accept:'application/json'}};
}
async function request(opt,body){
  return await new Promise((resolve,reject)=>{
    const req=https.request(opt,res=>{
      const parts=[];res.on('data',chunk=>parts.push(chunk));
      // Deliberately matches the real plugin's data/end + request/error shape.
      res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(parts)}));
    });
    req.on('error',reject);
    if(body!==undefined)req.write(body);
    req.end();
  });
}
async function bounded(promise,ms=1800){
  let timer;
  try{return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new Error('test_plugin_style_promise_unsettled')),ms);
  })]);}finally{clearTimeout(timer);}
}
let key,ca,pin;
async function peerCase(name,kind,run,overrides={}){
  const sockets=new Set(),observed={connections:0,http:0,bytes:0};
  const server=tls.createServer({key,cert:ca,minVersion:'TLSv1.2'},socket=>{
    observed.connections++;sockets.add(socket);socket.on('error',()=>{});
    socket.once('close',()=>sockets.delete(socket));
    let bytes=Buffer.alloc(0),responded=false;
    socket.on('data',part=>{
      observed.bytes+=part.length;bytes=Buffer.concat([bytes,part]);
      const headerEnd=bytes.indexOf('\r\n\r\n');
      if(responded||headerEnd<0)return;
      responded=true;observed.http++;
      const route=bytes.subarray(0,headerEnd).toString().split(' ')[1];
      const payload=Buffer.from(JSON.stringify(route==='/v1/auth/approle/login'
        ?{auth:{client_token:'synthetic-only-token-main3',lease_duration:3600}}
        :{data:{data:{synthetic:true},metadata:{version:1}}}));
      if(kind==='stall')return;
      if(kind==='truncated'){
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{}');return;
      }
      if(kind==='oversize'){
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n{}');return;
      }
      if(kind==='chunked'){
        socket.end('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n');return;
      }
      if(kind==='invalid-login'){
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}');return;
      }
      socket.end(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+
        payload.length+'\r\nConnection: close\r\n\r\n'),payload]));
    });
  });
  server.on('tlsClientError',()=>{});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const port=server.address().port,deadline=performance.now()+2500;
  const fence=installWireFence({address:'https://127.0.0.1:'+port,ca,certificateSha256:pin,hostId:'mac',managed:slots,
    remainingMs:cap=>{const remaining=Math.min(cap,Math.floor(deadline-performance.now()),kind==='stall'?120:1500);
      assert(remaining>0);return remaining;},...overrides});
  let closure;
  try{await run({fence,opt:options(port,ca),observed,port});}
  catch(error){failedPeer={name,kind,observed,rows:fence.rows};throw error;}
  finally{
    try{await fence.close();closure=fence.publicClosure();}
    finally{
      fence.restoreHooks();
      const closes=[...sockets].map(socket=>new Promise(resolve=>socket.once('close',resolve)));
      for(const socket of sockets)socket.destroy();
      const done=new Promise(resolve=>server.close(resolve));await bounded(Promise.all([done,...closes]),1000);
      totalConnections+=observed.connections;totalHttp+=observed.http;
      allPeersClosed=allPeersClosed&&sockets.size===0;
    }
  }
  assert.equal(closure.remainingSocketCount,0);assert.equal(closure.remainingRequestCount,0);
  assert.equal(closure.ownedHttpsAgentClosed,true);
  checks.push({case:name,passed:true});
}

try{
  execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout',keyFile,'-out',certFile],{stdio:['ignore','pipe','pipe'],timeout:10000,maxBuffer:65536});
  fs.chmodSync(keyFile,0o600);fs.chmodSync(certFile,0o600);
  key=fs.readFileSync(keyFile);ca=fs.readFileSync(certFile);
  pin=createHash('sha256').update(new X509Certificate(ca).raw).digest('hex');
  check('route_exact_three_slot_ordinals',()=>slots.forEach((slot,n)=>assert.deepEqual(
    classifyRoute('GET','/v1/openclaw-auth/data/profiles/'+slot.key,'mac',slots),
    {routeCategory:'profile-read',slotOrdinal:n+1})));
  check('route_unknown_and_cross_host_writes_refused',()=>{
    for(const [method,route]of [['GET','/v1/sys/health'],['POST','/v1/openclaw-auth/data/profiles/selected-main-1'],
      ['POST','/v1/openclaw-auth/data/inbox/another/00000000-0000-0000-0000-000000000000'],
      ['GET','/v1/openclaw-auth/data/profiles/selected-main-1?extra=1']])
      assert.throws(()=>classifyRoute(method,route,'mac',slots));
  });
  check('bounded_complete_response_headers',()=>{
    assert.equal(responseLength({'content-length':'1048576'},200),1048576);
    assert.equal(responseLength({'content-length':'0'},204),0);
    for(const headers of [{},{'content-length':'1048577'},{'content-length':'-1'},
      {'content-length':['2','2']},{'content-length':'2','transfer-encoding':'chunked'},
      {'content-length':'2','content-encoding':'gzip'}])assert.throws(()=>responseLength(headers,200));
  });
  check('one_unprivileged_loopback_https_endpoint',()=>{
    for(const address of ['http://127.0.0.1:38200','https://localhost:38200','https://127.0.0.1:9',
      'https://127.0.0.1:443','https://127.0.0.1:38200/extra','https://user@127.0.0.1:38200'])
      assert.throws(()=>installWireFence({address,ca,certificateSha256:pin,hostId:'mac',managed:slots,remainingMs:()=>100}));
    assert.equal(https.request,original.request);
  });
  await peerCase('real_tls_login_reads_inbox_and_exact_connection_closure','good',async({fence,opt,observed,port})=>{
    const login=await bounded(request(opt));assert.equal(login.status,200);
    assert.equal(fence.tokens.length,1);assert.equal(fence.tokens[0],'synthetic-only-token-main3');
    await bounded(request(options(port,ca,'/v1/openclaw-auth/data/manifest','GET')));
    await bounded(request(options(port,ca,'/v1/openclaw-auth/data/profiles/selected-main-2','GET')));
    await bounded(request(options(port,ca,'/v1/openclaw-auth/data/inbox/mac/00000000-0000-0000-0000-000000000000','POST')));
    assert.equal(observed.http,4);assert.equal(fence.rows.length,4);
    assert.equal(fence.rows[2].slotOrdinal,2);
    assert(fence.rows.every(row=>row.responseComplete&&row.tlsVerified&&row.requestCount===1));
    assert.equal(fence.unknown(),false);assert.equal(fence.deniedCount(),0);
  });
  await peerCase('wrong_leaf_pin_prevents_http_request_and_blocks_replay','good',async({fence,opt,observed})=>{
    await assert.rejects(bounded(request(opt)));assert.equal(observed.http,0);
    assert.equal(fence.rows[0].tlsVerified,false);assert.equal(fence.tokens.length,0);
    assert.throws(()=>https.request(opt,()=>{}));assert.equal(fence.rows.length,1);
  },{certificateSha256:'0'.repeat(64)});
  for(const kind of ['truncated','oversize','chunked'])
    await peerCase(kind+'_response_rejected_no_retry_and_all_handles_closed',kind,async({fence,opt,observed})=>{
      await assert.rejects(bounded(request(opt)),error=>error.message!=='test_plugin_style_promise_unsettled');
      assert.equal(observed.http,1);assert.equal(fence.tokens.length,0);
      assert.equal(fence.unknown(),true);assert.throws(()=>https.request(opt,()=>{}));
      assert.equal(fence.rows.length,1);
    });
  await peerCase('absolute_response_deadline_and_no_retry','stall',async({fence,opt,observed})=>{
    const before=performance.now();await assert.rejects(bounded(request(opt)));
    assert(performance.now()-before<1000);assert.equal(observed.http,1);assert.equal(fence.unknown(),true);
    assert.throws(()=>https.request(opt,()=>{}));
  });
  await peerCase('malformed_complete_login_never_exposes_token_or_allows_next_dispatch','invalid-login',async({fence,opt})=>{
    await bounded(request(opt));assert.equal(fence.tokens.length,0);
    assert.equal(fence.rows[0].errorCode,'sdk_wire_login_payload_invalid');
    assert.equal(fence.rows[0].responseComplete,true);assert.throws(()=>https.request(opt,()=>{}));
  });
  await peerCase('request_body_bound_blocks_before_http_and_closes_request','good',async({fence,opt,observed})=>{
    const req=https.request(opt,()=>{});req.on('error',()=>{});
    assert.throws(()=>req.write(Buffer.alloc(1048577)),{safeCode:'sdk_wire_request_write_refused'});
    assert.throws(()=>https.request(opt,()=>{}));assert.equal(fence.rows[0].requestCount,0);
    await new Promise(resolve=>setImmediate(resolve));assert.equal(observed.http,0);
  });
  await peerCase('route_admission_refusal_dispatches_nothing','good',async({fence,opt,observed})=>{
    assert.throws(()=>https.request({...opt,path:'/v1/sys/health'},()=>{}));
    assert.equal(fence.rows.length,0);assert.equal(observed.http,0);assert.equal(fence.deniedCount(),1);
  });
  await peerCase('other_network_apis_refused_and_poison_cycle','good',async({fence,opt,observed})=>{
    assert.throws(()=>http.request('http://127.0.0.1:9'));assert.throws(()=>globalThis.fetch('https://example.invalid'));
    assert.throws(()=>https.request(opt,()=>{}));assert.equal(fence.rows.length,0);assert.equal(observed.http,0);
  });
  check('all_global_hooks_restored',()=>{
    assert.equal(https.request,original.request);assert.equal(https.get,original.get);
    assert.equal(http.request,original.httpRequest);assert.equal(http.get,original.httpGet);assert.equal(globalThis.fetch,original.fetch);
  });
  check('all_owned_tls_peers_closed',()=>assert.equal(allPeersClosed,true));
  process.stdout.write(JSON.stringify({schema:'heptabao.main3-sdk-wire.local-qualification.r1',ok:true,
    platform:process.platform,node:process.version,checks,passed:checks.length,failed:0,
    totalTlsConnections:totalConnections,totalHttpRequests:totalHttp,
    macSandboxExecuted:false,actualSdkExecuted:false,productionCredentialsRead:false,
    elapsedMs:Number((process.hrtime.bigint()-started)/1000000n)})+'\n');
}catch(error){
  process.stdout.write(JSON.stringify({schema:'heptabao.main3-sdk-wire.local-qualification.r1',ok:false,
    checks,passed:checks.length,error:error.stack,failedPeer,macSandboxExecuted:false,actualSdkExecuted:false})+'\n');
  process.exitCode=1;
}finally{fs.rmSync(temporary,{recursive:true,force:false});}
