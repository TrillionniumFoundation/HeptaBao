import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openCoordinator } from '../coordinator.mjs';
import { ProductionTransportClient } from '../transport/production-client.js';
import { digest,TRANSPORT,sourceFor,slotKey,validatePair } from '../protocol.mjs';
import { makeRoot,configuration,event,grant,FileKv } from './fixture.mjs';

async function fixture(t){
  const root=makeRoot(t),keyFile=path.join(root,'tls.key'),certFile=path.join(root,'tls.crt');
  const child=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',certFile,
    '-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],{timeout:5000,maxBuffer:65536});
  assert.equal(child.status,0);assert.equal(child.signal,null);
  fs.chmodSync(keyFile,0o600);fs.chmodSync(certFile,0o600);
  const certificate=fs.readFileSync(certFile),key=fs.readFileSync(keyFile),pin=new X509Certificate(certificate).fingerprint256.replaceAll(':','').toLowerCase();
  const config=configuration(root),remote=new FileKv(path.join(root,'remote.private.json'));
  config.implementationSha256=JSON.parse(fs.readFileSync(fileURLToPath(new URL('../source-manifest.public.json',import.meta.url)),'utf8')).implementationSha256;
  const rows=[],sockets=new Set(),peerCloses=[],revoked=new Set();let dropAck=false;
  const credentials={coordinator:{role:'synthetic-coordinator-role',secret:'synthetic-coordinator-secret',token:'synthetic-coordinator-bearer'},
    producer:{role:'synthetic-producer-role',secret:'synthetic-producer-secret',token:'synthetic-producer-bearer'}};
  const server=https.createServer({key,cert:certificate,minVersion:'TLSv1.2'},(request,response)=>{
    const chunks=[];let bytes=0;request.on('data',b=>{bytes+=b.length;if(bytes>1024*1024)request.destroy();else chunks.push(b);});
    request.on('end',async()=>{try{
      const url=new URL(request.url,'https://127.0.0.1'),payload=chunks.length?JSON.parse(Buffer.concat(chunks).toString('utf8')):null;
      const row={method:request.method,path:url.pathname};rows.push(row);
      const reply=(status,value)=>{response.writeHead(status,{'Content-Type':'application/json','Connection':'close'});response.end(value===undefined?undefined:JSON.stringify(value));};
      if(url.pathname==='/v1/auth/approle/login'){
        const found=Object.values(credentials).find(c=>c.role===payload?.role_id&&c.secret===payload?.secret_id);
        if(!found){reply(403,{errors:['denied']});return;}revoked.delete(found.token);reply(200,{auth:{client_token:found.token,lease_duration:3600,renewable:true}});return;
      }
      const token=request.headers['x-vault-token'],isCoordinator=token===credentials.coordinator.token;
      if(!Object.values(credentials).some(c=>c.token===token)||revoked.has(token)){reply(403,{errors:['denied']});return;}
      if(url.pathname==='/v1/auth/token/renew-self'){reply(200,{auth:{client_token:token,lease_duration:3600,renewable:true}});return;}
      if(url.pathname==='/v1/auth/token/revoke-self'){revoked.add(token);reply(204);return;}
      if(url.pathname==='/v1/auth/token/lookup-self'){reply(200,{data:{}});return;}
      if(url.pathname==='/v1/openclaw-auth/config'){
        if(!isCoordinator){reply(403,{errors:['denied']});return;}reply(200,{data:{max_versions:2,cas_required:true}});return;
      }
      if(url.pathname.startsWith('/v1/openclaw-auth/metadata/')){
        if(!isCoordinator){reply(403,{errors:['denied']});return;}
        const key=url.pathname.slice('/v1/openclaw-auth/metadata/'.length).split('/').map(decodeURIComponent).join('/'),current=await remote.read(key);
        reply(current?200:404,current?{data:{max_versions:0,cas_required:false,current_version:current.version}}:{errors:['absent']});return;
      }
      const prefix='/v1/openclaw-auth/data/';if(!url.pathname.startsWith(prefix)){reply(404,{errors:['absent']});return;}
      const key=url.pathname.slice(prefix.length).split('/').map(decodeURIComponent).join('/');
      if(request.method==='GET'){
        const version=url.searchParams.get('version');const current=version?await remote.history(key,Number(version)):await remote.read(key);
        reply(current?200:404,current?{data:{data:current.data,metadata:{version:current.version}}}:{errors:['absent']});return;
      }
      if(request.method==='POST'){
        if(!isCoordinator&&!key.startsWith('transport-v1/fixture-host/outbox/')&&!key.startsWith('transport-v1/fixture-host/reports/')){reply(403,{errors:['denied']});return;}
        try{const version=await remote.write(key,payload.data,payload.options.cas);
          if(dropAck&&key.includes('/ack/')&&payload.options.cas>0){dropAck=false;request.socket.destroy();return;}
          reply(200,{data:{version}});
        }catch(error){if(error.conflict)reply(400,{errors:['check-and-set parameter did not match the current version']});else throw error;}return;
      }
      reply(405,{errors:['method']});
    }catch{request.socket.destroy();}});
  });
  server.on('connection',socket=>{sockets.add(socket);peerCloses.push(new Promise(resolve=>socket.once('close',()=>{sockets.delete(socket);resolve();})));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=`https://127.0.0.1:${server.address().port}`;
  Object.assign(config,{address,caFile:certFile,serverCertificateSha256:pin,roleIdFile:path.join(root,'coordinator-role'),secretIdFile:path.join(root,'coordinator-secret')});
  fs.writeFileSync(config.roleIdFile,credentials.coordinator.role,{mode:0o600});fs.writeFileSync(config.secretIdFile,credentials.coordinator.secret,{mode:0o600});
  const producerDir=path.join(root,'producer');fs.mkdirSync(producerDir,{mode:0o700});
  const producerConfig={address,caFile:certFile,serverCertificateSha256:pin,hostId:'fixture-host',roleIdFile:path.join(producerDir,'role'),secretIdFile:path.join(producerDir,'secret')};
  fs.writeFileSync(producerConfig.roleIdFile,credentials.producer.role,{mode:0o600});fs.writeFileSync(producerConfig.secretIdFile,credentials.producer.secret,{mode:0o600});
  t.after(async()=>{let timer;try{
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    await Promise.race([Promise.all(peerCloses),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('synthetic_peer_close_not_observed')),2000);})]);
    assert.equal(sockets.size,0);
  }finally{clearTimeout(timer);key.fill(0);}});
  return {root,config,remote,rows,producerDir,producerConfig,dropNextAck(){dropAck=true;}};
}

async function setup(f){const c=openCoordinator(f.config),first=event(1,'new-profile');await c.initialize();await c.authorize(grant(first));await c.bootstrap(first);await c.enroll();
  const productionTransport={schema:TRANSPORT,production:true,epoch:c.topology[0].epoch,slots:1,agents:['main'],controlDigest:digest(c.control),serverCertificateSha256:f.config.serverCertificateSha256};
  const producer=new ProductionTransportClient({...f.producerConfig,productionTransport},f.producerDir);return {c,producer,first};}

test('concrete strict TLS/AppRole adapter and unchanged production client perform complete fixed-slot transaction',{timeout:15000},async t=>{
  const f=await fixture(t),{c,producer,first}=await setup(f);
  try{const next=event(2);await c.authorize(grant(next,first));await producer.writeInbox(next.sourceHost,next.eventId,next);
    assert.equal((await c.once()).credentialAcknowledgements,1);const profile=(await producer.readSecret('manifest')).data.profiles[0];assert.equal(profile.digest,next.digest);
    assert.equal((await producer.writeInbox(next.sourceHost,next.eventId,next)).alreadyCanonical,true);
    assert.equal(f.rows.filter(r=>r.path==='/v1/auth/approle/login').length,2);
    assert.ok(f.rows.some(r=>r.path.startsWith('/v1/openclaw-auth/metadata/')));
  }finally{await producer.close();await c.close({revoke:true,deadlineMs:Date.now()+15000});}
});

test('strict TLS wrong leaf pin prevents HTTP authentication or KV dispatch',{timeout:10000},async t=>{
  const f=await fixture(t),c=openCoordinator({...f.config,serverCertificateSha256:'0'.repeat(64)});
  try{await assert.rejects(c.initialize(),/tls_leaf_pin_mismatch/);assert.equal(f.rows.length,0);assert.equal(f.remote.load().writes.length,0);}
  finally{await c.close();}
});

test('real TLS dropped ack response remains unknown and cold coordinator only reads to reconcile',{timeout:15000},async t=>{
  const f=await fixture(t);let {c,producer,first}=await setup(f);
  try{const next=event(2);await c.authorize(grant(next,first));await producer.writeInbox(next.sourceHost,next.eventId,next);f.dropNextAck();
    await assert.rejects(c.once(),e=>e.unknown===true);const key=slotKey(sourceFor(c.topology[0],c.owner),0,'ack'),before=f.remote.load().writes.filter(r=>r.key===key).length;
    await c.close();c=openCoordinator(f.config);assert.equal((await c.recover()).completed,true);
    assert.equal(f.remote.load().writes.filter(r=>r.key===key).length,before);
    const source=sourceFor(c.topology[0],c.owner);assert.equal(validatePair(source,0,await f.remote.read(slotKey(source,0)),await f.remote.read(key)),true);
    assert.equal(f.rows.filter(r=>r.path==='/v1/auth/approle/login').length,2);
  }finally{await producer.close();await c.close({revoke:true,deadlineMs:Date.now()+15000});}
});
