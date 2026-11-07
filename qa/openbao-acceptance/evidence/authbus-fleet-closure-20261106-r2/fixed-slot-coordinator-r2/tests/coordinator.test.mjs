import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { BoundedOutbox, normalizeTransport } from '../transport/bounded-outbox.js';
import { PrivateOutboxStore } from '../transport/private-outbox-store.js';
import { digest, sourceFor, slotKey, reportKey, validatePair, TRANSPORT, receiptKey } from '../protocol.mjs';
import { makeRoot, initialized, openFixture, event, grant, FileKv, configuration } from './fixture.mjs';

function client(root,c){const state=path.join(root,'producer');fs.mkdirSync(state,{mode:0o700});
  const store=new PrivateOutboxStore(path.join(state,'outbox'),{schema:'synthetic-producer-state'});
  const config=normalizeTransport({schema:TRANSPORT,production:true,epoch:c.topology[0].epoch,slots:1,agents:['main'],
    controlDigest:digest(c.control),serverCertificateSha256:'a'.repeat(64)},'fixture-host');
  const adapter={readSecret:(key,_options)=>c.adapter.read(key),writeSecret:(key,value,cas,_options)=>c.adapter.write(key,value,cas)};
  return {store,outbox:new BoundedOutbox(adapter,store,config)};}

test('unchanged producer validates enrollment, two exact authorized rotations and slot reuse',async t=>{
  const root=makeRoot(t),{c,first}=await initialized(root);t.after(()=>c.close());const p=client(root,c);t.after(()=>p.store.close());
  for(const [previous,next] of [[first,event(2)],[event(2),event(3)]]){
    await c.authorize(grant(next,previous));await p.outbox.publish(next);const result=await c.once();assert.equal(result.credentialAcknowledgements,1);
    const source=sourceFor(c.topology[0],c.owner),slot=await c.adapter.read(slotKey(source,0)),ack=await c.adapter.read(slotKey(source,0,'ack'));
    assert.equal(validatePair(source,0,slot,ack),true);assert.equal(ack.data.receipt.credentialDigest,next.digest);
    assert.equal((await c.adapter.read('manifest')).data.coordinator.authorizations.length,0);
  }
  assert.equal((await c.adapter.read(slotKey(sourceFor(c.topology[0],c.owner),0))).version,3);
  assert.equal((await c.once()).credentialAcknowledgements,0);
});

test('no grant and revoked grant stay pending; full single slot preserves backpressure',async t=>{
  const root=makeRoot(t),{c,first}=await initialized(root);t.after(()=>c.close());const p=client(root,c);t.after(()=>p.store.close());
  const next=event(2);await p.outbox.publish(next);const before=c.adapter.load().writes.length;
  assert.equal((await c.once()).deferredUnauthorized,1);assert.equal(c.adapter.load().writes.length,before);
  await assert.rejects(p.outbox.publish(event(3)),e=>e.backpressure===true);
  const approval=grant(next,first);await c.authorize(approval);await c.revokeAuthorization(approval.authorizationId);
  assert.equal((await c.once()).deferredUnauthorized,1);
  await assert.rejects(c.authorize(grant(next,event(99))),/operator_expected_current_digest_mismatch/);
});

test('health ack and fixed report make zero scheduler/provider actions',async t=>{
  const root=makeRoot(t),{c}=await initialized(root);t.after(()=>c.close());const p=client(root,c);t.after(()=>p.store.close());
  const health={schemaVersion:2,kind:'health-observation',sourceHost:'fixture-host',eventId:'44444444-4444-4444-8444-444444444444',agentId:'main',healthy:false};
  await p.outbox.publish(health);let result=await c.once();assert.equal(result.healthAcknowledgements,1);assert.equal(result.schedulerActions,0);
  assert.equal((await c.adapter.read(slotKey(sourceFor(c.topology[0],c.owner),0,'ack'))).data.status,'observed_health_no_scheduler_action');
  await p.outbox.publish({schemaVersion:2,kind:'agent-report',sourceHost:'fixture-host',eventId:'55555555-5555-4555-8555-555555555555',agentId:'main',profiles:[]});
  result=await c.once();assert.equal(result.reportsObserved,1);assert.equal(result.providerCalls,0);
});

for(const role of ['profile','manifest','ack'])for(const mode of ['before','after']){
  test(`${role} unknown ${mode} remote commit retains original intent across cold process state`,async t=>{
    const root=makeRoot(t);let {c,first,adapter}=await initialized(root);const p=client(root,c);t.after(()=>p.store.close());
    const next=event(2);await c.authorize(grant(next,first));await p.outbox.publish(next);
    const profile={schemaVersion:1,profileId:next.profileId,credential:next.credential,digest:next.digest,identity:next.identity};
    const key=role==='profile'?'profiles/sha256-'+digest(profile):role==='manifest'?'manifest':slotKey(sourceFor(c.topology[0],c.owner),0,'ack');
    adapter.fault={key,mode};await assert.rejects(c.once(),e=>e.unknown===true);const calls=adapter.load().writes.filter(x=>x.key===key).length;
    await c.close();c=openFixture(root,{adapter:new FileKv(adapter.filename)});t.after(()=>c.close());
    if(mode==='before'){
      await assert.rejects(c.recover(),e=>e.unknown===true);await assert.rejects(c.once(),e=>e.unknown===true);
      assert.equal(c.adapter.load().writes.filter(x=>x.key===key).length,calls);assert.equal(c.store.get('active').value.phase,'dispatched');
    }else{
      const result=await c.recover();assert.equal(result.completed,true);
      assert.equal(c.adapter.load().writes.filter(x=>x.key===key).length,calls);
      const source=sourceFor(c.topology[0],c.owner);assert.equal(validatePair(source,0,await c.adapter.read(slotKey(source,0)),await c.adapter.read(slotKey(source,0,'ack'))),true);
      assert.equal((await c.once()).credentialAcknowledgements,0);
    }
  });
}

test('exact retained manifest history resolves an original committed postimage without rewrite',async t=>{
  const root=makeRoot(t);let {c,first,adapter}=await initialized(root);const p=client(root,c);t.after(()=>p.store.close());
  const next=event(2);await c.authorize(grant(next,first));await p.outbox.publish(next);adapter.fault={key:'manifest',mode:'after'};
  await assert.rejects(c.once(),e=>e.unknown===true);const committed=await adapter.read('manifest');
  const changed=structuredClone(committed.data);changed.coordinator.authorizations.push(grant(event(3),next));await adapter.write('manifest',changed,committed.version);
  const calls=adapter.load().writes.filter(x=>x.key==='manifest').length;await c.close();c=openFixture(root,{adapter:new FileKv(adapter.filename)});t.after(()=>c.close());
  await c.recover();assert.equal(c.adapter.load().writes.filter(x=>x.key==='manifest').length,calls);assert.ok(c.adapter.counts.historyReads>=1);
});

test('immutable profile collision refuses before canonical mutation',async t=>{
  const root=makeRoot(t),{c,first}=await initialized(root);t.after(()=>c.close());const p=client(root,c);t.after(()=>p.store.close());
  const next=event(2);await c.authorize(grant(next,first));await p.outbox.publish(next);
  const profile={schemaVersion:1,profileId:next.profileId,credential:next.credential,digest:next.digest,identity:next.identity};
  await c.adapter.write('profiles/sha256-'+digest(profile),{foreign:true},0);
  const before=(await c.adapter.read('manifest')).version;await assert.rejects(c.once(),/coordinator_immutable_collision/);
  assert.equal((await c.adapter.read('manifest')).version,before);
});

test('missing private enrollment history cannot adopt a used remote control',async t=>{
  const root=makeRoot(t),ready=await initialized(root);await ready.c.close();
  const replacement=makeRoot(t),adapter=new FileKv(ready.adapter.filename),c=openFixture(replacement,{adapter});t.after(()=>c.close());
  await assert.rejects(c.enroll(),/coordinator_missing_local_enrollment_history/);await assert.rejects(c.once(),/coordinator_missing_local_enrollment_history/);
});

test('close stops admission and awaits the original operation before releasing SQLite/journal',async t=>{
  const root=makeRoot(t),ready=await initialized(root),c=ready.c;
  const originalRead=c.adapter.read.bind(c.adapter);let release,observed;
  const observedPromise=new Promise(resolve=>observed=resolve),held=new Promise(resolve=>release=resolve);
  c.adapter.read=async(key,...rest)=>{if(key==='transport-v1/control'){observed();await held;}return originalRead(key,...rest);};
  const operation=c.once();await observedPromise;let closed=false;
  const closing=c.close().then(value=>{closed=true;return value;});
  await assert.rejects(c.once(),/coordinator_closed/);assert.equal(closed,false);
  release();assert.equal((await operation).ok,true);assert.equal((await closing).closed,true);assert.equal(closed,true);
});
