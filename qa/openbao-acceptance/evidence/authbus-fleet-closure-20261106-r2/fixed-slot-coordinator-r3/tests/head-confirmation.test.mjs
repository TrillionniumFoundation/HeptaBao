import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { BoundedOutbox, normalizeTransport } from '../transport/bounded-outbox.js';
import { PrivateOutboxStore } from '../transport/private-outbox-store.js';
import { digest, sourceFor, slotKey, receiptKey, TRANSPORT } from '../protocol.mjs';
import { makeRoot, initialized, openFixture, event, grant, FileKv } from './fixture.mjs';

function producer(root,c){const directory=path.join(root,'producer');fs.mkdirSync(directory,{mode:0o700});
  const store=new PrivateOutboxStore(path.join(directory,'outbox'),{schema:'synthetic-producer-state'});
  const config=normalizeTransport({schema:TRANSPORT,production:true,epoch:c.topology[0].epoch,slots:1,agents:['main'],
    controlDigest:digest(c.control),serverCertificateSha256:'a'.repeat(64)},'fixture-host');
  return {store,outbox:new BoundedOutbox({readSecret:key=>c.adapter.read(key),writeSecret:(key,data,cas)=>c.adapter.write(key,data,cas)},store,config)};}

test('modified immutable profile, receipt and control heads cannot hide behind correct version-one history',async t=>{
  for(const role of ['profile','receipt','control']){
    const root=makeRoot(t);let c,adapter,key;
    if(role==='control'){
      c=openFixture(root);adapter=c.adapter;const first=event(1,'new-profile');
      await c.initialize();await c.authorize(grant(first));await c.bootstrap(first);
      key='transport-v1/control';adapter.fault={key,mode:'after'};
      await assert.rejects(c.enroll(),error=>error.unknown===true);
    }else{
      const ready=await initialized(root);({c,adapter}=ready);const p=producer(root,c);t.after(()=>p.store.close());
      const next=event(2);await c.authorize(grant(next,ready.first));await p.outbox.publish(next);
      const profile={schemaVersion:1,profileId:next.profileId,credential:next.credential,digest:next.digest,identity:next.identity};
      key=role==='profile'?'profiles/sha256-'+digest(profile):receiptKey(next.sourceHost,next.eventId);
      adapter.fault={key,mode:'after'};await assert.rejects(c.once(),error=>error.unknown===true);
    }
    const target=await adapter.read(key),originalActive=structuredClone(c.store.get('active').value);
    assert.equal(target.version,1);await adapter.write(key,{syntheticForeignOverwrite:true},1);
    assert.deepEqual(await adapter.history(key,1),target);
    const writes=adapter.load().writes.length;await c.close();
    const cold=openFixture(root,{adapter:new FileKv(adapter.filename)});t.after(()=>cold.close());
    await assert.rejects(cold.recover(),error=>error.unknown===true);
    assert.equal(cold.adapter.counts.historyReads,0);
    assert.equal(cold.adapter.load().writes.length,writes);
    assert.deepEqual(cold.store.get('active').value,originalActive);
  }
});

test('too-far manifest, ack or producer-slot heads refuse even when original target history remains available',async t=>{
  for(const role of ['manifest','ack','producer-slot']){
    const root=makeRoot(t);let {c,first,adapter}=await initialized(root);const p=producer(root,c);t.after(()=>p.store.close());
    const next=event(2);await c.authorize(grant(next,first));await p.outbox.publish(next);
    const source=sourceFor(c.topology[0],c.owner),ackKey=slotKey(source,0,'ack'),slot=slotKey(source,0);
    const key=role==='manifest'?'manifest':ackKey;
    adapter.fault={key,mode:'after'};await assert.rejects(c.once(),error=>error.unknown===true);
    const target=await adapter.read(key),originalActive=structuredClone(c.store.get('active').value),state=adapter.load();
    if(role==='producer-slot'){
      const original=state.records[slot].at(-1),changed=structuredClone(original.data);changed.sequence+=2;
      state.records[slot]=[original,{version:original.version+2,data:changed}];
    }else{
      const changed=structuredClone(target.data);
      if(role==='manifest')changed.coordinator.authorizations.push(grant(event(3),next));
      else{changed.sequence+=2;changed.slotVersion+=2;}
      // Deliberately corrupt the synthetic peer's retention metadata: a correct
      // historical target must not rescue an inadmissibly distant current head.
      state.records[key]=[target,{version:target.version+2,data:changed}];
    }
    adapter.save(state);assert.deepEqual(await adapter.history(key,target.version),target);
    const writes=adapter.load().writes.length;await c.close();
    const cold=openFixture(root,{adapter:new FileKv(adapter.filename)});t.after(()=>cold.close());
    await assert.rejects(cold.recover(),error=>error.unknown===true);
    assert.equal(cold.adapter.counts.historyReads,0);
    assert.equal(cold.adapter.load().writes.length,writes);
    assert.deepEqual(cold.store.get('active').value,originalActive);
  }
});
