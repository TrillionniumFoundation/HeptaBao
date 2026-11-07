import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { credentialTransition,receiptKey,parseEvent,credentialIdentity } from '../protocol.mjs';
test('exact original Python grant/profile/manifest/receipt contract matches new transaction planning',()=>{
  const child=spawnSync('python3',['-I','-B',fileURLToPath(new URL('./legacy-oracle.py',import.meta.url))],{encoding:'utf8',timeout:5000,maxBuffer:65536});
  assert.equal(child.status,0,child.stderr);assert.equal(child.signal,null);assert.equal(child.stderr,'');
  const oracle=JSON.parse(child.stdout),owner=oracle.before.data.coordinator.ownerId;
  const next=credentialTransition(oracle.before,oracle.event,owner,['fixture-host']);
  assert.deepEqual(next.manifest,oracle.after.manifest.data);
  assert.deepEqual(next.profile,oracle.after[next.profileKey].data);
  assert.deepEqual(next.receipt,oracle.after[next.receiptKey].data);
  assert.equal(next.receiptKey,receiptKey(oracle.event.sourceHost,oracle.event.eventId));
  assert.equal(credentialIdentity(oracle.event.credential),oracle.event.identity);
  const revoked=structuredClone(oracle.before);revoked.data.coordinator.authorizations=[];
  assert.throws(()=>credentialTransition(revoked,oracle.event,owner,['fixture-host']),/credential_transition_not_authorized/);
  for(const field of ['provider','identityDigest','nextDigest','expectedCurrentDigest']){
    const wrong=structuredClone(oracle.before);wrong.data.coordinator.authorizations[0][field]=field==='provider'?'other-provider':'f'.repeat(64);
    assert.throws(()=>credentialTransition(wrong,oracle.event,owner,['fixture-host']),/credential_transition_not_authorized|authorized_transition_source_changed/);
  }
});
