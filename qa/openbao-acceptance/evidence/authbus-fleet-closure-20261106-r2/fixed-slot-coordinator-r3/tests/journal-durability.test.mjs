import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { PrivateJournal } from '../private-journal.mjs';
import { makeRoot, initialized, event, grant } from './fixture.mjs';

const sameInode=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const injected=()=>Object.assign(new Error('synthetic_fsync_failure'),{code:'EIO'});

test('failed parent, intent-file or intent-directory fsync is re-proved before exactly one original dispatch',async t=>{
  const nativeSync=fs.fsyncSync;
  // The directory exists after failed publication, but neither EEXIST nor an
  // unchanged name can stand in for synchronizing its original parent.
  const parentRoot=makeRoot(t),parent=fs.lstatSync(parentRoot);let parentFailures=0;
  try{
    fs.fsyncSync=function(fd){if(sameInode(fs.fstatSync(fd),parent)){parentFailures++;throw injected();}return nativeSync.call(fs,fd);};
    assert.throws(()=>new PrivateJournal(parentRoot),error=>error.code==='EIO');
    assert.equal(fs.statSync(path.join(parentRoot,'operations')).isDirectory(),true);
    assert.throws(()=>new PrivateJournal(parentRoot),error=>error.code==='EIO');
    assert.equal(parentFailures,2);
  }finally{fs.fsyncSync=nativeSync;}
  const reopened=new PrivateJournal(parentRoot);reopened.close();

  for(const mode of ['file','directory']){
    const root=makeRoot(t);let enabled=false,armed=false,target,coordinator;
    const ready=await initialized(root,{phaseHook:async(phase)=>{
      if(enabled&&phase==='operation-prepared'){
        target=path.join(root,'operations',coordinator.store.get('active').value.id+'.step-0000.intent.json');armed=true;
      }
    }});coordinator=ready.c;t.after(()=>coordinator.close());
    const operations=fs.lstatSync(path.join(root,'operations'));let failures=0;
    const writes=ready.adapter.load().writes.length;enabled=true;
    try{
      fs.fsyncSync=function(fd){const held=fs.fstatSync(fd);
        const matches=armed&&(mode==='directory'?sameInode(held,operations):fs.existsSync(target)&&sameInode(held,fs.lstatSync(target)));
        if(matches){failures++;throw injected();}return nativeSync.call(fs,fd);};
      await assert.rejects(coordinator.authorize(grant(event(2),ready.first)),error=>error.code==='EIO');
      const active=structuredClone(coordinator.store.get('active').value);
      assert.equal(active.phase,'ready');assert.equal(fs.statSync(target).size>0,true);
      assert.equal(ready.adapter.load().writes.length,writes);
      await assert.rejects(coordinator.recover(),error=>error.code==='EIO');
      assert.deepEqual(coordinator.store.get('active').value,active);
      assert.equal(ready.adapter.load().writes.length,writes);assert.equal(failures,2);
    }finally{armed=false;fs.fsyncSync=nativeSync;}
    assert.equal((await coordinator.recover()).completed,true);
    assert.equal(ready.adapter.load().writes.length,writes+1);
    assert.equal(coordinator.store.get('active').value,null);
    const before=ready.adapter.load().writes.length;await coordinator.recover();
    assert.equal(ready.adapter.load().writes.length,before);
  }
});
