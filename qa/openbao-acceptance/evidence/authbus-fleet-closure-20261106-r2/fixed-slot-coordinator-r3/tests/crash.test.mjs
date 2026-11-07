import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { BoundedOutbox,normalizeTransport } from '../transport/bounded-outbox.js';
import { PrivateOutboxStore } from '../transport/private-outbox-store.js';
import { digest,TRANSPORT,slotKey,sourceFor,validatePair } from '../protocol.mjs';
import { makeRoot,initialized,grant,event,openFixture,FileKv } from './fixture.mjs';

for(const phase of ['durable-dispatched','remote-confirmed-before-receipt']){
  test('real owned SIGKILL '+phase+' preserves ack custody and releases SQLite process lock',{timeout:15000},async t=>{
    const root=makeRoot(t);let {c,first,adapter}=await initialized(root);
    const parent=path.join(root,'producer');fs.mkdirSync(parent,{mode:0o700});
    const store=new PrivateOutboxStore(path.join(parent,'outbox'),{fixture:true});
    try{
      const source=normalizeTransport({schema:TRANSPORT,production:true,epoch:c.topology[0].epoch,slots:1,agents:['main'],controlDigest:digest(c.control),serverCertificateSha256:'a'.repeat(64)},'fixture-host');
      const outbox=new BoundedOutbox({readSecret:k=>adapter.read(k),writeSecret:(k,d,v)=>adapter.write(k,d,v)},store,source);
      const next=event(2);await c.authorize(grant(next,first));await outbox.publish(next);
    }finally{store.close();}
    await c.close();
    const child=fork(fileURLToPath(new URL('./crash-child.mjs',import.meta.url)),[root,phase],{execArgv:[],stdio:['ignore','pipe','pipe','ipc'],detached:true});
    let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
    const closed=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
    const timer=setTimeout(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');},10000);
    try{
      const message=await Promise.race([new Promise(resolve=>child.once('message',resolve)),closed.then(value=>({closed:value}))]);
      assert.deepEqual(message,{phase,role:'ack',waitingForOwnedParent:true},stderr);
      assert.equal(child.kill('SIGKILL'),true);assert.deepEqual(await closed,{code:null,signal:'SIGKILL'});
      assert.throws(()=>process.kill(-child.pid,0),e=>e.code==='ESRCH');assert.equal(stdout,'');assert.equal(stderr,'');
    }finally{clearTimeout(timer);if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await closed;}
    const key=slotKey(sourceFor(c.topology[0],c.owner),0,'ack'),before=adapter.load().writes.filter(x=>x.key===key).length;
    c=openFixture(root,{adapter:new FileKv(adapter.filename)});
    try{
      if(phase==='durable-dispatched')await assert.rejects(c.recover(),e=>e.unknown===true);
      else{await c.recover();const source=sourceFor(c.topology[0],c.owner);assert.equal(validatePair(source,0,await c.adapter.read(slotKey(source,0)),await c.adapter.read(key)),true);}
      assert.equal(c.adapter.load().writes.filter(x=>x.key===key).length,before);
    }finally{await c.close();}
  });
}
