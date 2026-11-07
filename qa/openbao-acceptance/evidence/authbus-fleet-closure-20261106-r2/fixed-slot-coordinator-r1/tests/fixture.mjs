import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { after } from 'node:test';
import { PrivateOutboxStore } from '../transport/private-outbox-store.js';
import { PrivateJournal } from '../private-journal.mjs';
import { FixedSlotCoordinator, deploymentBinding } from '../coordinator.mjs';
import { clone, digest, credentialIdentity, sourceFor, TRANSPORT, hashText } from '../protocol.mjs';

export const owner='11111111-1111-4111-8111-111111111111';
export const epoch='22222222-2222-4222-8222-222222222222';
export function configuration(stateDir){return {schema:'heptabao.fixed-slot-coordinator.r1.config',stateDir,ownerId:owner,
  topology:[{host_id:'fixture-host',epoch,slots:1,agents:['main']}],bootstrapProfileCount:1,
  address:'https://127.0.0.1:9443',serverCertificateSha256:'a'.repeat(64),implementationSha256:'b'.repeat(64),
  operationMs:30000,scanLimit:32,pollMs:250};}
const roots=[];
after(()=>{for(const root of roots)fs.rmSync(root,{recursive:true,force:true});});
export function makeRoot(_t){const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'heptabao-coordinator-'));fs.chmodSync(root,0o700);
  roots.push(root);return root;}
export function event(number,reason='leader-refresh'){
  const credential={provider:'openai',type:'oauth',access:'synthetic-access-'+number,refresh:'synthetic-refresh-'+number,expires:2000000000000+number,accountId:'synthetic-account'};
  return {schemaVersion:1,eventId:`33333333-3333-4333-8333-${String(number).padStart(12,'0')}`,sourceHost:'fixture-host',
    reason,profileId:'synthetic-profile',credential,digest:digest(credential),identity:credentialIdentity(credential)};}
export function grant(next,previous=null){return {authorizationId:crypto.randomUUID(),profileId:next.profileId,sourceHost:next.sourceHost,
  provider:next.credential.provider,identityDigest:next.identity,expectedCurrentDigest:previous?.digest??null,nextDigest:next.digest};}

/** Synthetic durable remote state, deliberately not a Bao/HTTP implementation. */
export class FileKv {
  constructor(filename){this.filename=filename;this.fault=null;this.counts={reads:0,historyReads:0,writeDispatches:0,writeResponses:0};
    if(!fs.existsSync(filename))this.save({schema:'synthetic-file-kv.r1',records:{},writes:[]});}
  load(){return JSON.parse(fs.readFileSync(this.filename,'utf8'));}
  save(value){const next=this.filename+'.tmp';const fd=fs.openSync(next,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    try{fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(next,this.filename);
    const dir=fs.openSync(path.dirname(this.filename),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
  async maintain(){}
  async read(key){this.counts.reads++;const rows=this.load().records[key];return rows?.length?clone(rows.at(-1)):null;}
  async history(key,version){this.counts.historyReads++;return clone(this.load().records[key]?.find(r=>r.version===version)??null);}
  async retention(){return true;}
  async write(key,data,cas){this.counts.writeDispatches++;const state=this.load(),rows=state.records[key]??[];
    const fault=this.fault?.key===key?this.fault:null;if(fault)this.fault=null;
    if(fault?.mode==='before'){state.writes.push({key,cas,committed:false});this.save(state);throw Object.assign(new Error('synthetic_unknown'),{unknown:true});}
    if((rows.at(-1)?.version??0)!==cas)throw Object.assign(new Error('synthetic_conflict'),{unknown:false,conflict:true,status:400});
    const version=cas+1;rows.push({version,data:clone(data)});state.records[key]=rows.slice(-2);
    state.writes.push({key,cas,committed:true});this.save(state);
    if(fault?.mode==='after')throw Object.assign(new Error('synthetic_unknown'),{unknown:true});
    this.counts.writeResponses++;return version;}
  async close(){return {closed:true,revoked:false,syntheticRemote:true};}
}
export function openFixture(root,{adapter,phaseHook,config}={}){
  config??=configuration(root);adapter??=new FileKv(path.join(root,'remote.private.json'));
  const store=new PrivateOutboxStore(path.join(root,'journal-store'),deploymentBinding(config));const journal=new PrivateJournal(root);
  return new FixedSlotCoordinator(config,{store,journal,adapter,phaseHook});
}
export async function initialized(root,options={}){const c=openFixture(root,options),first=event(1,'new-profile');
  await c.initialize();await c.authorize(grant(first));await c.bootstrap(first);await c.enroll();return {c,first,adapter:c.adapter};}
export function producer(c,sourceStateDir){const source=sourceFor(c.topology[0],c.owner);return {source,sourceStateDir};}
