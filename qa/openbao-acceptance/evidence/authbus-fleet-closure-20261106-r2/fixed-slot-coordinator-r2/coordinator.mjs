import path from 'node:path';
import { StrictBaoClient } from './transport/strict-bao-client.js';
import { PrivateOutboxStore } from './transport/private-outbox-store.js';
import { PrivateJournal } from './private-journal.mjs';
import { verifyImplementation } from './source-verification.mjs';
import { TRANSPORT, PROTOCOL, stable, digest, hashText, initialSlot, initialAck, slotKey, reportKey, validatePair,
  CoordinatorError, need, object, integer, exact, clone, equal, SHA, UUID, normalizeTopology, controlDocument,
  sourceFor, validateManifest, validateGrant, parseEvent, expectedProfile, validateReceipt, receiptKey,
  credentialTransition, acknowledgement, reportDocument } from './protocol.mjs';

const SCHEMA='heptabao.fixed-slot-coordinator.r1';
const MOUNT='openclaw-auth';
function options(deadlineMs){need(Number.isSafeInteger(deadlineMs)&&Date.now()<deadlineMs,'coordinator_operation_deadline');return {deadlineMs};}
function safeKey(key){need(typeof key==='string'&&key.length<=4096&&key.split('/').every(p=>p&&p!=='.'&&p!=='..')&&!/[\x00-\x1f\x7f]/.test(key),'coordinator_key_shape');return key.split('/').map(encodeURIComponent).join('/');}
function snapshot(value){need(value===null||object(value)&&integer(value.version)&&value.version>=1&&object(value.data),'coordinator_kv_snapshot_shape');return value;}

/** Concrete adapter: unchanged strict TLS/AppRole implementation; no fetch or fallback HTTP. */
export class StrictKvAdapter {
  constructor(client,store){this.client=client;this.store=store;this.counts={reads:0,historyReads:0,writeDispatches:0,writeResponses:0};}
  async maintain(deadlineMs){const state=this.store.loadAuth().value;if(state?.phase!=='active')return;
    need(Number.isSafeInteger(state.expiresAtUnixMs),'coordinator_bearer_expiry_shape');const left=state.expiresAtUnixMs-Date.now();
    if(left<=0)await this.client.login(options(deadlineMs));
    else if(left<=60000){need(state.renewable===true,'coordinator_bearer_not_renewable');await this.client.renew(options(deadlineMs));}}
  async read(key,deadlineMs){this.counts.reads++;return snapshot(await this.client.readSecret(key,options(deadlineMs)));}
  async history(key,version,deadlineMs){need(integer(version)&&version>0,'coordinator_history_version');this.counts.historyReads++;
    const body=await this.client.request('GET',`/v1/${MOUNT}/data/${safeKey(key)}?version=${version}`,undefined,undefined,options(deadlineMs));
    if(body===null)return null;need(object(body?.data?.data)&&body.data.metadata?.version===version,'coordinator_history_response');
    return {data:body.data.data,version};}
  async write(key,data,cas,deadlineMs){this.counts.writeDispatches++;const version=await this.client.writeSecret(key,data,cas,options(deadlineMs));this.counts.writeResponses++;return version;}
  async retention(key,deadlineMs){this.counts.reads++;
    const mount=await this.client.request('GET',`/v1/${MOUNT}/config`,undefined,undefined,options(deadlineMs));
    need(object(mount?.data)&&mount.data.max_versions===2&&mount.data.cas_required===true,'coordinator_mount_retention_and_cas_required');
    this.counts.reads++;const metadata=await this.client.request('GET',`/v1/${MOUNT}/metadata/${safeKey(key)}`,undefined,undefined,options(deadlineMs));
    need(object(metadata?.data)&&[0,2].includes(metadata.data.max_versions)
      &&typeof metadata.data.cas_required==='boolean'&&integer(metadata.data.current_version)&&metadata.data.current_version>=1,
      'coordinator_key_retention_metadata');return true;}
  async close({revoke=false,deadlineMs}={}){return this.client.close({revoke,deadlineMs});}
}

export function deploymentBinding(config){const control=controlDocument(config);
  need(config.schema===SCHEMA+'.config'&&typeof config.address==='string'&&typeof config.stateDir==='string'
    &&path.isAbsolute(config.stateDir)&&path.resolve(config.stateDir)===config.stateDir
    &&typeof config.serverCertificateSha256==='string'&&SHA.test(config.serverCertificateSha256)
    &&typeof config.implementationSha256==='string'&&SHA.test(config.implementationSha256),'coordinator_deployment_configuration');
  need(config.operationMs===30000&&Number.isInteger(config.scanLimit)&&config.scanLimit>=1&&config.scanLimit<=32
    &&Number.isInteger(config.pollMs)&&config.pollMs>=250&&config.pollMs<=60000,'coordinator_bounded_configuration');
  return stable({schema:SCHEMA+'.local-binding',address:config.address,stateDir:config.stateDir,
    implementationSha256:config.implementationSha256,serverCertificateSha256:config.serverCertificateSha256,control});
}

/** A real concrete coordinator. Test injection substitutes only the remote KV,
 * while the same private SQLite lock/journal and transaction engine still run. */
export class FixedSlotCoordinator {
  constructor(config,{store,journal,adapter,phaseHook=async()=>{}}){
    this.config=clone(config);this.binding=deploymentBinding(config);this.control=this.binding.control;
    this.owner=config.ownerId;this.topology=this.control.topology;this.hosts=this.topology.map(x=>x.host_id);
    this.store=store;this.journal=journal;this.adapter=adapter;this.phaseHook=phaseHook;this.closed=false;this.closing=false;this.inFlight=null;
    this.slots=this.topology.flatMap(row=>Array.from({length:row.slots},(_,index)=>({source:sourceFor(row,this.owner),index})));
  }
  deadline(options_={}){need(!this.closed&&!this.closing,'coordinator_closed');const deadlineMs=options_.deadlineMs??Date.now()+30000;
    need(Number.isSafeInteger(deadlineMs)&&deadlineMs<=Date.now()+30000,'coordinator_original_operation_budget');return options(deadlineMs).deadlineMs;}
  async locked(fn,options_={}){const until=this.deadline(options_);need(this.inFlight===null,'coordinator_in_process_operation_busy');
    const original=this.store.withLock(async()=>{options(until);this.store.assertCustody();this.journal.assertCustody();await this.adapter.maintain(until);return fn(until);});
    this.inFlight=original;try{return await original;}finally{if(this.inFlight===original)this.inFlight=null;}}
  async manifest(until){const current=await this.adapter.read('manifest',until);need(current,'coordinator_not_initialized');validateManifest(current.data,this.owner,this.hosts);return current;}
  async admitted(until){const marker=this.store.get('enrollment');need(marker?.value?.controlDigest===digest(this.control),'coordinator_missing_local_enrollment_history');
    const remote=await this.adapter.read('transport-v1/control',until);need(remote?.version===1&&equal(remote.data,this.control),'coordinator_control_binding');
    const canonical=await this.manifest(until);need(canonical.data.profiles.length>=1,'coordinator_empty_production_manifest');return canonical;}
  #step(key,expected,desired,role,guard=null){snapshot(expected);need(object(desired),'coordinator_desired_document');
    return {type:'write',key,expected:clone(expected),desired:clone(desired),role,guard:clone(guard)};}
  #plan(kind,context,steps){need(Array.isArray(steps)&&steps.length<=4096,'coordinator_plan_step_bound');
    return stable({schema:SCHEMA+'.operation',bindingDigest:digest(this.binding),kind,context:clone(context),steps});}
  #validatePlan(plan){need(exact(plan,['schema','bindingDigest','kind','context','steps'])&&plan.schema===SCHEMA+'.operation'
    &&plan.bindingDigest===digest(this.binding)&&['initialize','authorize','revoke-authorization','bootstrap','enroll','slot'].includes(plan.kind)
    &&object(plan.context)&&Array.isArray(plan.steps)&&plan.steps.length<=4096,'coordinator_operation_binding');
    for(const step of plan.steps){need(object(step)&&['write','retention'].includes(step.type),'coordinator_step_shape');safeKey(step.key);
      if(step.type==='write'){need(exact(step,['type','key','expected','desired','role','guard'])&&object(step.desired)
        &&['manifest','profile','receipt','ack','enrollment'].includes(step.role),'coordinator_write_step_shape');snapshot(step.expected);
        if(step.guard!==null){need(exact(step.guard,['key','expected']),'coordinator_slot_guard_shape');safeKey(step.guard.key);snapshot(step.guard.expected);}}
      else need(exact(step,['type','key']),'coordinator_retention_step_shape');}
    return plan;}
  async #confirm(step,until){const targetVersion=(step.expected?.version??0)+1;
    const head=await this.adapter.read(step.key,until);let retainedHistoryUsed=false,slotHeadVersion=null;
    const unresolved=()=>{throw new CoordinatorError('coordinator_original_effect_unresolved',{unknown:true});};
    const exactHead=head?.version===targetVersion&&equal(head.data,step.desired);
    if(['profile','receipt','enrollment'].includes(step.role)){
      // Immutable profiles/receipts/control and pre-control enrollment writes
      // cannot be confirmed by an older version beneath a modified head.
      if(!(step.expected===null&&targetVersion===1&&exactHead))unresolved();
    }else if(step.role==='manifest'){
      // An operator may have published one further authorization update. The
      // fixed two-version contract can prove only this exact retained target.
      if(!head||![targetVersion,targetVersion+1].includes(head.version))unresolved();
      try{validateManifest(head.data,this.owner,this.hosts);}catch{unresolved();}
      if(head.version===targetVersion){if(!exactHead)unresolved();}
      else{const original=await this.adapter.history(step.key,targetVersion,until);
        if(!(original?.version===targetVersion&&equal(original.data,step.desired)))unresolved();
        retainedHistoryUsed=true;}
    }else if(step.role==='ack'){
      // The producer never writes ack. It can only reuse the acknowledged slot
      // once; a later ack or a two-generation slot leap is not our confirmation.
      if(!exactHead||step.guard===null||!step.guard.expected)unresolved();
      const originalSlot=step.guard.expected,data=originalSlot.data;
      const topology=this.topology.find(row=>row.host_id===data?.sourceHost&&row.epoch===data?.epoch);
      if(!topology||!integer(data.slot)||data.slot>=topology.slots)unresolved();
      const source=sourceFor(topology,this.owner);
      if(step.guard.key!==slotKey(source,data.slot)||step.key!==slotKey(source,data.slot,'ack'))unresolved();
      const slot=await this.adapter.read(step.guard.key,until);
      if(!slot||![originalSlot.version,originalSlot.version+1].includes(slot.version))unresolved();
      try{validatePair(source,data.slot,originalSlot,head);validatePair(source,data.slot,slot,head);}catch{unresolved();}
      slotHeadVersion=slot.version;
    }else unresolved();
    return {version:targetVersion,observedHeadVersion:head.version,retainedHistoryUsed,
      originalTargetDigest:digest(step.desired),slotHeadVersion};}
  async #guard(step,until){if(step.guard!==null){const value=await this.adapter.read(step.guard.key,until);need(equal(value,step.guard.expected),'coordinator_slot_changed_before_dispatch');}
    const current=await this.adapter.read(step.key,until);need(equal(current,step.expected),'coordinator_preimage_changed_before_dispatch');}
  async #complete(active,plan){const done={schema:SCHEMA+'.completed',operationDigest:active.id,kind:plan.kind,stepCount:plan.steps.length,allStepsConfirmed:true};
    this.journal.writeOnce(active.id+'.completed.json',done);
    if(plan.kind==='enroll')this.store.put('enrollment',{controlDigest:digest(this.control),operationDigest:active.id});
    this.store.put('active',null);return {ok:true,completed:true,kind:plan.kind,confirmedSteps:plan.steps.length};}
  async #runActive(until){const row=this.store.get('active');if(!row?.value)return {ok:true,recovered:false};
    let active=row.value;need(exact(active,['id','step','phase'])&&SHA.test(active.id)&&integer(active.step)
      &&['ready','dispatched','blocked'].includes(active.phase),'coordinator_active_journal_shape');
    const plan=this.#validatePlan(this.journal.read(active.id+'.json'));need(digest(plan)===active.id&&active.step<=plan.steps.length,'coordinator_original_plan_digest');
    if(active.phase==='blocked')throw new CoordinatorError('coordinator_known_request_rejection_requires_review');
    while(active.step<plan.steps.length){options(until);const index=active.step,step=plan.steps[index];
      const base=active.id+'.step-'+String(index).padStart(4,'0');
      if(step.type==='retention'){
        need(active.phase==='ready','coordinator_retention_not_mutator');await this.adapter.retention(step.key,until);
        this.journal.writeOnce(base+'.confirmed.json',{schema:SCHEMA+'.retention-confirmed',operationDigest:active.id,index,key:step.key,twoRetainedVersions:true,casRequired:true});
      }else{
        const intent={schema:SCHEMA+'.request-intent',operationDigest:active.id,index,step};
        if(active.phase==='ready'){
          need(this.journal.read(base+'.response.json')===null,'coordinator_ready_response_collision');
          await this.#guard(step,until);options(until);this.journal.writeOnce(base+'.intent.json',intent);
          active={id:active.id,step:index,phase:'dispatched'};this.store.put('active',active);this.store.assertCustody();this.journal.assertCustody();
          await this.phaseHook('durable-dispatched',{kind:plan.kind,role:step.role,index});
          let version;
          try{options(until);version=await this.adapter.write(step.key,step.desired,step.expected?.version??0,until);}
          catch(error){if(error?.conflict===true||error?.unknown===false&&Number.isInteger(error?.status)&&error.status>=400&&error.status<500){
              this.journal.writeOnce(base+'.response.json',{schema:SCHEMA+'.response',operationDigest:active.id,index,knownRejection:true,conflict:error.conflict===true,status:error.status});
              this.store.put('active',{...active,phase:'blocked'});
              throw new CoordinatorError('coordinator_known_request_rejection_requires_review');}
            throw new CoordinatorError('coordinator_mutation_outcome_unknown',{unknown:true});}
          need(version===(step.expected?.version??0)+1,'coordinator_write_response_version');
          await this.phaseHook('remote-confirmed-before-receipt',{kind:plan.kind,role:step.role,index});
          this.journal.writeOnce(base+'.response.json',{schema:SCHEMA+'.response',operationDigest:active.id,index,knownRejection:false,version});
        }else{
          need(equal(this.journal.read(base+'.intent.json'),intent),'coordinator_original_dispatched_intent');
          const response=this.journal.read(base+'.response.json');
          if(response?.knownRejection===true){this.store.put('active',{...active,phase:'blocked'});throw new CoordinatorError('coordinator_known_request_rejection_requires_review');}
          if(response!==null)need(response.operationDigest===active.id&&response.index===index&&response.knownRejection===false
            &&response.version===(step.expected?.version??0)+1,'coordinator_original_response_binding');
        }
        const confirmation=await this.#confirm(step,until);
        this.journal.writeOnce(base+'.confirmed.json',{schema:SCHEMA+'.effect-confirmed',operationDigest:active.id,index,
          ...confirmation,desiredDigest:digest(step.desired)});
      }
      active={id:active.id,step:index+1,phase:'ready'};this.store.put('active',active);
      await this.phaseHook('step-confirmed',{kind:plan.kind,role:step.role??'retention',index});
    }
    options(until);return this.#complete(active,plan);
  }
  async #start(plan,until){need(!this.store.get('active')?.value,'coordinator_previous_operation_pending');this.#validatePlan(plan);
    const id=digest(plan);const completed=this.journal.read(id+'.completed.json');
    if(completed!==null){need(completed.operationDigest===id&&completed.allStepsConfirmed===true,'coordinator_completed_record_binding');
      for(const step of plan.steps){if(step.type==='write')await this.#confirm(step,until);else await this.adapter.retention(step.key,until);}
      return {ok:true,completed:true,alreadyCompleted:true,kind:plan.kind,confirmedSteps:plan.steps.length};}
    this.journal.writeOnce(id+'.json',plan);this.store.put('active',{id,step:0,phase:'ready'});
    await this.phaseHook('operation-prepared',{kind:plan.kind});return this.#runActive(until);
  }
  async #recoverBefore(until){return this.#runActive(until);}
  recover(options_={}){return this.locked(until=>this.#runActive(until),options_);}
  initialize(options_={}){return this.locked(async until=>{await this.#recoverBefore(until);const current=await this.adapter.read('manifest',until);
    if(current){validateManifest(current.data,this.owner,this.hosts);return {ok:true,alreadyInitialized:true,credentialProfiles:current.data.profiles.length};}
    need(await this.adapter.read('transport-v1/control',until)===null,'coordinator_control_without_manifest');
    const value={schemaVersion:1,generation:0,profiles:[],coordinator:{protocol:PROTOCOL,ownerId:this.owner,authorizations:[],lastReceipt:null}};
    return this.#start(this.#plan('initialize',{},[this.#step('manifest',null,value,'manifest')]),until);},options_);}
  authorize(grant,options_={}){validateGrant(grant,this.hosts);return this.locked(async until=>{await this.#recoverBefore(until);const current=await this.manifest(until),value=clone(current.data);
    need((value.profiles.find(p=>p.profileId===grant.profileId)?.digest??null)===grant.expectedCurrentDigest,'operator_expected_current_digest_mismatch');
    if(value.coordinator.authorizations.some(g=>equal(g,grant)))return {ok:true,alreadyAuthorized:true};
    need(value.coordinator.authorizations.length<32&&value.coordinator.authorizations.every(g=>g.profileId!==grant.profileId&&g.authorizationId!==grant.authorizationId),'operator_authorization_already_pending');
    value.coordinator.authorizations.push(clone(grant));validateManifest(value,this.owner,this.hosts);
    return this.#start(this.#plan('authorize',{authorizationId:grant.authorizationId},[this.#step('manifest',current,value,'manifest')]),until);},options_);}
  revokeAuthorization(id,options_={}){need(typeof id==='string'&&UUID.test(id),'operator_authorization_id_shape');return this.locked(async until=>{await this.#recoverBefore(until);
    const current=await this.manifest(until),value=clone(current.data),old=value.coordinator.authorizations;
    value.coordinator.authorizations=old.filter(g=>g.authorizationId!==id);
    if(value.coordinator.authorizations.length===old.length)return {ok:true,authorizationPending:false};
    return this.#start(this.#plan('revoke-authorization',{authorizationId:id},[this.#step('manifest',current,value,'manifest')]),until);},options_);}
  async #immutableStep(key,value,role,until,guard=null){const current=await this.adapter.read(key,until);
    if(current!==null){need(current.version===1&&equal(current.data,value),'coordinator_immutable_collision');return [];}
    return [this.#step(key,null,value,role,guard)];}
  async #credentialSteps(event,until,guard=null){const parsed=parseEvent(event.sourceHost,event.eventId,event);need(parsed.kind==='credential','coordinator_expected_credential_event');
    const key=receiptKey(event.sourceHost,event.eventId),existing=await this.adapter.read(key,until);
    if(existing!==null){need(existing.version===1,'coordinator_receipt_immutable_version');validateReceipt(existing.data,this.owner,event,parsed);
      return {steps:[],receipt:existing.data,alreadyCanonical:true};}
    const current=await this.manifest(until);const transition=credentialTransition(current,event,this.owner,this.hosts);
    const steps=await this.#immutableStep(transition.profileKey,transition.profile,'profile',until,guard);
    steps.push(this.#step('manifest',current,transition.manifest,'manifest',guard));
    steps.push(...await this.#immutableStep(transition.receiptKey,transition.receipt,'receipt',until,guard));
    return {steps,receipt:transition.receipt,alreadyCanonical:false};}
  bootstrap(event,options_={}){need(this.hosts.includes(event?.sourceHost),'coordinator_bootstrap_source');return this.locked(async until=>{await this.#recoverBefore(until);
    need(await this.adapter.read('transport-v1/control',until)===null,'coordinator_bootstrap_after_enrollment_refused');
    const prepared=await this.#credentialSteps(event,until);if(!prepared.steps.length)return {ok:true,alreadyCanonical:true};
    return this.#start(this.#plan('bootstrap',{sourceHost:event.sourceHost,eventId:event.eventId,eventDigest:digest(event)},prepared.steps),until);},options_);}
  enroll(options_={}){return this.locked(async until=>{await this.#recoverBefore(until);const existing=await this.adapter.read('transport-v1/control',until);
    if(existing!==null){await this.admitted(until);return {ok:true,alreadyEnrolled:true};}
    const canonical=await this.manifest(until);need(canonical.data.profiles.length===this.config.bootstrapProfileCount,'coordinator_bootstrap_profile_count');
    const steps=[];const guard={key:'transport-v1/control',expected:null};
    for(const row of this.topology){const source=sourceFor(row,this.owner);
      for(let index=0;index<source.slots;index++)for(const [key,value] of [[slotKey(source,index),initialSlot(source,index)],[slotKey(source,index,'ack'),initialAck(source,index)]]){
        steps.push(...await this.#immutableStep(key,value,'enrollment',until,guard));steps.push({type:'retention',key});}
      for(const agent of source.agents){const key=reportKey(source,agent);steps.push(...await this.#immutableStep(key,reportDocument(source,agent),'enrollment',until,guard));steps.push({type:'retention',key});}}
    steps.push(this.#step('transport-v1/control',null,this.control,'enrollment'));
    return this.#start(this.#plan('enroll',{controlDigest:digest(this.control)},steps),until);},options_);}
  async #slot(source,index,until){const key=slotKey(source,index),ackKey=slotKey(source,index,'ack');
    const slot=await this.adapter.read(key,until),ack=await this.adapter.read(ackKey,until);
    if(validatePair(source,index,slot,ack))return {terminal:true};
    const event=slot.data.event,parsed=parseEvent(source.hostId,slot.data.eventId,event);
    need(parsed.kind!=='report','coordinator_report_in_slot_refused');const guard={key,expected:slot};let prepared;
    if(parsed.kind==='credential')prepared=await this.#credentialSteps(event,until,guard);
    else{const receipt={schema:PROTOCOL+'.health-receipt',ownerId:this.owner,status:'observed_health_no_scheduler_action',
      sourceHost:source.hostId,eventId:event.eventId,eventDigest:parsed.sha256};
      // Health only has an inline ack receipt. It neither creates unbounded
      // health receipt keys nor changes canonical credentials/scheduling.
      prepared={steps:[],receipt};}
    const desired=acknowledgement(source,index,slot,prepared.receipt);validatePair(source,index,slot,{data:desired,version:ack.version+1});
    prepared.steps.push(this.#step(ackKey,ack,desired,'ack',guard));
    const result=await this.#start(this.#plan('slot',{sourceHost:source.hostId,epoch:source.epoch,index,slot,eventDigest:parsed.sha256},prepared.steps),until);
    const afterSlot=await this.adapter.read(key,until),afterAck=await this.adapter.read(ackKey,until);
    // A concurrent producer may reuse a confirmed ack immediately. Both legal
    // terminal and exactly-one-pending states must still satisfy validatePair.
    validatePair(source,index,afterSlot,afterAck);
    return {terminal:false,processed:true,credential:parsed.kind==='credential',health:parsed.kind==='health',result};}
  once(options_={}){return this.locked(async until=>{const recovered=await this.#recoverBefore(until);await this.admitted(until);
    const out={ok:true,recoveredOperation:recovered.recovered!==false,scanned:0,terminalPairs:0,credentialAcknowledgements:0,
      healthAcknowledgements:0,deferredUnauthorized:0,reportsObserved:0,providerCalls:0,schedulerActions:0,legacyInboxTouched:false};
    const cursor=this.store.get('cursor')?.value??{slot:0,report:0};need(exact(cursor,['slot','report'])&&integer(cursor.slot)&&cursor.slot<this.slots.length&&integer(cursor.report),'coordinator_cursor_binding');
    for(let offset=0;offset<Math.min(this.config.scanLimit,this.slots.length);offset++){
      const position=(cursor.slot+offset)%this.slots.length,{source,index}=this.slots[position];
      let result;try{result=await this.#slot(source,index,until);}catch(error){if(['credential_transition_not_authorized','authorized_transition_source_changed'].includes(error.code)
        &&!this.store.get('active')?.value){out.deferredUnauthorized++;result=null;}else throw error;}
      out.scanned++;if(result?.terminal)out.terminalPairs++;if(result?.credential)out.credentialAcknowledgements++;if(result?.health)out.healthAcknowledgements++;
      this.store.put('cursor',{slot:(position+1)%this.slots.length,report:cursor.report});}
    const reports=this.topology.flatMap(row=>row.agents.map(agent=>({source:sourceFor(row,this.owner),agent})));
    need(cursor.report<reports.length,'coordinator_report_cursor_binding');
    for(let offset=0;offset<Math.min(this.config.scanLimit,reports.length);offset++){
      const position=(cursor.report+offset)%reports.length,{source,agent}=reports[position];
      const record=await this.adapter.read(reportKey(source,agent),until),data=record?.data;
      need(record&&exact(data,['schema','sourceHost','epoch','agentId','sequence','event'])&&data.schema===TRANSPORT+'.report'
        &&data.sourceHost===source.hostId&&data.epoch===source.epoch&&data.agentId===agent&&integer(data.sequence)&&record.version===data.sequence+1,'coordinator_report_binding');
      if(data.sequence===0)need(data.event===null,'coordinator_initial_report_changed');
      else{const parsed=parseEvent(source.hostId,data.event?.eventId,data.event);need(parsed.kind==='report'&&data.event.agentId===agent,'coordinator_report_event_scope');out.reportsObserved++;}
      this.store.put('cursor',{slot:this.store.get('cursor').value.slot,report:(position+1)%reports.length});}
    return out;},options_);}
  async close({revoke=false,deadlineMs}={}){if(this.closed)return {closed:true};need(!this.closing,'coordinator_close_already_pending');this.closing=true;
    // Stop admission and wait for the original operation, including its lock
    // finally, before closing any journal/SQLite resource. Never abort/retry it.
    if(this.inFlight)try{await this.inFlight;}catch{}
    let first,result;
    try{result=await this.store.withLock(()=>{need(!revoke||!this.store.get('active')?.value,'coordinator_revoke_with_pending_operation');return this.adapter.close({revoke,deadlineMs});});}catch(error){first=error;}
    try{this.journal.close();}catch(error){first??=error;}
    try{this.store.close();}catch(error){first??=error;}
    this.closed=true;if(first)throw first;return result;}
}

export function openCoordinator(config){const binding=deploymentBinding(config);verifyImplementation(config.implementationSha256);let store,journal;
  try{store=new PrivateOutboxStore(path.join(config.stateDir,'journal-store'),binding);journal=new PrivateJournal(config.stateDir);
    const client=new StrictBaoClient({...config,kvMount:MOUNT},store);const adapter=new StrictKvAdapter(client,store);
    return new FixedSlotCoordinator(config,{store,journal,adapter});}
  catch(error){let first=error;try{journal?.close();}catch(e){first??=e;}try{store?.close();}catch(e){first??=e;}throw first;}}
