#!/usr/bin/env node
/** Narrow injected-I/O checks. No original SDK, database, network or Mac
 * process is executed. Actual Mac cold-SDK qualification remains separate. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {bindFreshCloneReader,CloneReadRefused} from './mac_sdk_private_clone_reader_r1.mjs';

const ROOT='/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1/captures/owner-01';
const LIVE='/Users/qianqi/.openclaw';
const AGENTS=['main','trnm','hepta-ui','hepta','hepta-backend'];
const WHOLE='6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a';
const fields=['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'];
const full=s=>fields.map(k=>String(s[k]));
const cases=[];
function test(name,fn){fn();cases.push({name,passed:true});}
function refused(fn){assert.throws(fn,error=>error instanceof CloneReadRefused);}

function fixture({closeFault=null}={}){
 const named=new Map(),fds=new Map(),closed=[],report={};let next=100,now=1n;
 function entry(filename,kind){
  const value={dev:1n,ino:BigInt(named.size+1),uid:filename.startsWith('/Users/qianqi')?501n:0n,
   gid:filename.startsWith('/Users/qianqi')?20n:0n,
   mode:BigInt(kind==='file'?0o100600:filename.startsWith('/Users/qianqi')?0o40700:0o40755),
   nlink:1n,size:kind==='file'?4096n:64n,mtimeNs:1n,ctimeNs:1n,kind};
  named.set(filename,value);return value;
 }
 const chain=[];for(let d=ROOT+'/output/source-clones';;d=path.dirname(d)){
  chain.unshift(d);if(path.dirname(d)===d)break;
 }
 for(const dir of chain)entry(dir,'directory');
 function stat(value){return {...value,isFile:()=>value.kind==='file',isDirectory:()=>value.kind==='directory'};}
 const binding={schema:'heptabao.fresh-whole-clone-read.private.r1',backupSourceSha256:WHOLE,
  sourcePhase:'after_writer_quiescence',entries:AGENTS.map((agent,i)=>{
   const physicalPath=ROOT+'/output/source-clones/candidate-'+i+'.sqlite';
   const original=entry(physicalPath,'file');
   return {ordinal:i,logicalPath:LIVE+'/agents/'+agent+'/agent/openclaw-agent.sqlite',physicalPath,
    physicalFull9:full(original),twoCompleteBackupOutputsEqual:true,freshIndependentTransaction:true,
    keeperUsedAsLatestSource:false,sourceContentCopyAuthority:'sqlite_online_backup_api'};
  })};
 const io={constants:fs.constants,
  openSync(filename,flags){assert.ok(flags&fs.constants.O_NOFOLLOW);const value=named.get(filename);
   assert.ok(value,'fixture only contains fixed declared names');
   if(flags&fs.constants.O_DIRECTORY)assert.equal(value.kind,'directory');
   const fd=next++;fds.set(fd,{filename,value,attempts:0});return fd;},
  fstatSync(fd){const row=fds.get(fd);assert.ok(row&&!row.attempts);return stat(row.value);},
  lstatSync(filename){const value=named.get(filename);assert.ok(value);return stat(value);},
  closeSync(fd){const row=fds.get(fd);assert.ok(row);row.attempts++;assert.equal(row.attempts,1);
   closed.push(fd);if(row.filename===closeFault)throw new Error('synthetic original close unknown');}
 };
 const open=()=>bindFreshCloneReader({root:ROOT,binding,until:100n,io,clock:()=>now},report);
 const allAttempted=()=>assert.ok([...fds.values()].every(x=>x.attempts===1));
 return {binding,named,fds,closed,report,open,allAttempted,setTime:x=>{now=x;}};
}

test('only_five_logical_readonly_constructors_route_to_exact_private_outputs',()=>{
 const f=fixture(),reader=f.open();
 for(const entry of f.binding.entries){const options={readOnly:true,timeout:0},before=structuredClone(options);
  assert.equal(reader.route(entry.logicalPath,options),entry.physicalPath);assert.deepEqual(options,before);}
 assert.equal(f.report.cloneDatabaseConstructorsRouted,5);
 assert.equal(f.report.sourceDatabaseConstructorsDispatched,0);
 reader.verify();reader.close();f.allAttempted();assert.equal(f.report.allOriginalDescriptorsClosedOnce,true);
});
for(const [name,filename,options]of[
 ['sixth_database_refused',LIVE+'/agents/other/agent/openclaw-agent.sqlite',{readOnly:true}],
 ['normalized_alias_does_not_expand_exact_scope',LIVE+'/agents/main/agent/../agent/openclaw-agent.sqlite',{readOnly:true}],
 ['writable_constructor_refused',LIVE+'/agents/main/agent/openclaw-agent.sqlite',{readOnly:false}],
 ['string_readonly_does_not_authorize',LIVE+'/agents/main/agent/openclaw-agent.sqlite',{readOnly:'true'}]]){
 test(name,()=>{const f=fixture(),reader=f.open();refused(()=>reader.route(filename,options));
  assert.equal(f.report.cloneDatabaseConstructorsRouted,0);reader.close();f.allAttempted();});
}
for(const [name,change]of[
 ['other_physical_capture_root_refused',b=>{b.entries[0].physicalPath=b.entries[0].physicalPath.replace('owner-01','owner-02');}],
 ['duplicate_slot_refused',b=>{b.entries[1].ordinal=0;}],
 ['unqualified_backup_source_refused',b=>{b.backupSourceSha256='0'.repeat(64);}],
 ['old_keeper_cannot_be_latest',b=>{b.entries[0].keeperUsedAsLatestSource=true;}],
 ['only_one_backup_output_refused',b=>{b.entries[0].twoCompleteBackupOutputsEqual=false;}]]){
 test(name,()=>{const f=fixture();change(f.binding);refused(f.open);f.allAttempted();});
}
test('named_file_replacement_refuses_same_old_held_descriptor',()=>{
 const f=fixture(),reader=f.open(),entry=f.binding.entries[0],old=f.named.get(entry.physicalPath);
 f.named.set(entry.physicalPath,{...old,ino:old.ino+1000n});
 refused(()=>reader.route(entry.logicalPath,{readOnly:true}));reader.close();f.allAttempted();
});
test('same_inode_content_generation_change_refused',()=>{
 const f=fixture(),reader=f.open(),entry=f.binding.entries[0];f.named.get(entry.physicalPath).mtimeNs++;
 refused(reader.verify);reader.close();f.allAttempted();
});
test('other_home_ancestor_ctime_change_not_rebased',()=>{
 const f=fixture(),reader=f.open();f.named.get('/Users/qianqi').ctimeNs++;
 refused(reader.verify);reader.close();f.allAttempted();
});
test('only_declared_private_output_directory_entries_may_change',()=>{
 const f=fixture(),reader=f.open();
 for(const name of [ROOT+'/output',ROOT+'/output/source-clones']){
  f.named.get(name).ctimeNs++;f.named.get(name).mtimeNs++;f.named.get(name).size+=10n;}
 reader.verify();reader.close();f.allAttempted();
});
test('mutable_directory_inode_replacement_is_still_refused',()=>{
 const f=fixture(),reader=f.open(),name=ROOT+'/output/source-clones',old=f.named.get(name);
 f.named.set(name,{...old,ino:old.ino+1000n});refused(reader.verify);reader.close();f.allAttempted();
});
test('clone_wrong_group_refuses_and_closes_all_returned_descriptors',()=>{
 const f=fixture(),entry=f.binding.entries[2];f.named.get(entry.physicalPath).gid=0n;
 refused(f.open);f.allAttempted();
});
test('close_result_unknown_never_retries_or_skips_other_original_fds',()=>{
 const f=fixture({closeFault:ROOT+'/output/source-clones/candidate-3.sqlite'}),reader=f.open();
 refused(reader.close);f.allAttempted();const count=f.closed.length;
 refused(reader.close);assert.equal(f.closed.length,count);assert.equal(f.report.allOriginalDescriptorsClosedOnce,false);
});
test('expired_context_cannot_route_another_database',()=>{
 const f=fixture(),reader=f.open();f.setTime(100n);
 refused(()=>reader.route(f.binding.entries[0].logicalPath,{readOnly:true}));reader.close();f.allAttempted();
});
process.stdout.write(JSON.stringify({schema:'heptabao.private-clone-reader.local-qualification.r1',
 ok:true,checks:cases.length,passed:cases.length,cases,syntheticInjectedIo:true,
 actualSdkExecuted:false,actualSqliteBackupExecuted:false,actualMacQualified:false,
 productionSourceReads:0,providerDispatches:0,productionMutations:0})+'\n');
