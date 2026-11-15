#!/usr/bin/env node
/** Local synthetic protocol negatives only; no SDK import, provider, SQL,
 * production file or Mac process is executed by these cases. */
import assert from 'node:assert/strict';
import {ROOT,validatePrivateInput,bindWriterChannel} from './mac_refresh_production_worker_r1.mjs';

const identity=(inode,bytes=0)=>['1',String(inode),'501','20','4480','1',String(bytes),'1','1'];
function input(){
 const bytes=Buffer.from('{"synthetic":true}');
 return {schema:'heptabao.main3-refresh-original-worker.private.r1',ordinal:0,remainingMilliseconds:120000,
  parentPid:123,parentNonce:'a'.repeat(64),channels:{request:{descriptor:3,identity:identity(3).slice(0,5)},
   response:{descriptor:4,identity:identity(4).slice(0,5)}},
  capsulePath:ROOT+'/captures/owner-01/output/selected-owner-credentials.private.json',
  capsuleIdentity:['1','2','501','20','33152','1',String(bytes.length),'1','1'],capsuleBytesBase64:bytes.toString('base64')};
}
function fixture(options={}){
 const value=input(),report={},closed=[],writes=[];let clock=1n,request='',reply=Buffer.alloc(0),reads=0;
 const io={
  fstatSync(fd){const id=identity(options.badPipe===fd?999:fd);
   return Object.fromEntries([...['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs'].map((k,i)=>[k,BigInt(id[i])]),
    ['isFIFO',()=>options.nonPipe!==fd]]);},
  writeSync(fd,bytes,offset,length){assert.equal(fd,3);const n=Math.min(length,options.writeChunk??length);
   const part=Buffer.from(bytes.subarray(offset,offset+n));writes.push(part);request+=part.toString('utf8');
   if(request.endsWith('\n')){
    const r=JSON.parse(request),response={...r,allowed:options.allowed!==false};
    if(options.wrongNonce)response.nonce='b'.repeat(64);
    const encoded=JSON.stringify(response)+'\n';
    reply=Buffer.from(options.duplicate?encoded.replace('"allowed":true','"allowed":false,"allowed":true'):
     options.oversized?'x'.repeat(4097):encoded);
   }return n;},
  readSync(fd,bytes,offset,length){assert.equal(fd,4);reads++;
   if(options.eof)return 0;
   const n=Math.min(reply.length,length,options.readChunk??length);
   reply.copy(bytes,offset,0,n);reply=reply.subarray(n);
   if(options.expireAfterRead)clock=1001n;
   return n;},
  closeSync(fd){closed.push(fd);if(options.closeFailure===fd)throw new Error('synthetic-close-fault');}
 };
 return {value,report,io,closed,writes,get reads(){return reads;},setClock:n=>{clock=n;},
  open:()=>bindWriterChannel({input:value,until:1000n,io,clock:()=>clock,parentPid:()=>123},report)};
}
const cases=[];
function test(name,fn){fn();cases.push({name,passed:true});}
function refused(fn,code){assert.throws(fn,error=>error.code===code);}

test('private_handoff_complete_original_capture',()=>assert.deepEqual(validatePrivateInput(input()),Buffer.from('{"synthetic":true}')));
test('old_or_other_ordinal_capture_refused',()=>{const v=input();v.capsulePath=v.capsulePath.replace('owner-01','owner-02');
 refused(()=>validatePrivateInput(v),'worker_fixed_fresh_ordinal_capture_path');});
test('unlisted_input_authority_refused',()=>{const v=input();v.providerAllowed=true;
 refused(()=>validatePrivateInput(v),'worker_exact_private_input_fields');});
test('noncanonical_private_bytes_refused',()=>{const v=input();v.capsuleBytesBase64+='=';
 refused(()=>validatePrivateInput(v),'worker_canonical_complete_private_capsule_bytes');});
test('stdin_or_shared_channel_descriptor_refused',()=>{for(const descriptor of [0,1,2,4]){
 const v=input();v.channels.request.descriptor=descriptor;
 refused(()=>validatePrivateInput(v),'worker_distinct_original_channel_bindings');}});
test('constructor_refusal_retires_both_original_pipes',()=>{const f=fixture({badPipe:4});
 refused(f.open,'worker_original_parent_pipe_identity');assert.deepEqual(f.closed,[4,3]);
 assert.equal(f.report.allOriginalPipesClosedOnce,true);assert.equal(f.writes.length,0);});
test('partial_original_io_complete_once',()=>{const f=fixture({writeChunk:7,readChunk:11}),channel=f.open();
 assert.equal(channel.verify(null,'final-native-send'),true);assert.ok(f.reads>1);
 assert.equal(f.report.requests,1);assert.equal(f.report.completeAuthorizations,1);channel.close();
 assert.deepEqual(f.closed,[4,3]);});
test('explicit_parent_refusal_blocks_all_later_dispatch',()=>{const f=fixture({allowed:false}),channel=f.open();
 refused(()=>channel.verify(null,'before-lock'),'worker_original_parent_refused');const written=f.writes.length;
 refused(()=>channel.verify(null,'before-lock'),'worker_original_writer_channel_lifetime');
 assert.equal(f.writes.length,written);assert.equal(f.report.completeRefusals,1);assert.equal(f.report.outcomeUnknown,false);channel.close();});
test('unrelated_parent_reply_is_unknown_and_not_replayed',()=>{const f=fixture({wrongNonce:true}),channel=f.open();
 refused(()=>channel.verify(null,'final-native-send'),'worker_exact_original_parent_authorization');
 const written=f.writes.length;refused(()=>channel.verify(null,'after-provider-return'),'worker_original_writer_channel_lifetime');
 assert.equal(f.writes.length,written);assert.equal(f.report.outcomeUnknown,true);channel.close();});
test('eof_after_request_is_unknown',()=>{const f=fixture({eof:true}),channel=f.open();
 refused(()=>channel.verify(null,'final-native-send'),'worker_original_parent_response_not_eof');
 assert.equal(f.report.outcomeUnknown,true);channel.close();});
test('expired_before_request_does_not_dispatch',()=>{const f=fixture(),channel=f.open();f.setClock(1001n);
 refused(()=>channel.verify(null,'before-lock'),'worker_original_writer_channel_lifetime');assert.equal(f.writes.length,0);
 assert.equal(f.report.outcomeUnknown,false);channel.close();});
test('response_after_deadline_never_authorizes_send',()=>{const f=fixture({expireAfterRead:true}),channel=f.open();
 refused(()=>channel.verify(null,'final-native-send'),'worker_original_writer_channel_lifetime');
 assert.equal(f.report.completeAuthorizations,0);assert.equal(f.report.outcomeUnknown,true);channel.close();});
test('oversized_response_refuses_without_second_request',()=>{const f=fixture({oversized:true}),channel=f.open();
 refused(()=>channel.verify(null,'final-native-send'),'worker_bounded_parent_response');assert.equal(f.report.requests,1);channel.close();});
test('duplicate_response_field_refused',()=>{const f=fixture({duplicate:true}),channel=f.open();
 refused(()=>channel.verify(null,'final-native-send'),'worker_exact_original_parent_authorization');
 assert.equal(f.report.completeAuthorizations,0);channel.close();});
test('failed_close_does_not_skip_or_retry_other_pipe',()=>{const f=fixture({closeFailure:4}),channel=f.open();
 refused(()=>channel.close(),'worker_original_parent_channel_close_unknown');
 refused(()=>channel.close(),'worker_writer_channel_close_once');assert.deepEqual(f.closed,[4,3]);
 assert.equal(f.report.allOriginalPipesClosedOnce,false);assert.equal(f.report.originalPipeCloseAttempts,2);});

process.stdout.write(JSON.stringify({schema:'heptabao.refresh-original-worker-channel.local.r1',ok:true,
 checks:cases.length,passed:cases.length,cases,syntheticInjectedIo:true,actualMacQualified:false,
 providerDispatches:0,productionSourceReads:0,productionMutations:0,realKernelPipeQualification:false})+'\n');
