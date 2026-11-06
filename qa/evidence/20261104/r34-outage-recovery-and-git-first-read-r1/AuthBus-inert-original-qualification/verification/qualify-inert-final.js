function qualifyInertFinal(x,h){
const checks=[],need=(v,n)=>{checks.push({name:n,pass:v===true});if(v!==true)throw Error(n);};
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),g=x.go,q=JSON.parse(x.requestText),input=JSON.parse(q.stdin),a=x.authority,n=x.streams,s=h.parse(n.stdout.text),anchor=h.parse(h.text(h.decode(input.anchorBase64)));
need(eq(h.meta(x.requestText),g.exactProcessStart),"exact_corrected_request");
need(h.meta(q.stdin).bytes===g.publicationScope.stdin.bytes&&h.meta(q.stdin).sha256===g.publicationScope.stdin.sha256,"exact_stdin");
need(a.job_id===x.job&&n.job_id===x.job&&a.state==="succeeded"&&a.exit_code===0,"original_job_exit0");
for(const k of ["output_complete","output_durable","terminal_publication_confirmed","audit_recorded"])need(a[k]===true,"authority_"+k);
for(const k of ["timed_out","cancelled","automatic_retry"])need(a[k]===false,"authority_"+k);
for(const [label,want] of [["stdout",15393],["stderr",0]]){
const z=n[label],m=h.meta(z.text),hex=Array.from(h.utf8(z.text),b=>b.toString(16).padStart(2,"0")).join("");
need(z.offset===0&&z.next_offset===want&&z.size===want&&z.eof===true&&m.bytes===want&&z.bytes_hex===hex,label+"_hex_text_whole_eof");
need(a.log_bytes[label].seen===want&&a.log_bytes[label].stored===want&&a.log_synced[label]===true&&a.log_truncated[label]===false&&a.log_errors[label]===null,label+"_authority_matches");
}
need(h.meta(n.stdout.text).bytes<=g.observers.stdoutMaximumBytes,"stdout_bound");
need(n.stderr.text==="","empty_stderr");
need(x.observers.length===2&&x.observers.every(z=>z.complete===true&&z.futureClosed===true),"both_original_observers_closed");
need(x.runtimeCallInFlight===false&&x.paused===false,"no_pending_native_error_or_call");
need(s.schema==="heptabao.mac-current-registry-wal-4e808-inert.r1","publisher_schema");
for(const k of ["ok","originalDeadlineMetAfterClosure","allOwnedCommandsStopped","allOwnedDescriptorsClosed","preparedCandidate","fixedLibraryDefinitionsLoadedOnly","authoritativeExitZeroRequired","candidateFileAloneIsNotQualification"])need(s[k]===true,"publisher_"+k);
for(const k of ["outcomeUnknown","currentPrivateInputsOpened","productionSqliteOpened","sqliteExecuted","inputEntrypointsExecuted","consumerExecuted","serviceStarted","cargoStarted","gitStarted"])need(s[k]===false,"publisher_"+k);
need(s.elapsedSeconds>=0&&s.elapsedSeconds<45&&s.newOriginalInertSeconds===45,"original_shared45_closed_deadline");
need(s.createdRoot===g.newRoot&&s.createdQa===g.newRoot+"/qa"&&s.createdProofs===g.newRoot+"/proofs","fresh_fixed_root");
need(s.freshRootAbsence.path===g.newRoot&&eq(s.freshRootAbsence.twoEnoentObservations,[true,true]),"fresh_root_two_absence");
const valid9=z=>Array.isArray(z)&&z.length===9&&z.every(v=>typeof v==="string"&&/^\d+$/.test(v));
need(valid9(s.freshRootAbsence.heldParentIdentity),"fresh_parent_full9_lossless");
need(s.inputBytes===g.publicationScope.stdin.bytes&&s.inputSha256===g.publicationScope.stdin.sha256,"publisher_input_binding");
const expected=new Map();
for(const [name,b64] of Object.entries(input.files)){const m=h.meta(h.text(h.decode(b64)));expected.set("qa/"+name,{kind:"source",bytes:m.bytes,sha256:m.sha256});}
for(const [name,b64] of Object.entries(input.documents)){const m=h.meta(h.text(h.decode(b64)));expected.set(name,{kind:"public_document",bytes:m.bytes,sha256:m.sha256});}
need(expected.size===30&&Object.keys(input.files).length===22&&Object.keys(input.documents).length===8,"input_22_sources_8_documents");
need(s.files.length===30&&new Set(s.files.map(z=>z.name)).size===30&&s.sourceCount===22&&s.publicDocumentCount===8,"actual_exact30_unique");
for(const z of s.files){
const e=expected.get(z.name);need(!!e&&z.kind===e.kind&&z.bytes===e.bytes&&z.sha256===e.sha256,"exact_pin:"+z.name);
need(valid9(z.identity)&&z.identity[0]===anchor.expectedVolumeDevice&&z.identity[2]==="501"&&z.identity[4]==="33152"&&z.identity[5]==="1"&&z.identity[6]===String(z.bytes),"full9_regular_singlelink:"+z.name);
need(z.wholeReadbackVerified===true&&z.readbackUsesSeparateHeldFd===true,"independent_held_whole:"+z.name);
}
const py=Object.keys(input.files).filter(z=>z.endsWith(".py")).sort(),js=Object.keys(input.files).filter(z=>z.endsWith(".mjs")).sort();
need(s.compiledPythonCountExpected===18&&eq([...s.compiledSources].sort(),py)&&eq([...s.byteVerifiedJavascriptSources].sort(),js)&&js.length===4,"18_compile_4_byte_only");
need(eq(s.loadedLibraryDefinitions,g.publicationScope.definitionOnlyLibraries),"only3_definition_libraries");
const t=s.heldT5Final;
need(t.allDescriptorsClosed===true&&t.lastAnchorCheckPassed===true&&t.volumeUUIDVerified===true&&eq(t.closeErrors,[]),"T5_closed_known");
need(t.expectedVolumeDevice===anchor.expectedVolumeDevice&&eq(t.anchors,anchor.anchors)&&t.anchors.every(z=>valid9(z.identity)),"T5_all27_exact");
need(anchor.volumeUUID==="FB804D1B-24CB-4D6E-AEA7-A9E180807758","fixed_volume_UUID_input");
need(s.commands.allOwnedCommandsStopped===true&&s.commands.unknownCommandCount===0&&s.commands.commands.length===1,"one_owned_command_closed");
const c=s.commands.commands[0],cl=c.cleanup;
need(eq(c,s.volumeProbe)&&eq(c.argv,["/usr/sbin/diskutil","info","-plist","/Volumes/T5"])&&c.label==="inert-t5-volume","original_diskutil_only");
need(c.exitCode===0&&c.outcomeUnknown===false&&c.completeBeforeDeadline===true&&c.elapsedSeconds>=0&&c.elapsedSeconds<30&&c.streamsClosed===true&&c.errorCode===null&&c.errorType===null&&c.stderrBytes===0,"diskutil_known_exit_and_streams");
need(cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true&&eq(cl.remainingGroupRows,[])&&cl.postReapSignalSent===false,"diskutil_owned_cleanup");
need(eq(cl.cleanupCaps,{group:3,psMax:4,term:1,wait:5}),"cleanup_original_caps");
need(cl.pid===c.pid&&cl.pgid===c.pid&&cl.custody.ps.pid===c.pid&&cl.custody.ps.pgid===c.pid&&cl.custody.ps.uid===501&&cl.custody.sid_observed_while_live===c.pid&&typeof cl.custody.ps.start==="string"&&cl.custody.ps.start.length>0,"diskutil_retained_custody");
need(cl.retainedExit.pid===c.pid&&cl.retainedExit.code===1&&cl.retainedExit.status===0&&cl.exitCode===0&&eq(cl.signals,[]),"diskutil_natural_WNOWAIT_exit");
const r=s.candidateReceipt;
need(r.name==="inert-registry-wal-4e808-result.public.json"&&r.kind==="inert_candidate_receipt"&&Number.isInteger(r.bytes)&&r.bytes>0&&r.bytes<=65536&&r.sha256===s.candidateReceiptSha256&&/^[a-f0-9]{64}$/.test(r.sha256),"receipt_final_pin");
need(valid9(r.identity)&&r.identity[0]===anchor.expectedVolumeDevice&&r.identity[2]==="501"&&r.identity[4]==="33152"&&r.identity[5]==="1"&&r.identity[6]===String(r.bytes)&&r.wholeReadbackVerified===true&&r.readbackUsesSeparateHeldFd===true,"receipt_held_whole_full9");
return{schema:"heptabao.owner-renew-inert.conditional-metadata-admission.r1",pass:true,rootGo:h.meta(x.goText),originalJob:x.job,stdout:h.meta(n.stdout.text),authority:x.authorityPin,checks,checkCount:checks.length,actualSources:22,actualDocuments:8,actualReceipt:r,elapsedSeconds:s.elapsedSeconds,metadataNowPermitted:3,bodyStillConditionalOnAll3Info:true,fullWorkerAuthorized:false,sequentialObservationNotAtomicExecCustody:true};
}
