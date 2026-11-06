function verifySnapshotServiceRegressionSource(input) {
 const {changes,newFiles,canonical,meta,apply,audit}=input;
 const checks=[];function check(name,value){checks.push({name,pass:!!value});if(!value)throw Error(name);}
 check("exact b694 canonical Merkle",audit(canonical).root_sha==="9c800e97a2527e7f01c3a4b0be594e6762f9581e");
 const map=new Map(canonical.tree.filter(e=>e.type==="blob").map(e=>[e.path,e]));
 check("6 modified2 new fixed paths",changes.length===6&&newFiles.length===2&&new Set([...changes,...newFiles].map(x=>x.path)).size===8);
 for(const c of changes){
  check("canonical before "+c.name,map.get(c.path)?.sha===c.before.blob&&map.get(c.path)?.size===c.before.bytes);
  check("before/after whole "+c.name,JSON.stringify(meta(c.beforeText))===JSON.stringify(c.before)&&JSON.stringify(meta(c.afterText))===JSON.stringify(c.after));
  check("strict forward "+c.name,apply(c.beforeText,c.diff)===c.afterText);
  check("strict reverse "+c.name,apply(c.afterText,c.reverse)===c.beforeText&&apply(c.afterText,c.diff,true)===c.beforeText);
  let reconstructed=c.beforeText,reversed=c.afterText;
  for(const e of c.edits){check("unique insert "+c.name+" "+e.before.slice(0,50),reconstructed.split(e.before).length-1===1);reconstructed=reconstructed.replace(e.before,e.after);}
  for(const e of [...c.edits].reverse()){check("unique removal "+c.name+" "+e.after.slice(0,50),reversed.split(e.after).length-1===1);reversed=reversed.replace(e.after,e.before);}
  check("only declared additions "+c.name,reconstructed===c.afterText&&reversed===c.beforeText);
  const added=c.edits.map(e=>e.after.replace(e.before,"")).join("\n");
  check("cfg(test) injection "+c.name,c.name.endsWith("_tests.rs")||c.edits.every(e=>e.after.includes("#[cfg(test)]")||e.after.includes('#[cfg(all(test, feature = "native-v6-ha"))]')));
 }
 for(const f of newFiles){
  check("new canonical absence "+f.name,!map.has(f.path));
  check("new whole "+f.name,JSON.stringify(meta(f.text))===JSON.stringify(f.after));
 }
 const source=changes.find(c=>c.name==="service_snapshot_forward_source.rs").afterText;
 const client=changes.find(c=>c.name==="service_snapshot_forward_client.rs").afterText;
 const common=changes.find(c=>c.name==="service_snapshot_forward.rs").afterText;
 const service=changes.find(c=>c.name==="service.rs").afterText;
 const hist=changes.find(c=>c.name==="service_native_v6_ha_historical_restore_tests.rs").afterText;
 const fault=newFiles.find(c=>c.name==="service_snapshot_forward_test_faults.rs").text;
 const tests=newFiles.find(c=>c.name==="service_native_snapshot_forward_audit_tests.rs").text;
 check("test-only perService state/default",service.includes('#[cfg(all(test, feature = "native-v6-ha"))]\n    snapshot_forward_test:')&&service.includes('#[cfg(all(test, feature = "native-v6-ha"))]\n            snapshot_forward_test: Default::default()'));
 check("test-only fault module",common.includes('#[cfg(test)]\n#[path = "service_snapshot_forward_test_faults.rs"]'));
 check("child of existing real historical fixture",hist.includes('#[path = "service_native_snapshot_forward_audit_tests.rs"]\nmod snapshot_forward_audit_tests;'));
 check("source hook after real retained finalizer and status refusal",source.indexOf("self.complete_snapshot_transfer_retained")<source.indexOf("test_faults::Point::SourceAfterFinalizer")&&source.indexOf('if !matches!(response.status, 200 | 204)')<source.indexOf("test_faults::Point::SourceAfterFinalizer")&&source.indexOf("test_faults::Point::SourceAfterFinalizer")<source.indexOf("let publication: Result"));
 check("first gate hook after original sync/activation before real check",client.indexOf("test_faults::Point::IngressFirstDelivery")>client.indexOf("let activation = Zeroizing::new(service.unseal_nonce.clone())")&&client.indexOf("test_faults::Point::IngressFirstDelivery")<client.indexOf("self.delivery_check(service, &original, &data, &response, &activation)?"));
 check("second hook after mandatory success audit before real second check",client.indexOf("test_faults::Point::IngressSecondDelivery")>client.indexOf('// The source committed the original terminal clock floor.')&&client.indexOf("test_faults::Point::IngressSecondDelivery")<client.indexOf("if self.delivery_check(service, &original, &data, &response, &activation).is_err()"));
 check("actual nonce binding",fault.includes("self.snapshot_forward_test.armed != Some((point, nonce))")&&fault.indexOf("self.snapshot_forward_test.armed.take()")<fault.indexOf("self.audit.metadata()"));
 check("registration one shot and no reset",fault.includes("self.hits != 0")&&fault.includes("self.snapshot_forward_test.hits += 1")&&!/static mut|thread_local!|Mutex<Option|OnceLock/.test(fault));
 check("only injected state mutation nonce/audit cap",fault.includes("self.audit_capacity = bytes")&&fault.includes('self.unseal_nonce.push_str(":snapshot-forward-audit-fixture")')&&!/self\.(?:recovery_required|ha_activation|state|native_root|barrier_key)\s*=/.test(fault));
 check("no manufactured completion/receipt/root",!fault.includes("CompletionWire::seal(")&&!fault.includes("NativeV6PublishedRoot")&&!fault.includes("NativeHaHistoricalReceipt")&&!fault.includes("publish_native_v6"));
 check("observations only real fields",fault.includes("original_identity: original.original_identity")&&fault.includes("installed_identity: self.current_state_identity().ok()")&&fault.includes("audit_sequence: self.audit_sequence")&&fault.includes("injected: audit_bytes.is_some()"));
 check("exact4 test functions",(tests.match(/#\[test\]/g)||[]).length===4);
 check("real Pipeline and actual production listener",tests.includes("Pipeline::start_for_snapshot_forwarding()?")&&tests.includes(".register_snapshot_forward_handler(")&&tests.includes("Service::serve_native_snapshot_peer(&service, ingress, REQUEST_BUDGET)"));
 check("no handler strong Service cycle",tests.includes("let weak = Arc::downgrade(service)")&&tests.includes("weak.upgrade()"));
 check("real archive/once restore path",tests.includes("Zeroizing::new(export(pipeline, leader, pipeline.admin())?)")&&tests.includes("plan.execute(&service, &mut &archive[..]).into_parts()"));
 check("postarchive finite final use token",tests.indexOf("let (migration_source, archive) = prepare_archive")<tests.indexOf("let token = finite_original_token")&&tests.includes('"num_uses":1')&&tests.includes('assert_eq!(response.body["auth"]["num_uses"], 1)'));
 check("no second business admission",!tests.includes("authenticate(")&&!tests.includes("finish_external_request(")&&!tests.includes("restore(&pipeline")&&!fault.includes("begin_snapshot_request_before"));
 check("original deadline scope and exact ingress peer deadline",tests.includes("let until = began + REQUEST_BUDGET")&&tests.includes("RequestDeadlineScope::enter(until)")&&tests.includes("assert!(original_peer_deadline <= until)")&&tests.includes("assert_eq!(observed.deadline, original_peer_deadline)"));
 check("unknown and original authority asserted",tests.includes('assert_eq!(denied.body["outcome_unknown"], true)')&&tests.includes('assert_eq!(denied.body["retry_allowed"], false)')&&tests.includes('assert_eq!(denied.body["root_attempted"], true)')&&tests.includes("assert_eq!(reference, expected_reference)"));
 check("no data/file/headers/index at failed delivery",tests.includes("assert!(private_output.is_none())")&&tests.includes('assert!(denied.body.get("data").is_none())')&&tests.includes("assert!(denied.response_headers.is_empty())")&&tests.includes("assert!(denied.consistency_index.is_none())"));
 check("real originalAuth separated from installed",tests.includes("assert_ne!(observed.installed_auth, Some(observed.original_auth))"));
 check("actual audit append veto and fence",tests.includes("assert_eq!(target.audit_sequence, observed.audit_sequence)")&&tests.includes("target.audit.metadata()?.len()")&&tests.includes("assert!(target.recovery_required)")&&tests.includes("assert!(target.ha_activation.is_none())"));
 check("actual one epoch and exact operation/ref",tests.includes("assert_eq!(committed.1.epoch_transitions().len(), 1)")&&tests.includes("transition.source_root_digest(), observation.original_identity.digest()")&&tests.includes("transition.operation_digest(), committed.1.intent().operation_digest"));
 check("cold actual owner replacement",tests.includes("pipeline.stop_process(fault_node)?")&&tests.includes("rejoin_for_unseal(&mut pipeline, fault_node, migration_source)?")&&tests.includes("assert_eq!(reopened, committed)")&&tests.includes('"forward-audit-cold-future-absent"'));
 check("real private lease availability",tests.includes("let lease = spool.lease()?")&&tests.includes("assert_private_lease_released(&pipeline, ingress)?")&&tests.includes("assert_private_lease_released(&pipeline, leader)?"));
 check("one actual dispatch measured",tests.includes("assert_eq!(count_calls(&counts), 1)")&&tests.includes("count.fetch_add(1, Ordering::SeqCst)"));
 check("negative has both no-exchange and real mTLS denial",tests.includes("run_unverified_attempt(false)?")&&tests.includes("run_unverified_attempt(true)")&&tests.includes("plan.reject_before_exchange(&service, test_faults::forged_root_response())")&&fault.includes("peer.reject(503, &bytes)"));
 check("negative no forged root/ref after failed audit",tests.includes('assert!(denied.body.get("root_attempted").is_none())')&&tests.includes('assert!(denied.body.get("recovery_reference").is_none())')&&tests.includes('assert!(denied.body.get("outcome_unknown").is_none())'));
 check("negative no root mutation and no new epoch",tests.includes("assert_eq!(after, before)")&&tests.includes("assert!(after.1.epoch_transitions().is_empty())"));
 check("only denied wire has forged reference",fault.includes("native-v6-restore-forged-untrusted-fixture")&&!fault.includes("AdmissionWire::seal")&&!fault.includes("accept_body("));
 return {schema:"heptabao.snapshot-forward.Service-audit-regression.SOURCE-checks.v1",baseCommit:"b6949024dc5d0922ca9b27d865923d28982286c3",checks,checkCount:checks.length,allPassed:checks.every(x=>x.pass),scope:"Pure byte/projection/order/fixture source checks only; not Rust parsing, compiling or executed Service behavior",rustExecuted:false,runtimeCalls:0,testsExecuted:0};
}
