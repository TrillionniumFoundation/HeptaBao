/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "combined_02b90762_fresh_build_gitfirst_r2";
const GF_REQUEST = {blob:"dc8f695b48db595fd84d438ee1d240679c0a936c",
 bytes:153606,sha256:"042ceb19df239ee4febd6eda9ea84fb1693fe5bdda9bda92ab94e8fe5374dce9"};

/* One separately approved observation of the newly owned public stage report.
 * This does not authorize binary_read or any new process. Existing state is kept.
 */
const GF_STAGE_RESULT_PATH = "/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/result.public.json";
const GF_STAGE_RESULT_MAX_BYTES = 4194304;
const GF_STAGE_INFO_REQUEST = {"blob":"7fd64e245a2030d5b71b26d62a4909f01fb9f28d","bytes":273,"sha256":"e79bc3486e419d122d50ae5142bcc1673982d7b3d7d9439747789a8ca7c761c4"};
const GF_STAGE_INFO_PREREQUISITES = [{"id":"82eca3d912f7ed4550db60ff96d55d340f7f842ad0e087eb8c6ba08fc5625caf","tool":"process_status","nativeText":{"blob":"10702d460d97a546576be01007e1ad1b3745a50c","bytes":728,"sha256":"c3ed05955b190e4e607e458c94269c3bb6768c87f0088d9678e8295c8587f1db"}},{"id":"b41b8414ce7a13bf55869a359187e237566305eb5f32576a2e9ee05a509b25d6","tool":"process_read","nativeText":{"blob":"8d4db2b90fb1a1d5685696cff725e72ecf314ed4","bytes":6443,"sha256":"951c5d73f68597edc2072a9c6498588e9eed50274603815adfc56181a630ec74"}},{"id":"807617b190e7e8f67a87456fe3d78c25fd5d0dd4f14c84e9511445d94839fe04","tool":"process_read","nativeText":{"blob":"8efab367ea32f4f8ff6d29fa1a2db5fc614e8b6f","bytes":1536,"sha256":"93e841edcf0ad8cf50c8ebe989f786765114702134af663284a61638d1247eae"}}];

function gfAuthorizeStageResultInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.startCalled===true
   && s.job==="1a1b282ded0-fc05-7e57" && s.stageResultInfoGO===undefined
   && s.stageResultInfoStarted!==true,"closed_existing_stage_before_info_only_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_info_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_result_file_info_only"
   && g.original_job===s.job && g.maximum_file_info_starts===1
   && g.binary_read_authorized===false
   && g.exact_request?.blob===GF_STAGE_INFO_REQUEST.blob
   && g.exact_request?.bytes===GF_STAGE_INFO_REQUEST.bytes
   && g.exact_request?.sha256===GF_STAGE_INFO_REQUEST.sha256,
   "exact_new_root_file_info_scope");
 for(const need of GF_STAGE_INFO_PREREQUISITES) {
  const prior=s.completedObservers.find(o=>o.id===need.id);
  const priorRaw=load(GF_SLOT+":closed_native:"+need.id);
  gfNeed(prior?.completedInactive===true && prior.tool===need.tool
    && gfMetaEquals(priorRaw,need.nativeText)
    && prior.nativeText.blob===need.nativeText.blob,"original_stage_closure_pin");
 }
 const authority=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_STAGE_INFO_PREREQUISITES[0].id));
 let stdout="",stderr="",so=0,se=0,last=null;
 for(const need of GF_STAGE_INFO_PREREQUISITES.slice(1)) {
  const v=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+need.id));
  gfNeed(v.job_id===s.job && v.stdout.offset===so && v.stderr.offset===se,
         "original_stream_sequence");
  stdout+=v.stdout.text;stderr+=v.stderr.text;
  so=v.stdout.next_offset;se=v.stderr.next_offset;last=v;
 }
 gfNeed(last.stdout.eof===true && last.stderr.eof===true
   && so===2391 && se===0 && s.nextStdout===so && s.nextStderr===se
   && gitBlobMeta(stdout).sha256==="4063a65b162e678ac10dd7afb2a7f8613bfe6005f1d5169409483e0ce1f860ef"
   && gitBlobMeta(stdout).bytes===2391 && stderr==="","whole_current_streams");
 const lines=stdout.trimEnd().split("\n");
 gfNeed(lines.length===3,"three_original_public_output_lines");
 const terminal=JSON.parse(lines[2]);
 gfNeed(authority.job_id===s.job && authority.exit_code===1
   && authority.output_complete===true && authority.output_durable===true
   && authority.terminal_publication_confirmed===true
   && authority.log_bytes.stdout.stored===2391 && authority.log_bytes.stderr.stored===0
   && !authority.timed_out && !authority.cancelled
   && terminal.all_owned_stopped===true && terminal.status==="failed"
   && terminal.publication_within_original_outer===true
   && terminal.source_commit==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270"
   && terminal.source_tree==="9781e9615ac5fb068d217241c74bb54bf87942cf"
   && terminal.result_sha256==="db0079589bd50c271486056283825ba1c3a415c19204f707ed4b5d1b786ec3b4"
   && terminal.result_path===GF_STAGE_RESULT_PATH,"known_failed_build_safe_public_result");
 s.stageResultInfoGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,exactRequest:GF_STAGE_INFO_REQUEST,
   maximumFileInfoStarts:1,binaryReadAuthorized:false};
}

/* One exact whole-report chunk after independently closed actual metadata.
 * Only this 40591-byte range is admitted; no body/listing fallback exists.
 */
const GF_STAGE_BODY_REQUEST = {"blob":"f5e60c6c72aca21ca5a7717571ddcefe6916eded","bytes":406,"sha256":"08e4972311e7f124f21b595fd3de45926033d30c13919cfae4d03cbdeb168ab3"};
const GF_STAGE_BODY_EXPECTED = {"path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/result.public.json","bytes":40591,"sha256":"db0079589bd50c271486056283825ba1c3a415c19204f707ed4b5d1b786ec3b4","version":"66306:28484413:40591:1793996644769259586:1793996644769259586","infoOperation":"a051062b0017b159aef24eaa85196061a1a066845d3fc3e12ff213ee30e08e59","infoNative":{"blob":"39ea5396f7b4c910b531f27151d0c9cbc36f8c3c","bytes":468,"sha256":"b82542605edf781a9dc6bce738a283f879c33ddc30f9028f2ade5d17c3611989"}};

function gfAuthorizeStageResultBodyOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),need=GF_STAGE_BODY_EXPECTED,info=s.stageResultInfo;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.job==="1a1b282ded0-fc05-7e57"
   && s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted===true
   && s.stageResultBodyGO===undefined && s.stageResultBodyStarted!==true,
   "closed_info_before_one_exact_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob && goPin.blob!==s.stageResultInfoGO.pin.blob,
   "separate_whole_body_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_result_binary_read_only"
   && g.original_job===s.job && g.info_operation===need.infoOperation
   && g.maximum_binary_read_starts===1
   && g.exact_request?.blob===GF_STAGE_BODY_REQUEST.blob
   && g.exact_request?.bytes===GF_STAGE_BODY_REQUEST.bytes
   && g.exact_request?.sha256===GF_STAGE_BODY_REQUEST.sha256,
   "exact_new_root_body_scope");
 const prior=s.completedObservers.find(o=>o.id===need.infoOperation);
 gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
   && prior.nativeText.blob===need.infoNative.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
   && info?.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && need.bytes>0 && need.bytes<=65536 && need.bytes<=GF_STAGE_RESULT_MAX_BYTES,
   "whole_current_info_identity_and_single_chunk");
 s.stageResultBodyGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,infoOperation:need.infoOperation,
   exactRequest:GF_STAGE_BODY_REQUEST,maximumBinaryReadStarts:1,wholeBytes:need.bytes};
}

/* Two separately approved fixed original Cargo logs: metadata only.
 * No process, byte-body read, directory enumeration, or metadata refresh. */
const GF_BUILD_LOG_INFOS = [{"index":0,"stream":"stderr","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stderr","sha256":"0b2916602918b7e3d05457d6445c20a55478846d99d7cd7067db0058f66c23cc","maximumBytes":4194304,"request":{"blob":"63319a0c58aa7fc8f71737de66230e46b50af98a","bytes":290,"sha256":"48d21505a5d1996eee1d9697a74f79d52686c742d8960d9c34cdea46d2a4aa8f"}},{"index":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","maximumBytes":4194304,"request":{"blob":"3103f0f552b07501d8e689500fdb6839d16412e0","bytes":290,"sha256":"d66ba4e596732bcf1c5474e55803a87b147f966f72e7b1a8255fc93801698bd1"}}];
const GF_BUILD_FAILED_REPORT = {"blob":"3749276afcc6e1ead912370e9626dc3645c111df","bytes":40591,"sha256":"db0079589bd50c271486056283825ba1c3a415c19204f707ed4b5d1b786ec3b4"};
function gfAuthorizeBuildLogsInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
  && s.job==="1a1b282ded0-fc05-7e57" && s.stageResultBodyGO?.whole===true
  && s.stageResultBodyStarted===true && s.buildLogsInfoGO===undefined,
  "closed_failed_report_before_fixed_log_infos");
 gfNeed(s.stageResultBody?.originalOperation==="6d813c6f6fd62632675eab72ef1446f7d5ef3ef98b1b20be6f24d7737deac949"
  && s.completedObservers.some(o=>o.id===s.stageResultBody.originalOperation
    && o.tool==="binary_read" && o.completedInactive===true)
  && gfMetaEquals(load(GF_SLOT+":stage_result_body_original"),GF_BUILD_FAILED_REPORT),
  "exact_original_failed_report_whole");
 const report=parseLosslessIntegers(load(GF_SLOT+":stage_result_body_original"));
 gfNeed(report.status==="failed" && report.source_commit==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270"
  && report.normal_release_build?.label==="normal-release-build"
  && report.normal_release_build.exit_code===101 && report.normal_release_build.timed_out===false
  && report.runtime_tests_started===false
  && GF_BUILD_LOG_INFOS.every(x=>report.normal_release_build[x.stream+"_sha256"]===x.sha256),
  "original_actual_Cargo_failure_and_log_hashes");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
  && ![s.goPin.blob,s.stageResultInfoGO.pin.blob,s.stageResultBodyGO.pin.blob].includes(goPin.blob),
  "separate_whole_fixed_logs_info_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_logs_file_info_only"
  && g.original_job===s.job && g.maximum_file_info_starts===2 && g.binary_read_authorized===false
  && JSON.stringify(g.exact_requests)===JSON.stringify(GF_BUILD_LOG_INFOS.map(x=>x.request)),
  "exact_new_root_two_log_metadata_scope");
 s.buildLogsInfoGO={pin:goPin,raw:goRaw,whole:true};
 s.buildLogInfoNext=0;s.buildLogInfoCalled=0;s.buildLogInfos=[];
 gfSave(s);
 return {exactRequests:GF_BUILD_LOG_INFOS.map(x=>x.request),maximumFileInfoStarts:2,binaryReadAuthorized:false};
}

/* Seven fixed version-bound ranges for the two original closed Cargo logs.
 * New log-body observers alone use 16 KiB immutable pages; old routes stay 8 KiB.
 * Per-file bytes are joined and whole-hashed before one UTF8 decode.
 */
const GF_BUILD_LOG_BODY_INFOS = [{"index":0,"stream":"stderr","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stderr","size":20639,"sha256":"0b2916602918b7e3d05457d6445c20a55478846d99d7cd7067db0058f66c23cc","version":"66306:28477815:20639:1793996644686260313:1793996644686260313","nativeText":{"blob":"74dcc914acc1a0718c206a7e963018936b942390","bytes":477,"sha256":"63e7af3d5867fe5e6042975e81b71b9649a1ed23796c569c2fd8ac2c1b2f2a1b"},"originalOperation":"aa636e3172f3db62ce4df425ae55997b2b4bde19011caa0eab9a46905d680bf9","full9Strings":["66306","28477815","1000","1000","33152","1","20639","1793996644686260313","1793996644686260313"],"regularFileFromNativeFileInfoContract":true,"binaryReadAuthorized":false},{"index":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","size":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","nativeText":{"blob":"ddfe06f45322b80000ce01e66ea04970873fcba4","bytes":479,"sha256":"d6f7b2c7ba8fe19308bfeb708319e1df6150b7cec91d3566844b8b7083e46abf"},"originalOperation":"4f501a3e7177c46291be7e1f878e8ad20f52d7e0aff27ae631984abba0a6c70d","full9Strings":["66306","28477813","1000","1000","33152","1","384182","1793996644686260313","1793996644686260313"],"regularFileFromNativeFileInfoContract":true,"binaryReadAuthorized":false}];
const GF_BUILD_LOG_RANGES = [{"index":0,"fileIndex":0,"stream":"stderr","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stderr","bytes":20639,"sha256":"0b2916602918b7e3d05457d6445c20a55478846d99d7cd7067db0058f66c23cc","version":"66306:28477815:20639:1793996644686260313:1793996644686260313","offset":0,"limit":20639,"eof":true,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stderr-body0","request":{"blob":"1b7d38ad753a643df0bd00fad92565abbe7b24b8","bytes":424,"sha256":"caac2dbb5b378a83d0cd9c84f00baabb65c9dc9e718ca219b4f7c4d615b58a92"}},{"index":1,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":0,"limit":65536,"eof":false,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body0","request":{"blob":"0d0c82ad90e49197b5b133bb94d53fbc21627bee","bytes":425,"sha256":"70c8ff6027f9242871976da0d8ebe93b1a4e3b67d71a5a98cf7b986a6cf2e642"}},{"index":2,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":65536,"limit":65536,"eof":false,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body1","request":{"blob":"23fd903f426df732a3fa2b9d894903599b4122b2","bytes":429,"sha256":"d2ef6c599a2655922f978c04defd53d50799a3945fe2ed9fbe1556a8cf971531"}},{"index":3,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":131072,"limit":65536,"eof":false,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body2","request":{"blob":"484a738f535e476874acb1a42a26e7a62f52c8c5","bytes":430,"sha256":"10aaf8751d8e102972b4e7686503f138f5b383b0286b75c1195be4a476022ed9"}},{"index":4,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":196608,"limit":65536,"eof":false,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body3","request":{"blob":"c31805ba762fd82a42a5f366f07847ddbb40a4cf","bytes":430,"sha256":"b00122e9ded6e0118e9ac44b2993ed8c90177acab42b413326890bcc92056660"}},{"index":5,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":262144,"limit":65536,"eof":false,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body4","request":{"blob":"7d77c62f4c5ab15171dc9d99aa6f76f03bbfea0b","bytes":430,"sha256":"817dadaf6303d956392f6ae17305f376dc18715b6f568528ffa4e8162672e1db"}},{"index":6,"fileIndex":1,"stream":"stdout","path":"/home/qian-qi/hb-02b90762-controls-20261106-r2/build-tests-r1/normal-release-build.stdout","bytes":384182,"sha256":"9fc6bdccb931b4cf5febb609921cb849a74e56920869dd4e2988bcebde9d0948","version":"66306:28477813:384182:1793996644686260313:1793996644686260313","offset":327680,"limit":56502,"eof":true,"idempotencyKey":"heptabao-combined-02b90762-fresh-observe-r2-release-stdout-body5","request":{"blob":"a01b2f211179576916eb333beb01bba011a864eb","bytes":430,"sha256":"ee7c55e48921c006478794f5252d44e6ebe4d0193adbe95d4ab6a4e04df2cc1e"}}];
function gfBuildLogPageBytes(s) {
 const a=s.activeObserver,n=GF_BUILD_LOG_RANGES[s.buildLogBodyNext];
 return s.buildLogsBodyGO?.whole===true && a?.tool==="binary_read" && n
  && a.request.idempotency_key===n.idempotencyKey
  && a.request.operation.arguments.path===n.path
  && a.request.operation.arguments.offset===n.offset ? 16384 : 8192;
}
function gfAuthorizeBuildLogBodiesOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
  && s.job==="1a1b282ded0-fc05-7e57" && s.buildLogsInfoGO?.whole===true
  && s.buildLogInfoNext===2 && s.buildLogInfoCalled===2
  && s.buildLogsBodyGO===undefined && s.buildLogBodies===undefined,
  "both_original_log_infos_closed_before_body_GO");
 gfNeed(JSON.stringify(s.buildLogInfos)===JSON.stringify(GF_BUILD_LOG_BODY_INFOS),
  "unchanged_actual_two_log_full9");
 for(const f of GF_BUILD_LOG_BODY_INFOS) {
  const original=s.completedObservers.find(x=>x.id===f.originalOperation);
  gfNeed(original?.tool==="file_info" && original.completedInactive===true
   && original.nativeText.blob===f.nativeText.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+f.originalOperation),f.nativeText),
   "both_exact_original_info_native_whole");
 }
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
  && ![s.goPin.blob,s.stageResultInfoGO.pin.blob,s.stageResultBodyGO.pin.blob,s.buildLogsInfoGO.pin.blob].includes(goPin.blob),
  "separate_whole_log_body_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_logs_binary_read_ranges_only"
  && g.original_job===s.job && g.maximum_binary_read_starts===7
  && g.new_body_page_bytes===16384 && g.maximum_body_bytes===404821
  && JSON.stringify(g.exact_requests)===JSON.stringify(GF_BUILD_LOG_RANGES.map(x=>x.request)),
  "exact_seven_ranges_and_new_body_page_width");
 s.buildLogsBodyGO={pin:goPin,raw:goRaw,whole:true};
 s.buildLogBodyNext=0;s.buildLogBodyCalled=0;s.buildLogParts={stderr:[],stdout:[]};s.buildLogBodies=[];
 gfSave(s);
 return {maximumBinaryReadStarts:7,totalBytes:404821,newBodyPageBytes:16384};
}

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,digest,fingerprint}) {
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_context_must_be_recovered_not_reinitialized");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"exact_whole_root_go");
 gfNeed(/^[0-9a-f]{64}$/.test(digest) && /^[0-9]{1,20}$/.test(fingerprint),
        "root_independently_bound_native_identity");
 // The caller must supply the separately reviewed actual GO, not the SOURCE contract.
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest,fingerprint,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  gfNeed(!s.startCalled && s.job===null && s.activeObserver===null
    && gfMetaEquals(raw,GF_REQUEST),"one_exact_diagnostic_start");
 } else if(kind==="operation_start") {
  gfNeed(s.job!==null && s.activeObserver===null,"original_job_no_unclosed_observer");
  gfNeed(Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && typeof q.idempotency_key==="string" && q.idempotency_key.length<=128
    && /^heptabao-combined-02b90762-fresh-observe-r2-/.test(q.idempotency_key),
    "bounded_original_observer_key");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && a && a.host==="rog","same_original_host_only");
  if(op.tool==="binary_read" && s.buildLogsBodyGO?.whole===true) {
   const n=GF_BUILD_LOG_RANGES[s.buildLogBodyNext];
   gfNeed(n && s.buildLogBodyCalled===s.buildLogBodyNext
    && gfMetaEquals(raw,n.request)
    && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
    && a.path===n.path && a.offset===n.offset && a.limit===n.limit && a.limit<=65536
    && a.expected_version===n.version,"next_once_exact_original_log_range");
  } else if(op.tool==="file_info" && s.buildLogsInfoGO?.whole===true) {
   const need=GF_BUILD_LOG_INFOS[s.buildLogInfoNext];
   gfNeed(need && s.buildLogInfoCalled===s.buildLogInfoNext
    && gfMetaEquals(raw,need.request) && Object.keys(a).sort().join(",")==="host,path"
    && a.path===need.path,"next_once_exact_fixed_log_metadata");
  } else if(op.tool==="binary_read") {
   gfNeed(s.stageResultBodyGO?.whole===true && s.stageResultBodyStarted!==true
     && gfMetaEquals(raw,GF_STAGE_BODY_REQUEST)
     && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.path===GF_STAGE_BODY_EXPECTED.path && a.offset===0
     && a.limit===GF_STAGE_BODY_EXPECTED.bytes && a.limit<=65536
     && a.expected_version===GF_STAGE_BODY_EXPECTED.version,
     "one_exact_version_bound_whole_report_chunk");
  } else if(op.tool==="file_info") {
   gfNeed(s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted!==true
     && gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)
     && Object.keys(a).sort().join(",")==="host,path"
     && a.path===GF_STAGE_RESULT_PATH,"one_exact_newly_owned_stage_result_info");
  } else if(op.tool==="process_status") {
   gfNeed(a.job_id===s.job,"same_original_job_only");
   gfNeed(Object.keys(a).sort().join(",")==="host,job_id","exact_status_arguments");
  } else {
   gfNeed(op.tool==="process_read" && a.job_id===s.job
     && Object.keys(a).sort().join(",")==="host,job_id,limit,stderr_offset,stdout_offset"
     && a.limit===16384 && a.stdout_offset===s.nextStdout
     && a.stderr_offset===s.nextStderr,"original_stream_cursors_and_cap");
  }
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id && q.limit===gfBuildLogPageBytes(s)
   && q.offset===s.activeObserver.nextPageOffset && !s.activeObserver.eof,
   "same_closed_original_operation_next_page");
 } else throw new Error("closed_native_tool_set");
}
async function gfPrepareOne({callKey,kind,requestRaw}) {
 const s=gfState();
 gfNeed(/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey) && !s.calls[callKey],"fresh_call_record");
 const q=JSON.parse(requestRaw); // Public exact request, no native response.
 gfValidateRequest(s,kind,q,requestRaw);
 const requestPin=gitBlobMeta(requestRaw);
 const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",
  callKey,kind,request:requestPin,
  rootGo:(s.buildLogsBodyGO?.whole===true
    && ((kind==="operation_start" && q.operation.tool==="binary_read")
      || s.activeObserver?.tool==="binary_read")) ? s.buildLogsBodyGO.pin
    : (s.buildLogsInfoGO?.whole===true
    && ((kind==="operation_start" && q.operation.tool==="file_info")
      || s.activeObserver?.tool==="file_info")) ? s.buildLogsInfoGO.pin
    : ((kind==="operation_start" && q.operation.tool==="binary_read")
    || s.activeObserver?.tool==="binary_read") ? s.stageResultBodyGO.pin
    : ((kind==="operation_start" && q.operation.tool==="file_info")
      || s.activeObserver?.tool==="file_info") ? s.stageResultInfoGO.pin : s.goPin,
  originalJob:s.job,
  originalOperation:s.activeObserver?.id??null,maximumNativeCalls:1,
  nativeNotYetCalled:true,lossOfAcknowledgmentNeverGrantsReplay:true,
  localFirstExplicitlyReplacedByExactRootGO:true};
 const armed={...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,
  recovery:"Read exact original job/operation only; absence of later ACK is UNKNOWN."};
 s.pending=callKey;
 s.calls[callKey]={kind,requestRaw,requestPin,phase:"arming",called:false};
 gfSave(s);
 try {
  const archive=await archiveFlatPublicTextsOnce({
   key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"request.json":requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
          "armed.json":JSON.stringify(armed,null,2)+"\n"}});
  s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";gfSave(s);
  return {callKey,armedTree:archive.tree,request:requestPin,nativeCalled:false};
 } catch(error) {
  s.paused=true;s.calls[callKey].archiveFailure=String(error);gfSave(s);throw error;
 }
}
async function gfInvokePreparedOnce(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===callKey
  && c?.phase==="armed_whole" && c.armed?.whole===true && !c.called,
  "completed_external_arm_before_once_call");
 const q=JSON.parse(c.requestRaw);
 gfNeed(gfMetaEquals(c.requestRaw,c.requestPin),"armed_request_unchanged");
 c.called=true;c.phase="native_call_entered";s.nativeCallInFlight=true;
 if(c.kind==="process_start")s.startCalled=true;
 if(c.kind==="operation_start" && q.operation.tool==="file_info") {
  if(s.buildLogsInfoGO?.whole===true)s.buildLogInfoCalled++;
  else s.stageResultInfoStarted=true;
 }
 if(c.kind==="operation_start" && q.operation.tool==="binary_read") {
  if(s.buildLogsBodyGO?.whole===true)s.buildLogBodyCalled++;
  else s.stageResultBodyStarted=true;
 }
 gfSave(s); // No await or second dispatch between this marker and the one call.
 let sdk;
 try {
  if(c.kind==="process_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_start(q);
  else if(c.kind==="operation_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q);
  else if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);
  else if(c.kind==="operation_result")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);
  else throw new Error("unreachable_closed_dispatch_kind");
 } catch(error) {
  const record={name:error.name,message:String(error.message),nativeCallMayHaveCompleted:true,
    originalRequest:c.requestPin,replayAllowed:false};
  store(GF_SLOT+":native_exception:"+callKey,record); // Preserve before any Git operation.
  s.nativeCallInFlight=false;s.paused=true;c.phase="transport_unknown";gfSave(s);
  try {c.exceptionArchive=await archiveFlatPublicTextsOnce({
   key:"gfx-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"transport-exception.json":JSON.stringify(record,null,2)+"\n"}});gfSave(s);}
  catch(archiveError){store(GF_SLOT+":exception_archive_error:"+callKey,String(archiveError));}
  throw error;
 }
 store(GF_SLOT+":original_sdk:"+callKey,sdk); // First operation on the returned SDK.
 recordGitSDKImmutable(GF_SLOT+":native:"+callKey,"original_return",sdk);
 s.nativeCallInFlight=false;c.phase="sdk_returned_uninterpreted";gfSave(s);
 const raw=JSON.stringify(sdk,null,2)+"\n";
 store(GF_SLOT+":original_sdk_raw:"+callKey,raw);
 c.sdkPin=gitBlobMeta(raw);gfSave(s);
 try {
  c.sdkArchive=await archiveFlatPublicTextsOnce({
   key:"gfs-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"original.sdk.json":raw}});
  c.phase="sdk_whole_uninterpreted";gfSave(s);
  return {callKey,sdk:c.sdkPin,tree:c.sdkArchive.tree,interpreted:false};
 } catch(error) {
  // The native response remains in store. Recover only the identical Git objects.
  s.paused=true;c.phase="sdk_git_archive_unresolved";c.archiveFailure=String(error);
  gfSave(s);throw error;
 }
}
function gfAcceptArchivedSDK(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && s.pending===callKey && !s.nativeCallInFlight
  && c?.phase==="sdk_whole_uninterpreted" && c.sdkArchive?.whole===true,
  "SDK_whole_before_isError");
 const raw=load(GF_SLOT+":original_sdk_raw:"+callKey);
 gfNeed(gfMetaEquals(raw,c.sdkPin),"whole_SDK_unchanged");
 const sdk=JSON.parse(raw); // Only now interpret isError/shape/native contents.
 try {
  gfNeed(sdk.isError!==true,"native_tool_error_preserved_stop");
  gfNeed(sdk.content?.length===1 && sdk.content[0].type==="text",
         "single_original_native_text");
  const nativeRaw=sdk.content[0].text;
  store(GF_SLOT+":native_raw:"+callKey,nativeRaw);
  const v=parseLosslessIntegers(nativeRaw),q=JSON.parse(c.requestRaw);
  if(c.kind==="process_start") {
   gfNeed(v.audit_recorded===true && v.local_record_pending===false && v.reused===false
    && v.launch?.ok===true && v.job?.host==="rog" && v.job.execution_mode==="operator"
    && v.job.idempotency_key===q.idempotency_key && v.job.executable===q.executable
    && v.job.cwd===q.cwd && JSON.stringify(v.job.args)===JSON.stringify(q.args)
    && v.job.request_digest===s.digest && gfIntegerText(v.job.request_fingerprint)===s.fingerprint
    && /^[a-z0-9-]{1,100}$/.test(v.job.id),"exact_unique_native_start_binding");
   s.job=v.job.id;
  } else if(c.kind==="operation_start") {
   gfNeed(/^[a-f0-9]{64}$/.test(v.operation_id) && v.tool_name===q.operation.tool
     && v.reused===false && v.automatic_retry===false,"original_observer_admission");
   s.activeObserver={id:v.operation_id,request:q,tool:v.tool_name,futureClosed:false,
    nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
  } else if(c.kind==="operation_status") {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.tool_name===a.tool && v.automatic_retry===false,
          "same_original_status");
   if(v.async_state==="completed") {
    gfNeed(v.owned_future_active===false && v.result_state==="stored_observed"
      && v.payload_available===true,"completed_original_payload_available");
    a.futureClosed=true;
   } else gfNeed(v.async_state==="running" || v.async_state==="queued",
                 "unexpected_original_status_stop");
  } else {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.offset===q.offset && v.immutable_snapshot===true
    && v.payload_kind==="native_result"
    && v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
    && Number.isSafeInteger(v.total_bytes) && v.total_bytes>=0 && v.total_bytes<=1048576
    && /^[a-f0-9]{64}$/.test(v.result_sha256),"exact_original_immutable_payload");
   const b=unb64(v.data_base64);
   gfNeed(b.length<=gfBuildLogPageBytes(s) && b.length<=q.limit && v.next_offset===q.offset+b.length
     && v.next_offset<=v.total_bytes && v.eof===(v.next_offset===v.total_bytes)
     && (b.length>0||v.eof),"exact_original_page_extent");
   gfNeed(a.total===null || (a.total===v.total_bytes && a.digest===v.result_sha256),
          "one_original_payload_identity");
   a.total=v.total_bytes;a.digest=v.result_sha256;
   a.pages.push({offset:q.offset,next:v.next_offset,base64:v.data_base64,
                 originalSDK:c.sdkPin,nativeText:gitBlobMeta(nativeRaw)});
   a.nextPageOffset=v.next_offset;a.eof=v.eof;
  }
  c.nativePin=gitBlobMeta(nativeRaw);c.phase="accepted";
  s.pending=null;gfSave(s);
  return {callKey,nativeRaw,value:v,job:s.job,operation:s.activeObserver?.id??null,
          nativeCallInFlight:false};
 } catch(error) {
  s.paused=true;c.phase="native_interpretation_refused";c.interpretationFailure=String(error);
  gfSave(s);throw error;
 }
}
async function gfCloseOriginalObserver() {
 const s=gfState(),a=s.activeObserver;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && a?.futureClosed===true && a.eof,"closed_whole_original_observer_boundary");
 let bytes=[],next=0;
 for(const p of a.pages){gfNeed(p.offset===next,"page_continuity");bytes=bytes.concat(unb64(p.base64));next=p.next;}
 gfNeed(next===a.total,"complete_original_payload_length");
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 gfNeed(pin.bytes===a.total && pin.sha256===a.digest,"complete_original_payload_hash");
 // Persist the full immutable envelope before interpreting original SDK success.
 const archiveKey="gfc-"+a.id;
 let archive;
 try {
  archive=await archiveFlatPublicTextsOnce({key:archiveKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"payload.original.json":raw}});
 } catch(error) {
  s.paused=true;s.originalPayloadArchiveFailure=String(error);gfSave(s);throw error;
 }
 const p=parseLosslessIntegers(raw);
 try {
  gfNeed(p.resultType==="complete" && p.isError===false
    && p.content?.length===1 && p.content[0].type==="text","original_native_result_success");
  const nativeRaw=p.content[0].text,v=parseLosslessIntegers(nativeRaw);
  if(a.tool==="binary_read" && s.buildLogsBodyGO?.whole===true) {
   const n=GF_BUILD_LOG_RANGES[s.buildLogBodyNext],parts=s.buildLogParts[n?.stream];
   gfNeed(n && parts && s.buildLogBodyCalled===s.buildLogBodyNext+1
    && a.request.idempotency_key===n.idempotencyKey
    && v.path===n.path && v.version===n.version && v.size===n.bytes
    && v.offset===n.offset && v.next_offset===n.offset+n.limit && v.eof===n.eof
    && typeof v.data_base64==="string","exact_original_log_range_extent");
   const bytes=unb64(v.data_base64),chunkSHA=sha256Latin1(byteString(bytes));
   gfNeed(bytes.length===n.limit && chunkSHA===v.chunk_sha256
    && parts.reduce((sum,x)=>sum+x.bytes,0)===n.offset,"actual_chunk_bytes_hash_continuity");
   parts.push({index:n.index,offset:n.offset,bytes:bytes.length,base64:v.data_base64,
    chunkSHA256:chunkSHA,originalOperation:a.id,originalPayload:pin});
   if(n.eof) {
    let joined=[];for(const part of parts)joined=joined.concat(unb64(part.base64));
    gfNeed(joined.length===n.bytes && sha256Latin1(byteString(joined))===n.sha256,
     "complete_log_bytes_and_whole_SHA_before_UTF8");
    const bodyRaw=utf8Text(joined),bodyPin=gitBlobMeta(bodyRaw);
    gfNeed(bodyPin.bytes===n.bytes && bodyPin.sha256===n.sha256,"whole_log_UTF8_exact");
    store(GF_SLOT+":build_log_body_original:"+n.stream,bodyRaw);
    const bodyArchive=await archiveFlatPublicTextsOnce({
     key:"gflog-"+s.job+"-"+n.stream,
     repository:"TrillionniumFoundation/HeptaBao",
     texts:{[n.stream+".original.txt"]:bodyRaw}});
    s.buildLogBodies.push({stream:n.stream,path:n.path,version:n.version,body:bodyPin,
     wholeArchive:bodyArchive.tree,wholeReadback:bodyArchive.whole,
     originalOperations:parts.map(x=>x.originalOperation),semanticQualification:false});
   }
   s.buildLogBodyNext++;
  } else if(a.tool==="file_info" && s.buildLogsInfoGO?.whole===true) {
   const need=GF_BUILD_LOG_INFOS[s.buildLogInfoNext],md=v.metadata;
   const parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(need && s.buildLogInfoCalled===s.buildLogInfoNext+1
    && v.path===need.path && a.request.operation.arguments.path===need.path
    && Number.isSafeInteger(v.size) && v.size>0 && v.size<=need.maximumBytes
    && v.sha256===need.sha256 && v.mode===384
    && md?.metadata_platform==="linux" && md.mode===384
    && md.uid===1000 && md.gid===1000 && md.link_count===1
    && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
    && parts[2]===String(v.size),"exact_original_log_metadata_and_version");
   s.buildLogInfos.push({index:need.index,stream:need.stream,path:v.path,size:v.size,
    sha256:v.sha256,version:v.version,nativeText:gitBlobMeta(nativeRaw),originalOperation:a.id,
    full9Strings:[parts[0],parts[1],"1000","1000",String(32768|v.mode),"1",String(v.size),parts[3],parts[4]],
    regularFileFromNativeFileInfoContract:true,binaryReadAuthorized:false});
   s.buildLogInfoNext++;
  } else if(a.tool==="binary_read") {
   const need=GF_STAGE_BODY_EXPECTED;
   gfNeed(v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===0 && v.next_offset===need.bytes && v.eof===true
     && typeof v.data_base64==="string" && v.chunk_sha256===need.sha256,
     "whole_report_original_binary_extent");
   const bodyBytes=unb64(v.data_base64),bodyRaw=utf8Text(bodyBytes),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(bodyBytes.length===need.bytes && bodyPin.bytes===need.bytes
     && bodyPin.sha256===need.sha256,"whole_report_actual_bytes_SHA");
   store(GF_SLOT+":stage_result_body_original",bodyRaw);
   s.stageResultBody={path:need.path,version:need.version,body:bodyPin,
     originalOperation:a.id,metadataOperation:need.infoOperation,
     originalPayload:pin,semanticQualification:false};
  } else if(a.tool==="file_info") {
   const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(v.path===GF_STAGE_RESULT_PATH && Number.isSafeInteger(v.size)
     && v.size>0 && v.size<=GF_STAGE_RESULT_MAX_BYTES
     && v.sha256==="db0079589bd50c271486056283825ba1c3a415c19204f707ed4b5d1b786ec3b4" && v.mode===384
     && md?.metadata_platform==="linux" && md.mode===384
     && md.uid===1000 && md.gid===1000 && md.link_count===1
     && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
     && parts[2]===String(v.size),"fixed_report_content_metadata_and_version");
   s.stageResultInfo={path:v.path,size:v.size,sha256:v.sha256,version:v.version,
     nativeText:gitBlobMeta(nativeRaw),originalOperation:a.id,
     full9Strings:[parts[0],parts[1],"1000","1000",String(32768|v.mode),
       "1",String(v.size),parts[3],parts[4]],
     regularFileFromNativeFileInfoContract:true,
     binaryReadAuthorized:false};
  } else gfNeed(v.job_id===s.job,"original_job_native_result_binding");
  if(a.tool==="process_read") {
   for(const stream of ["stdout","stderr"]) {
    const row=v[stream],asked=a.request.operation.arguments[stream+"_offset"];
    gfNeed(row && row.offset===asked && Number.isSafeInteger(row.next_offset)
      && typeof row.text==="string" && typeof row.bytes_hex==="string"
      && /^[a-f0-9]*$/.test(row.bytes_hex),"lossless_original_stream_shape");
    const b=[];for(let i=0;i<row.bytes_hex.length;i+=2)b.push(parseInt(row.bytes_hex.slice(i,i+2),16));
    gfNeed(row.bytes_hex.length%2===0 && b.length<=16384 && row.next_offset===asked+b.length
      && utf8Text(b)===row.text && Number.isSafeInteger(row.size)
      && row.size>=row.next_offset && typeof row.eof==="boolean"
      && (!row.eof||row.next_offset===row.size),
      "lossless_original_stream_text_hex_extent");
    s[stream==="stdout"?"nextStdout":"nextStderr"]=row.next_offset;
   }
  }
  const original={id:a.id,tool:a.tool,payload:pin,payloadTree:archive.tree,
    nativeText:gitBlobMeta(nativeRaw),pages:a.pages.length,completedInactive:true};
  s.completedObservers.push(original);s.activeObserver=null;gfSave(s);
  store(GF_SLOT+":closed_native:"+a.id,nativeRaw);
  return {original,nativeRaw,value:v};
 } catch(error) {
  s.paused=true;gfSave(s);throw error;
 }
}
/* Recovery rule (not automatic):
 * If any Git mutation ACK is unclear, use its stored expectedTree/entries/texts
 * only for immutable Git GET and exact whole comparison. Never call create_tree
 * again. If a native ACK is unclear, keep the armed record UNKNOWN; never rerun
 * gfInvokePreparedOnce or create a new native key. Root directs same-ID/job reads.
 * A cache loss requires restoring the external armed/SDK objects and call map.
 * Initialization from an empty store must not replace such an earlier context.
 */


/* Git-only recovery, never a second mutation or native call. The caller retains
 * the original prepared-state map; it may inspect the returned completion and
 * request root review. This function does not unpause or dispatch anything. */
async function gfReconcileSameGitArchiveReadOnly(archiveKey) {
 const prefix="pure_git_once:"+archiveKey,prior=load(prefix);
 gfNeed(prior && prior.expectedTree && prior.entries && prior.texts,
        "original_git_admission_required_no_guessed_content");
 const treeSDK=await tools.mcp__codex_apps__github_fetch({
  url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"
      +prior.expectedTree+"?recursive=1"});
 recordGitSDKImmutable(prefix,"recovery_tree",treeSDK);
 store(prefix+":recovery_tree_sdk",treeSDK);
 gfNeed(treeSDK.isError!==true,"original_expected_tree_not_observed");
 const treeText=treeSDK.structuredContent?.content;
 gfNeed(typeof treeText==="string","original_tree_text");
 const tree=JSON.parse(treeText);
 const audit=gitTreeAudit(tree);
 gfNeed(audit.root_sha===prior.expectedTree && audit.leaf_count===prior.entries.length,
        "original_expected_tree_complete");
 const expected=new Map(prior.entries.map(x=>[x.path,x]));
 gfNeed(tree.tree.filter(x=>x.type==="blob").every(x=>expected.get(x.path)?.blob===x.sha
   && x.mode==="100644"),"original_exact_tree_members");
 const verified=[];
 for(const x of prior.entries) {
  const sdk=await tools.mcp__codex_apps__github_fetch_blob({
   repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:x.blob});
  recordGitSDKImmutable(prefix,"recovery_whole:"+x.path,sdk);
  store(prefix+":recovery_whole_sdk:"+x.path,sdk);
  gfNeed(sdk.isError!==true && typeof sdk.structuredContent?.content==="string",
         "original_blob_not_observed");
  const raw=sdk.structuredContent.content;
  gfNeed(raw===prior.texts[x.path] && gfMetaEquals(raw,x),"original_same_bytes_only");
  verified.push({...x,whole:true});
 }
 const record={tree:prior.expectedTree,entries:verified,count:verified.length,
  bytes:verified.reduce((a,x)=>a+x.bytes,0),whole:true,
  recoveryReadOnly:true,mutationRepeated:false,nativeCalled:false};
 store(prefix+":recovery_complete",record);
 return record;
}


/* The only invocation entry point. It always returns normally after retaining
 * failures, so a failed cell cannot roll back V8 state by an uncaught throw.
 * Internal functions may throw; they must only be invoked through gfRun.
 */
async function gfRun(action,args) {
 try {
  let value;
  if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);
  else if(action==="authorize_stage_result_info")value=gfAuthorizeStageResultInfoOnly(args);
  else if(action==="authorize_stage_result_body")value=gfAuthorizeStageResultBodyOnly(args);
  else if(action==="authorize_build_logs_info")value=gfAuthorizeBuildLogsInfoOnly(args);
  else if(action==="authorize_build_log_bodies")value=gfAuthorizeBuildLogBodiesOnly(args);
  else if(action==="prepare")value=await gfPrepareOne(args);
  else if(action==="invoke")value=await gfInvokePreparedOnce(args.callKey);
  else if(action==="accept")value=gfAcceptArchivedSDK(args.callKey);
  else if(action==="close_observer")value=await gfCloseOriginalObserver();
  else if(action==="git_readonly_reconcile")value=await gfReconcileSameGitArchiveReadOnly(args.archiveKey);
  else throw new Error("closed_gfRun_action");
  return {ok:true,action,value:value===undefined?null:value};
 } catch(error) {
  const record={schema:"heptabao.gitfirst.outer-caught-failure.r1",action,
   name:error?.name??"Error",message:String(error?.message??error),
   automaticRetry:false,newAdmissionAllowed:false,returnedNormally:true};
  try {
   const state=load(GF_SLOT);
   if(state){state.paused=true;state.outerFailure=record;store(GF_SLOT,state);}
   const raw=JSON.stringify(record,null,2)+"\n",pin=gitBlobMeta(raw);
   const key="gitfirst-failure-by-blob:"+pin.blob,old=load(key);
   if(old===undefined)store(key,raw);
   const history=load(GF_SLOT+":outer_failures")||[];
   history.push({ordinal:history.length+1,pin,immutableStoreKey:key});
   store(GF_SLOT+":outer_failures",history);
   store(GF_SLOT+":latest_outer_failure",record);
   return {ok:false,action,failure:record,pin};
  } catch(recordError) {
   store(GF_SLOT+":last_resort_caught_failure",
      {record,recordError:String(recordError?.message??recordError),newAdmissionAllowed:false});
   return {ok:false,action,failure:record,recordingIncomplete:true};
  }
 }
}
