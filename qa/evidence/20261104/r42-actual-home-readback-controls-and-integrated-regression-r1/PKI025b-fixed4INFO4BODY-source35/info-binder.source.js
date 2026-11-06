function bind025bPublishedInfo4(input) {
 const {base,initialReadyJournal,ready,closedState,authorityRaw,streamsRaw,authorityObserver,streamsObserver,rootQualification,receiptDeriver}=input;
 if(!rootQualification?.whole||!/^[a-f0-9]{40}$/.test(rootQualification.pin?.blob||""))throw Error("whole_original_publication_root_required");
 if(closedState.pending!==null||closedState.activeObserver!==null||closedState.nativeCallInFlight||closedState.paused||!closedState.startCalled)throw Error("publisher_original_chain_not_closed");
 const authority=parseLosslessIntegers(authorityRaw),streams=parseLosslessIntegers(streamsRaw),publication=parseLosslessIntegers(streams.stdout.text);
 if(authority.job_id!==closedState.job||streams.job_id!==closedState.job||authority.exit_code!==0||!authority.output_complete||!authority.output_durable||!authority.terminal_publication_confirmed||authority.timed_out||authority.cancelled)throw Error("original_publisher_authority");
 if(!authorityObserver.completedInactive||!streamsObserver.completedInactive||gitBlobMeta(authorityRaw).blob!==authorityObserver.nativeText.blob||gitBlobMeta(streamsRaw).blob!==streamsObserver.nativeText.blob)throw Error("original_closed_native_identity");
 if(!streams.stdout.eof||!streams.stderr.eof||streams.stderr.text!==""||streams.stdout.offset!==0||streams.stderr.offset!==0||closedState.nextStdout!==gitBlobMeta(streams.stdout.text).bytes||closedState.nextStderr!==0)throw Error("complete_original_stdout_only");
 if(publication.status!=="prepared"||publication.python_compile_only!==true||publication.files?.length!==3||["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"].some(k=>publication[k]!==false))throw Error("compile_only_original_publisher");
 const names=["native_jwt_build.py","launch_native_jwt_build.py","jwt-test-groups.public.json"],root="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2";
 const integer=x=>Number.isSafeInteger(x)?String(x):(x&&Object.keys(x).join(",")==="$exactInteger"&&/^[0-9]+$/.test(x.$exactInteger)?x.$exactInteger:(()=>{throw Error("lossless_full9_required");})());
 const expected=publication.files.map((row,i)=>{
  const pin=ready.pins[names[i]];
  if(row.path!==root+"/"+names[i]||row.publication!=="created"||row.bytes!==pin.bytes||row.sha256!==pin.sha256||row.mode!=="0600"||!Array.isArray(row.identity)||row.identity.length!==9)throw Error("exact_created_control");
  const full9=row.identity.map(integer);
  if(full9[2]!=="1000"||full9[3]!=="1000"||full9[4]!=="33152"||full9[5]!=="1"||full9[6]!==String(pin.bytes))throw Error("publisher_regular_0600_singlelink");
  return {index:i,name:names[i],path:row.path,bytes:pin.bytes,sha256:pin.sha256,publisherFull9:full9};
 });
 const dump=new Function(receiptDeriver+"\nreturn dumpPublisherJSON;")();
 if(dump(publication,null)+"\n"!==streams.stdout.text)throw Error("lossless_actual_compact_stdout");
 const expectedReceipt=dump(publication,2)+"\n",rp=gitBlobMeta(expectedReceipt);
 expected.push({index:3,name:"inert-stage.result.public.json",path:root+"/inert-stage.result.public.json",bytes:rp.bytes,sha256:rp.sha256,publisherFull9:null});
 const requests=expected.map((row,i)=>JSON.stringify({idempotency_key:"heptabao-native-jwt-pki-025b05a3-controls-observe-r2-published-info"+i,operation:{tool:"file_info",arguments:{host:"rog",path:row.path}}},null,2)+"\n");
 const pins=requests.map(gitBlobMeta),prerequisites=[authorityObserver,streamsObserver].map(o=>({id:o.id,tool:o.tool,nativeText:o.nativeText})),stdout=gitBlobMeta(streams.stdout.text);
 let after=base;const changes=[];
 function replace(a,b){if(after.split(a).length!==2)throw Error("one_info_literal:"+a.slice(0,30));after=after.replace(a,b);changes.push([a,b]);}
 replace("jwt_pki_33b814c7_build_controls_inert_gitfirst_r1","jwt_pki_025b05a3_build_controls_inert_gitfirst_r2");
 replace(base.match(/const GF_REQUEST = \{[\s\S]*?\};/)[0],initialReadyJournal.match(/const GF_REQUEST = \{[\s\S]*?\};/)[0]);
 for(const[name,value]of [["GF_CONTROLS_INFO_REQUESTS",pins],["GF_CONTROLS_EXPECTED",expected],["GF_CONTROLS_INFO_PREREQUISITES",prerequisites],["GF_CONTROLS_STDOUT",stdout]])replace(base.match(new RegExp("const "+name+" = [^\\n]+;"))[0],"const "+name+" = "+JSON.stringify(value)+";");
 replace('s.job==="1a1b001e788-fc05-6d66"','s.job==="'+closedState.job+'"');
 replace("s.nextStdout===1444","s.nextStdout==="+stdout.bytes);
 replace("heptabao-native-jwt-pki-33b814c7-controls-observe-r1-","heptabao-native-jwt-pki-025b05a3-controls-observe-r2-");
 return {source:after,sourcePin:gitBlobMeta(after),changes,requests,requestPins:pins,expected,expectedReceipt,receiptPin:rp,stdout:streams.stdout.text,stdoutPin:stdout,prerequisites,rootQualification:rootQualification.pin,Runtime:false,authorization:"SOURCE_ONLY_PENDING_FIXED4_INFO_GO"};
}
