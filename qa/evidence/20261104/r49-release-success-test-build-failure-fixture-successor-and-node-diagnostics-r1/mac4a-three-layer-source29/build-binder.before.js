function bindFreshMacNormalBuild(input) {
 // Pure data binding only. Root must independently qualify these original observations and grant BUILD.
 function need(v,m){if(!v)throw Error(m);}
 function it(v){if(Number.isSafeInteger(v))return String(v);need(v&&Object.keys(v).join(",")==="$exactInteger"&&/^[0-9]+$/.test(v.$exactInteger),"lossless full9");return v.$exactInteger;}
 need(input.commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&input.tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740","frozen successor");
 const authority=parseLosslessIntegers(input.authorityNativeRaw),streams=parseLosslessIntegers(input.streamsNativeRaw);
 need(authority.job_id===streams.job_id&&authority.exit_code===0&&authority.output_complete===true
  &&authority.output_durable===true&&authority.terminal_publication_confirmed===true
  &&!authority.timed_out&&!authority.cancelled,"original publisher terminal");
 need(streams.stdout.eof===true&&streams.stdout.offset===0&&streams.stderr.eof===true
  &&streams.stderr.offset===0&&streams.stderr.next_offset===0&&streams.stderr.text==="","whole publisher stdout and empty stderr");
 const stdout=streams.stdout.text,bytes=utf8Bytes(stdout);
 need(bytes.length===streams.stdout.size&&streams.stdout.next_offset===bytes.length
  &&bytes.map(x=>x.toString(16).padStart(2,"0")).join("")===streams.stdout.bytes_hex,"lossless full original stdout");
 const result=parseLosslessIntegers(stdout),paths=input.paths;
 need(result.schema==="heptabao.mac-normal61-native-jwt-pki28-controls-inert.v1"&&result.status==="prepared"
  &&result.source_commit===input.commit&&result.source_tree===input.tree
  &&result.root_created===true&&result.control_created===true
  &&result.source_executed===false&&result.compiler_started===false&&result.service_started===false
  &&result.python_compile_only===true&&result.normal_total_test_count===61
  &&result.native_unique_test_count===28&&result.native_profile_execution_count===56
  &&result.selected_unique_test_count===89&&result.selected_profile_execution_count===117
  &&JSON.stringify(result.native_groups)===JSON.stringify([["native-jwt-pki-file28","file",28],["native-jwt-pki-default28","default",28]]),"exact inert publication");
 const rows=new Map(result.files.map(r=>[r.path,r]));
 need(result.files.length===3&&rows.size===3&&result.exact_test_count===44,"three controls and original groups");
 for(const [name,expected]of Object.entries(input.controlPins)){
  const row=rows.get(paths.control+"/"+name);need(row&&row.publication==="created"&&row.mode==="0600"
   &&row.bytes===expected.bytes&&row.sha256===expected.sha256&&row.identity.length===9,"published exact control");
  const identity=row.identity.map(it);
  need(identity[2]==="501"&&identity[4]==="33152"&&identity[5]==="1"&&identity[6]===String(expected.bytes),"safe actual control full9");
 }
 need(result.source_stage.path===paths.stageReport&&result.source_stage.bytes===input.stage.bytes
  &&result.source_stage.sha256===input.stage.sha256
  &&JSON.stringify(result.source_stage.identity.map(it))===JSON.stringify(input.stage.full9),"same qualified actual source report");
 const receipt=result.receipt;
 need(receipt.path===paths.receipt&&receipt.publication==="created"&&receipt.mode==="0600"
   &&Number.isSafeInteger(receipt.bytes)&&receipt.bytes>0&&receipt.bytes<=20000
   &&/^[0-9a-f]{64}$/.test(receipt.sha256)&&receipt.identity.length===9,"actual whole-readback receipt");
 const full9=receipt.identity.map(it);
 need(full9[2]==="501"&&full9[4]==="33152"&&full9[5]==="1"&&full9[6]===String(receipt.bytes),"safe actual receipt full9");
 const runner=input.controlPins["mac_normal_same_root_publication_build.py"],launcher=input.controlPins["launch_normal_same_root_publication.py"],groups=input.controlPins["normal-test-groups.public.json"];
 const q={host:"mac",executable:"/opt/homebrew/bin/python3",
  args:["-I","-S","-B",paths.control+"/launch_normal_same_root_publication.py","--host","mac",
   "--commit",input.commit,"--tree",input.tree,"--stage-sha256",input.stage.sha256,
   "--runner-sha256",runner.sha256,"--groups-sha256",groups.sha256,"--launcher-sha256",launcher.sha256,
   "--controls-sha256",receipt.sha256,"--controls-full9-json",JSON.stringify(full9)],
  cwd:paths.base,timeout_seconds:8280,
  idempotency_key:"heptabao-5767739c-mac-normal61-native28-fresh-20261106-r1-"+launcher.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(q,null,2)+"\n";
 return {requestRaw,request:gitBlobMeta(requestRaw),typed:processStartBinding(q),actualPublisherJob:authority.job_id,
  actualReceipt:{path:receipt.path,bytes:receipt.bytes,sha256:receipt.sha256,full9},
  rootBuildGORequired:true,NativeExecuted:false,actualMacBuildQualified:false};
}
