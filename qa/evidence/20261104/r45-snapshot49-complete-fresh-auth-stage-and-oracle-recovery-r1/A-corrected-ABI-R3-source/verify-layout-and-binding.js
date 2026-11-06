function verifyFixedBsdInfoGuardCorrection(input) {
 const checks=[],ck=(name,value)=>checks.push({name,pass:value===true}),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const expected={header:"718a69fcf5340f547893ed8dc85908f253c1ce81",donor:"6ca7a8debfe9d9a31d19d1237ca3e84176cc40f5",before:"873fd511a30f70bfeba0a661f13952e122e40d94"};
 ck("primary_header_whole",gitBlobMeta(input.appleHeader).blob===expected.header);
 ck("existing_ctypes_donor_whole",gitBlobMeta(input.donor).blob===expected.donor);
 ck("original_failed_source_whole",gitBlobMeta(input.before).blob===expected.before);
 const pyBlock=s=>{const n=s.indexOf("class BsdInfo(ctypes.Structure):\n");if(n<0)throw Error("fixed_BsdInfo_definition");const end=s.indexOf("\nclass ",n+1);return s.slice(n,end).trimEnd()+"\n";};
 const b=pyBlock(input.before),a=pyBlock(input.after),donor=pyBlock(input.donor);
 ck("BsdInfo_declaration_byte_exact_donor",b===donor&&a===b);
 ck("no_pack_or_alignment_override",!/_pack_|_align_|_layout_/.test(b));
 const prefix=b.match(/for name in \(([\s\S]*?)\)\]/);if(!prefix)throw Error("fixed_uint32_prefix");
 const pyFields=[...prefix[1].matchAll(/'([^']+)'/g)].map(m=>({name:m[1],type:"c_uint32",count:1}));
 for(const m of b.matchAll(/\('([^']+)', ctypes\.(c_char|c_uint32|c_int32|c_uint64)(?: \* (\d+))?\)/g))pyFields.push({name:m[1],type:m[2],count:m[3]?Number(m[3]):1});
 const hb=input.appleHeader.match(/struct proc_bsdinfo\s*\{([\s\S]*?)\n\};/);if(!hb)throw Error("fixed_primary_struct");
 const cFields=[];for(const line of hb[1].replace(/\/\*[\s\S]*?\*\//g,"").split("\n")) {
  const m=line.trim().match(/^(uint32_t|uid_t|gid_t|char|int32_t|uint64_t)\s+([A-Za-z0-9_]+)(?:\[([^\]]+)\])?;/);if(!m)continue;
  let count=1;if(m[3]){const x=m[3].replace(/\s/g,"");if(x==="MAXCOMLEN")count=16;else if(x==="2*MAXCOMLEN")count=32;else throw Error("unmodeled_array");}
  cFields.push({name:m[2],type:m[1],count});
 }
 const aliases=["pbi_flags","pbi_status","pbi_xstatus","pbi_pid","pbi_ppid","pbi_uid","pbi_gid","pbi_ruid","pbi_rgid","pbi_svuid","pbi_svgid","rfu_1","pbi_comm","pbi_name","pbi_nfiles","pbi_pgid","pbi_pjobc","e_tdev","e_tpgid","pbi_nice","pbi_start_tvsec","pbi_start_tvusec"];
 ck("22_primary_and_ctypes_fields",cFields.length===22&&pyFields.length===22);
 const sizes={c_uint32:[4,4],c_int32:[4,4],c_uint64:[8,8],c_char:[1,1],uint32_t:[4,4],uid_t:[4,4],gid_t:[4,4],int32_t:[4,4],uint64_t:[8,8],char:[1,1]};
 const layout=fields=>{let n=0,max=1;const rows=fields.map(f=>{const [width,align]=sizes[f.type];n=Math.ceil(n/align)*align;const r={...f,width,align,offset:n,bytes:width*f.count};n+=r.bytes;max=Math.max(max,align);return r;});return {rows,size:Math.ceil(n/max)*max,alignment:max};};
 const py=layout(pyFields),header=layout(cFields);
 for(let i=0;i<22;i++){ck("field_"+i+"_"+pyFields[i].name,aliases[i]===cFields[i].name&&py.rows[i].offset===header.rows[i].offset&&py.rows[i].bytes===header.rows[i].bytes&&py.rows[i].align===header.rows[i].align);}
 const offsets=Object.fromEntries(py.rows.map(x=>[x.name,x.offset]));
 ck("fixed_sizes_and_offsets",py.size===136&&header.size===136&&py.alignment===8&&offsets.pid===12&&offsets.ppid===16&&offsets.uid===20&&offsets.pgid===100&&offsets.ttydev===108&&offsets.birth_sec===120&&offsets.birth_usec===128);
 ck("independent_prefix_arithmetic",12*4+16+32===offsets.nfiles&&offsets.nfiles+4===offsets.pgid);
 const guard=s=>{const n=s.indexOf("need(sys.platform == 'darwin' and ctypes.sizeof(BsdInfo) == 136");const end=s.indexOf("'current_pid_exact_bsdinfo_abi')",n);if(n<0||end<0)throw Error("fixed_guard");const out={};for(const m of s.slice(n,end).matchAll(/BsdInfo\.([a-z_]+)\.offset == ([0-9]+)/g))out[m[1]]=Number(m[2]);return out;};
 const oldGuard=guard(input.before),newGuard=guard(input.after),oldMismatches=Object.keys(oldGuard).filter(k=>oldGuard[k]!==offsets[k]),newMismatches=Object.keys(newGuard).filter(k=>newGuard[k]!==offsets[k]);
 ck("old_guard_has_exactly_pgid_source_mismatch",same(oldMismatches,["pgid"])&&oldGuard.pgid===108&&offsets.ttydev===108);
 ck("corrected_guard_all_offsets_match_model",newMismatches.length===0&&same(Object.keys(newGuard),Object.keys(oldGuard)));
 ck("only_one_literal_change",input.before.split("BsdInfo.pgid.offset == 108").length===2&&input.after===input.before.replace("BsdInfo.pgid.offset == 108","BsdInfo.pgid.offset == 100"));
 ck("strict_source_forward",strictApplySource(input.before,input.sourceDiff).raw===input.after);
 ck("strict_source_reverse",strictApplySource(input.after,input.sourceReverse).raw===input.before);
 ck("strict_journal_forward",strictApplySource(input.journalBefore,input.journalDiff).raw===input.journalAfter);
 ck("strict_journal_reverse",strictApplySource(input.journalAfter,input.journalReverse).raw===input.journalBefore);
 const qb=JSON.parse(input.requestBefore),qa=JSON.parse(input.requestAfter);
 ck("exact_source_stdin",qa.stdin===input.after&&qb.stdin===input.before);
 const qbr={...qb},qar={...qa};delete qbr.stdin;delete qbr.idempotency_key;delete qar.stdin;delete qar.idempotency_key;
 ck("same_host_interpreter_cwd_args_timeout",same(qbr,qar)&&qa.timeout_seconds===60&&!Object.hasOwn(qa,"stdin_text"));
 const sha=gitBlobMeta(input.after).sha256;
 ck("fresh_exact_key",qa.idempotency_key==="heptabao-mac-current-home-pid-observation-"+sha.slice(0,8)+"-20261106-r3"&&qa.idempotency_key!==qb.idempotency_key);
 let expectedJournal=input.journalBefore.replace("owner_authbus_home_r2_current_pid_observation_gitfirst_r2","owner_authbus_home_r2_current_pid_observation_gitfirst_r3");
 const bp=gitBlobMeta(input.requestBefore),ap=gitBlobMeta(input.requestAfter);
 expectedJournal=expectedJournal.replace(bp.blob,ap.blob).replace(bp.sha256,ap.sha256).replace("bytes:"+bp.bytes,"bytes:"+ap.bytes).replace("heptabao-mac-current-home-pid-observation-a414b14b-","heptabao-mac-current-home-pid-observation-"+sha.slice(0,8)+"-");
 ck("journal_only_identity_bindings",input.journalAfter===expectedJournal);
 return {schema:"heptabao.pure-fixed-BsdInfo-source-layout-check.r3",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,model:{uint32Bytes:4,uint64Bytes:8,uidGidBytes:4,charBytes:1,MAXCOMLEN:16,nativeAlignmentModel:8,sourceOnlyNotCurrentKernelMeasurement:true},primaryHeader:gitBlobMeta(input.appleHeader),ctypesDonor:gitBlobMeta(input.donor),fieldRows:py.rows.map((r,i)=>({...r,primaryName:cFields[i].name,primaryType:cFields[i].type})),size:py.size,oldGuard,newGuard,oldMismatches,newMismatches,pythonExecuted:false,ctypesLoaded:false,libprocCalled:false,productOrSdkExecuted:false,newNativeCalls:0};
}
