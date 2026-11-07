/* SOURCE ONLY. Mechanically bind the two reviewed None constants and the
 * existing three journal literals after the exact original bundle transport.
 * This pure function neither fetches evidence nor calls Native or Git.
 * The caller/root must first qualify the producer + INFO + body chains.
 */
function bindMac4aSourceOnlyStage({sourceTemplate,canonicalBase64Text,transportRaw,bindings,baseJournal}) {
 const need=(value,code)=>{if(!value)throw Error(code);};
 const samePin=(raw,pin)=>pin&&JSON.stringify(gitBlobMeta(raw))===JSON.stringify(pin);
 const isPin=pin=>pin&&/^[0-9a-f]{40}$/.test(pin.blob)&&Number.isSafeInteger(pin.bytes)&&pin.bytes>0&&/^[0-9a-f]{64}$/.test(pin.sha256);
 const templatePin={"blob":"33d304b409630c9e2e87c5d24dd44b04e905ec29","bytes":23568,"sha256":"a4a9fd066c134625695740eff14a21e1dd65ce2e95db82a0c20a2860fda42489"};
 const journalPin={"blob":"0bcb0ae541da1865f788a26cdb4a884425c50cbd","bytes":19047,"sha256":"f74c58e06d949fe5e3aac9c9e7f33b3f68504ce9e6721bc59c3309c6a7c7424d"};
 need(samePin(sourceTemplate,templatePin)&&samePin(baseJournal,journalPin),"exact_reviewed_stage_and_journal");
 need(bindings?.schema==="heptabao.mac-successor4a.actual-bundle-bindings.v1"
   &&bindings.ready===true,"actual_bundle_binding_unresolved");
 const c=bindings.candidate,b=bindings.bundle;
 need(c?.commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"
   &&c.tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"
   &&c.parent==="5767739cd25e458ac052dc8d384019bab8688ae0","one_actual_candidate");
 need(bindings.producer?.host==="rog"
   &&bindings.producer.path==="/home/qian-qi/hb-4a49405b-src-20261106-r1/control/canonical-hb-4a49405b-from576.bundle"
   &&isPin(bindings.producer.report)&&isPin(bindings.producer.rootQualification)
   &&isPin(bindings.infoNative)&&isPin(bindings.transportRootQualification),"reviewed_actual_evidence_references_required");
 need(b&&Number.isSafeInteger(b.bytes)&&b.bytes>0&&b.bytes<=4*1024*1024
   &&/^[0-9a-f]{64}$/.test(b.sha256)&&/^[0-9a-f]{64}$/.test(b.headerSha256)
   &&Array.isArray(b.full9)&&b.full9.length===9
   &&b.full9.every(x=>typeof x==="string"&&/^(0|[1-9][0-9]*)$/.test(x))
   &&b.full9[6]===String(b.bytes)
   &&b.version===[b.full9[0],b.full9[1],b.full9[6],b.full9[7],b.full9[8]].join(":"),
   "actual_lossless_full9_version");
 need(/^[a-f0-9]{64}$/.test(bindings.infoOperation)
   &&Array.isArray(bindings.bodyOperations)&&bindings.bodyOperations.length>0
   &&new Set(bindings.bodyOperations).size===bindings.bodyOperations.length
   &&bindings.bodyOperations.every(id=>/^[a-f0-9]{64}$/.test(id)),
   "original_closed_operation_references");
 need(isPin(bindings.transport)&&isPin(bindings.base64)
   &&samePin(transportRaw,bindings.transport)&&samePin(canonicalBase64Text,bindings.base64),
   "whole_actual_transport_and_base64");
 need(typeof canonicalBase64Text==="string"&&canonicalBase64Text.length<=262144
   &&canonicalBase64Text.endsWith("\n")&&!canonicalBase64Text.slice(0,-1).includes("\n")
   &&!canonicalBase64Text.includes("\r"),"one_canonical_base64_line");
 const raw=unb64(canonicalBase64Text.slice(0,-1));
 need(raw.length===b.bytes&&sha256Latin1(byteString(raw))===b.sha256
   &&encodeBase64Bytes(raw)+"\n"===canonicalBase64Text,"whole_actual_bundle_bytes");
 const t=JSON.parse(transportRaw);
 need(t.schema==="heptabao.canonical-source-bundle-base64-transport.v1"
   &&t.encoding==="base64-with-one-terminal-LF"&&t.native_binary_body_observed===true
   &&t.path===bindings.producer.path&&t.version===b.version
   &&t.binary_bytes===b.bytes&&t.binary_sha256===b.sha256
   &&JSON.stringify(t.encoded_file)===JSON.stringify(bindings.base64)
   &&t.info_operation===bindings.infoOperation
   &&JSON.stringify(t.original_operations)===JSON.stringify(bindings.bodyOperations),
   "exact_actual_transport_manifest");
 const prefix=byteString(raw.slice(0,65536)),marker=prefix.indexOf("\n\n");
 need(marker>0&&byteString(raw.slice(marker+2,marker+6))==="PACK"
   &&sha256Latin1(byteString(raw.slice(0,marker+2)))===b.headerSha256,"actual_v2_header_whole");
 const lines=prefix.slice(0,marker).split("\n");
 need(lines.length===3&&lines[0]==="# v2 git bundle"
   &&lines[1].startsWith("-"+c.parent+" ")
   &&lines[2]===c.commit+" HEAD","sole576_prerequisite_and4a_HEAD");
 let source=sourceTemplate;
 function oneSource(a,z){need(source.split(a).length===2,"one_exact_source_binding");source=source.replace(a,z);}
 oneSource("CANONICAL_BUNDLE_BYTES = None\n","CANONICAL_BUNDLE_BYTES = "+b.bytes+"\n");
 oneSource("CANONICAL_BUNDLE_SHA256 = None\n","CANONICAL_BUNDLE_SHA256 = '"+b.sha256+"'\n");
 const sourcePin=gitBlobMeta(source);
 const sourceDiff=strictDiff(sourceTemplate,source,"stage.actual-bundle-binding.py");
 need(applyStrict(sourceTemplate,sourceDiff)===source&&applyStrict(source,sourceDiff,true)===sourceTemplate,
   "exact_two_constant_bidirectional_diff");
 const carrier=JSON.stringify({schema:"heptabao.final-mac-source-only-carrier.v1",
   canonical_bundle_base64:canonicalBase64Text.slice(0,-1)})+"\n",carrierPin=gitBlobMeta(carrier);
 need(carrierPin.bytes<=262144,"original_complete_carrier_cap");
 const keyPrefix="heptabao-4a49405b-mac-source-only-";
 const q={host:"mac",executable:"/opt/homebrew/bin/python3",
   args:["-I","-S","-B","-c",source,"--self-sha256",sourcePin.sha256,
     "--carrier-sha256",carrierPin.sha256,"--canonical-bundle-bytes",String(b.bytes),
     "--canonical-bundle-sha256",b.sha256],
   cwd:"/Volumes/T5/hepta-vnext-recovery-20261013",stdin:carrier,timeout_seconds:360,
   idempotency_key:keyPrefix+"20261106-r1-"+sourcePin.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(q,null,2)+"\n",requestPin=gitBlobMeta(requestRaw),binding=processStartBinding(q);
 let journal=baseJournal;
 function oneJournal(a,z){need(journal.split(a).length===2,"one_exact_journal_binding");journal=journal.replace(a,z);}
 oneJournal('const GF_SLOT = "final02b_mac_source_only_stage_gitfirst_r1";',
   'const GF_SLOT = "successor4a_mac_source_only_stage_gitfirst_r1";');
 oneJournal('const GF_REQUEST = {"blob":"bd3f20cc6390cc8519265142cf2fb8624cf87008","bytes":254446,"sha256":"21ca75b8e1ca736dd96f3e564a70e757dc487d758d216793af5b420c5d46c99e"};',
   "const GF_REQUEST = "+JSON.stringify(requestPin)+";");
 oneJournal("^heptabao-final02b-mac-source-only-ea096d7a-","^"+keyPrefix+sourcePin.sha256.slice(0,8)+"-");
 const journalDiff=strictDiff(baseJournal,journal,"stage.gitfirst.actual-binding.js");
 need(applyStrict(baseJournal,journalDiff)===journal&&applyStrict(journal,journalDiff,true)===baseJournal,
   "exact_three_journal_literals_bidirectional_diff");
 return {source,sourcePin,sourceDiff,carrier,carrierPin,requestRaw,requestPin,journal,
   journalPin:gitBlobMeta(journal),journalDiff,bindingsPin:gitBlobMeta(JSON.stringify(bindings,null,2)+"\n"),
   typed:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,
     canonical_bytes:gitBlobMeta(binding.canonical).bytes},
   NativeExecuted:false,MacStageGO:null};
}
