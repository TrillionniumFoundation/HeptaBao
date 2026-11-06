function bindFinalMacSourceOnlyStage({source,canonicalBase64Text,transportRaw,baseJournal}) {
 const sourceExpected={"blob":"b6a9190bc5856e42be2d8e750875675521ecf22d","bytes":25130,"sha256":"ea096d7a13c4501d4d39d7d953fb6fd35c49aad6051227884c06e179bc8db9fd"};
 const sourcePin=gitBlobMeta(source);
 if(JSON.stringify(sourcePin)!==JSON.stringify(sourceExpected))throw Error("exact_reviewed_stager_source");
 if(typeof canonicalBase64Text!=="string"||!canonicalBase64Text.endsWith("\n")
   ||canonicalBase64Text.slice(0,-1).includes("\n")||canonicalBase64Text.includes("\r"))
   throw Error("one_canonical_base64_line");
 const raw=unb64(canonicalBase64Text.slice(0,-1));
 if(raw.length!==171016 || sha256Latin1(byteString(raw))!=="069e0e07ef05dc6ec7f75407f8a06edd5efd53764833334fee74dcbf5719a800"
   ||encodeBase64Bytes(raw)+"\n"!==canonicalBase64Text)throw Error("whole_actual_bundle_bytes");
 const t=JSON.parse(transportRaw),encodedPin=gitBlobMeta(canonicalBase64Text);
 if(t.schema!=="heptabao.canonical-source-bundle-base64-transport.v1"
   ||t.encoding!=="base64-with-one-terminal-LF"||t.native_binary_body_observed!==true
   ||t.path!=="/home/qian-qi/hb-02b90762-src-20261106-r1/control/canonical-hb-02b90762-from495.bundle"
   ||t.version!=="66306:28477674:171016:1793989775788602563:1793989775789602574"
   ||t.binary_bytes!==raw.length||t.binary_sha256!=="069e0e07ef05dc6ec7f75407f8a06edd5efd53764833334fee74dcbf5719a800"
   ||JSON.stringify(t.encoded_file)!==JSON.stringify(encodedPin)
   ||t.info_operation!=="f157e690beab5b5213992c56db5edee70be14ed8954e1c3045cc012d104ffbb3"
   ||!Array.isArray(t.original_operations)||t.original_operations.length!==3
   ||new Set(t.original_operations).size!==3||!t.original_operations.every(id=>/^[a-f0-9]{64}$/.test(id)))
   throw Error("actual_transport_manifest_binding");
 const marker=byteString(raw.slice(0,65536)).indexOf("\n\n");
 if(marker<=0||byteString(raw.slice(marker+2,marker+6))!=="PACK"
   ||sha256Latin1(byteString(raw.slice(0,marker+2)))!=="bc421f87f1547daeef2cdd4ffce357d0eac193e380297296919658640be05ab5")
   throw Error("actual_v2_header_identity");
 const carrier=JSON.stringify({schema:"heptabao.final-mac-source-only-carrier.v1",canonical_bundle_base64:canonicalBase64Text.slice(0,-1)})+"\n";
 const carrierPin=gitBlobMeta(carrier);
 if(carrierPin.bytes>262144)throw Error("original_carrier_cap");
 const q={host:"mac",executable:"/opt/homebrew/bin/python3",
   args:["-I","-S","-B","-c",source,"--self-sha256",sourcePin.sha256,
     "--carrier-sha256",carrierPin.sha256,"--canonical-bundle-bytes","171016",
     "--canonical-bundle-sha256","069e0e07ef05dc6ec7f75407f8a06edd5efd53764833334fee74dcbf5719a800"],
   cwd:"/Volumes/T5/hepta-vnext-recovery-20261013",stdin:carrier,timeout_seconds:360,
   idempotency_key:"heptabao-final02b-mac-source-only-20261106-r1-"+sourcePin.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(q,null,2)+"\n",requestPin=gitBlobMeta(requestRaw),binding=processStartBinding(q);
 let journal=baseJournal;
 function one(a,b){if(journal.split(a).length!==2)throw Error("one_exact_journal_binding");journal=journal.replace(a,b);}
 one('const GF_SLOT = "owner_launchd_gitfirst_r1";',
     'const GF_SLOT = "final02b_mac_source_only_stage_gitfirst_r1";');
 one('const GF_REQUEST = {blob:"d14f62155b86924edd5632673d2e73832f7b0af5",\n bytes:76816,sha256:"ab9afbcbbdc150acd11ad9451e35e2785f8fe086d4a371c3a63d4cf0f2a087b4"};',
     "const GF_REQUEST = "+JSON.stringify(requestPin)+";");
 one("^heptabao-mac-owned-launchd-readonly-e573407b-","^heptabao-final02b-mac-source-only-"+sourcePin.sha256.slice(0,8)+"-");
 const diff=strictDiff(baseJournal,journal,"mac-source-only.gitfirst.js");
 if(applyStrict(baseJournal,diff)!==journal||applyStrict(journal,diff,true)!==baseJournal)throw Error("exact_journal_bidirectional_diff");
 return {sourcePin,carrier,carrierPin,requestRaw,requestPin,journal,journalPin:gitBlobMeta(journal),journalDiff:diff,
   typed:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,canonical_bytes:gitBlobMeta(binding.canonical).bytes},
   NativeExecuted:false,MacStageGO:null};
}
