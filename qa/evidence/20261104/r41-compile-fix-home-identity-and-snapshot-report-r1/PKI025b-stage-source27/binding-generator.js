function bindCompileFixSourceStage({baseSource,baseRequestRaw,commit,expectedTree,soleParent,trackedBytes,indexSha256},h) {
 function need(v,n){if(!v)throw Error(n);}
 function once(s,a,b){need(s.split(a).length===2,"one_literal:"+a);return s.replace(a,b);}
 need(/^[0-9a-f]{40}$/.test(commit)&&commit!=="33b814c7034ec853151b1ff13e7529c83f65ea70","actual_root_frozen_successor");
 need(expectedTree==="1d8160c9385f8053b9a683cc1834da0f912e2d37"&&soleParent==="33b814c7034ec853151b1ff13e7529c83f65ea70","two_leaf_tree_parent");
 need(trackedBytes===62297399&&indexSha256==="aa43f995605190e7f0f7b6215e17eb73ccd923ff53f54dfcf44ba0c89e70e02b","canonical_full_index");
 need(h.gitBlobMeta(baseSource).blob==="038e14fda7a776eb5909bfaa7152872c2f1d7add","original_actual_stager");
 need(h.gitBlobMeta(baseRequestRaw).blob==="1b3da82ecf429adc5d816a2ff2cb78810059ac90","original_actual_request");
 const root="/home/qian-qi/heptabao-native-jwt-pki-source-"+commit.slice(0,8)+"-20261106-r1";
 const replacements=[
 ['"""Stage the exact formatted native JWT and PKI source independently; no Cargo or product."""','"""Stage the exact native JWT and PKI compile-fix source independently; no Cargo or product."""'],
 ["ROOT = Path('/home/qian-qi/heptabao-native-jwt-pki-source-33b814c7-20261106-r1')","ROOT = Path('"+root+"')"],
 ["COMMIT = '33b814c7034ec853151b1ff13e7529c83f65ea70'","COMMIT = '"+commit+"'"],
 ["TREE = 'b7f276f70e0da1a33306564f385ab7bc12fd44f6'","TREE = '"+expectedTree+"'"],
 ["PARENT = '808e45d690f177ecb922e13d1ed19f7877156094'","PARENT = '"+soleParent+"'"],
 ["ANCESTRY = (\n","ANCESTRY = (\n    ('"+commit+"', '"+soleParent+"'),\n"],
 ["'stage_purpose': 'formatted_jwt_pki_source_for_separate_build_admission'","'stage_purpose': 'jwt_pki_compile_fix_source_for_separate_build_admission'"],
 ["'canonical_history_count': 3766","'canonical_history_count': 3767"],
 ["assert len(added) == 14 and set(added)","assert len(added) == 15 and set(added)"],
 ["assert git(SOURCE, 'rev-list', '--count', COMMIT).decode().strip() == '3766'","assert git(SOURCE, 'rev-list', '--count', COMMIT).decode().strip() == '3767'"],
 ["assert result['full_worktree']['tracked_bytes'] == 62297347","assert result['full_worktree']['tracked_bytes'] == "+trackedBytes],
 ["assert result['full_worktree']['full_leaf_index_sha256'] == '7a2ab1d97a5140120034276c0d21547ffa935867055a0c5af95f7f061f8f3df0'","assert result['full_worktree']['full_leaf_index_sha256'] == '"+indexSha256+"'"],
 ["canonical_path = CONTROL / 'canonical-native-jwt-pki-33b814c7-from495.bundle'","canonical_path = CONTROL / 'canonical-native-jwt-pki-"+commit.slice(0,8)+"-from495.bundle'"]
 ];
 let source=baseSource;for(const [a,b]of replacements)source=once(source,a,b);
 let inverse=source;for(const [a,b]of [...replacements].reverse())inverse=once(inverse,b,a);
 need(inverse===baseSource,"inverse_byte_exact");
 const q=JSON.parse(baseRequestRaw),carrierPin=h.gitBlobMeta(q.stdin);
 need(q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===360,"original_native_envelope");
 need(q.args.length===9&&q.args[4]===baseSource&&carrierPin.blob==="f9166bc801c5b10e12b77274f485d27d61cd499a"&&carrierPin.bytes===79951,"original_inline_and_carrier");
 const sourcePin=h.gitBlobMeta(source);q.args[4]=source;q.args[6]=sourcePin.sha256;
 q.idempotency_key="heptabao-native-jwt-pki-"+commit.slice(0,8)+"-rog-source-20261106-r1-"+sourcePin.sha256.slice(0,8);
 need(q.idempotency_key.length<=128&&q.args[8]===carrierPin.sha256,"key_carrier_binding");
 const requestRaw=JSON.stringify(q,null,2)+"\n";
 return {source,sourcePin,request:q,requestRaw,requestPin:h.gitBlobMeta(requestRaw),carrier:q.stdin,carrierPin,replacements,root,sourcePath:root+"/source",resultPath:root+"/control/stage-result.public.json",commit,tree:expectedTree,soleParent,trackedBytes,indexSha256,newCommitsFrom495:15,canonicalHistoryCount:3767,sourceDefinitionsMustRemainByteIdentical:20,budgets:{stage:300,git:90,clone:180,outer:360,stdin:262144,cleanupTerm:5,cleanupKill:5},Runtime:false};
}
