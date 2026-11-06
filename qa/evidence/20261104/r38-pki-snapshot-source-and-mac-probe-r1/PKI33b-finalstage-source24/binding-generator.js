function bindFinalPkiSourceStage({baseSource,baseRequestRaw,commit,expectedTree,formatParent,trackedBytes,indexSha256},h) {
 function assert(v,c){if(!v)throw Error(c);}function once(s,a,b){assert(s.split(a).length===2,"single_literal:"+a);return s.replace(a,b);}
 assert(/^[0-9a-f]{40}$/.test(commit)&&commit!=="808e45d690f177ecb922e13d1ed19f7877156094","actual_child_commit");
 assert(expectedTree==="b7f276f70e0da1a33306564f385ab7bc12fd44f6"&&formatParent==="808e45d690f177ecb922e13d1ed19f7877156094","frozen_expected_tree_parent");
 assert(trackedBytes===62297347&&indexSha256==="7a2ab1d97a5140120034276c0d21547ffa935867055a0c5af95f7f061f8f3df0","fulltree_frozen_proof");
 const root="/home/qian-qi/heptabao-native-jwt-pki-source-"+commit.slice(0,8)+"-20261106-r1";
 const replacements=[
 ['"""Stage the exact unformatted native JWT source independently; no Cargo or product."""','"""Stage the exact formatted native JWT and PKI source independently; no Cargo or product."""'],
 ["ROOT = Path('/home/qian-qi/heptabao-native-jwt-source-e3afc157-20261106-r1')","ROOT = Path('"+root+"')"],
 ["COMMIT = 'e3afc157447d35c861f275a761b29da3e42aff8e'","COMMIT = '"+commit+"'"],
 ["TREE = '5497775d9d473541e13e1603be8c893a3e27681b'","TREE = '"+expectedTree+"'"],
 ["PARENT = '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'","PARENT = '"+formatParent+"'"],
 ["ANCESTRY = (\n","ANCESTRY = (\n    ('"+commit+"', '"+formatParent+"'),\n    ('"+formatParent+"', 'e3afc157447d35c861f275a761b29da3e42aff8e'),\n"],
 ["'stage_purpose': 'unformatted_jwt_source_for_separate_formatter_admission'","'stage_purpose': 'formatted_jwt_pki_source_for_separate_build_admission'"],
 ["'canonical_history_count': 3764","'canonical_history_count': 3766"],
 ["assert len(added) == 12 and set(added)","assert len(added) == 14 and set(added)"],
 ["assert git(SOURCE, 'rev-list', '--count', COMMIT).decode().strip() == '3764'","assert git(SOURCE, 'rev-list', '--count', COMMIT).decode().strip() == '3766'"],
 ["assert result['full_worktree']['tracked_bytes'] == 62287650","assert result['full_worktree']['tracked_bytes'] == "+trackedBytes],
 ["assert result['full_worktree']['full_leaf_index_sha256'] == 'd545c2109362dc3f74d85ade2e66717d7b1ff9dd630842982f2ae3215e121dea'","assert result['full_worktree']['full_leaf_index_sha256'] == '"+indexSha256+"'"],
 ["canonical_path = CONTROL / 'canonical-native-jwt-e3afc157-from495.bundle'","canonical_path = CONTROL / 'canonical-native-jwt-pki-"+commit.slice(0,8)+"-from495.bundle'"]
 ];
 let source=baseSource;for(const [a,b]of replacements)source=once(source,a,b);
 let inverse=source;for(const[a,b]of [...replacements].reverse())inverse=once(inverse,b,a);
 assert(inverse===baseSource,"inverse_whole_original");
 const q=JSON.parse(baseRequestRaw),oldCarrier=h.gitBlobMeta(q.stdin);
 assert(q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===360,"base_native_envelope");
 assert(q.args.length===9&&q.args[4]===baseSource,"base_inline_source");
 const pin=h.gitBlobMeta(source);q.args[4]=source;q.args[6]=pin.sha256;
 q.idempotency_key="heptabao-native-jwt-pki-"+commit.slice(0,8)+"-rog-source-20261106-r1-"+pin.sha256.slice(0,8);
 assert(q.idempotency_key.length<=128&&q.args[8]===oldCarrier.sha256,"key_and_unchanged_carrier");
 const raw=JSON.stringify(q,null,2)+"\n";
 return {source,sourcePin:pin,requestRaw:raw,requestPin:h.gitBlobMeta(raw),carrier:q.stdin,carrierPin:oldCarrier,replacements,root,sourcePath:root+"/source",resultPath:root+"/control/stage-result.public.json",commit,tree:expectedTree,parent:formatParent,trackedBytes,indexSha256,newCommitsFrom495:14,canonicalHistoryCount:3766,sourceDefinitionsMustRemainByteIdentical:20,budgets:{stage:300,git:90,clone:180,outer:360,stdin:262144,cleanupTerm:5,cleanupKill:5},Runtime:false};
}