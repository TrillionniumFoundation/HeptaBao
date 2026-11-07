function buildStage4a(I) {
 const c=JSON.parse(I.candidateRaw), edits=[];
 let after=I.before;
 function one(label,oldText,newText){if(after.split(oldText).length!==2)throw Error(label+":unique");after=after.replace(oldText,newText);edits.push({label,oldText,newText});}
 one("fresh-root", "ROOT = Path('/home/qian-qi/hb-5767739c-src-20261106-r1')", "ROOT = Path('/home/qian-qi/hb-4a49405b-src-20261106-r1')");
 one("candidate-commit","COMMIT = '5767739cd25e458ac052dc8d384019bab8688ae0'","COMMIT = '"+c.commit+"'");
 one("candidate-tree","TREE = '42477d622dcf96e1e2b0929fe9ecc6b7ba484740'","TREE = '"+c.tree+"'");
 one("sole-parent","PARENT = '02b90762b3d6cc8699cc88bffb6f76cb1f07e270'","PARENT = '"+c.parent+"'");
 one("prepend-one-parent","ANCESTRY = (\n","ANCESTRY = (\n    ('"+c.commit+"', '"+c.parent+"'),\n");
 one("history-report","'canonical_history_count': 3769","'canonical_history_count': 3770");
 one("ancestry-count","assert len(added) == 17 and","assert len(added) == 18 and");
 one("history-check","COMMIT).decode().strip() == '3769'","COMMIT).decode().strip() == '3770'");
 one("tracked-bytes","['tracked_bytes'] == 62553540","['tracked_bytes'] == 62553956");
 one("index-SHA","'20ff64f463eb63a45a6dda92a17f23e814503b77ca5325d1b2c4a0ee4f4a5423'","'"+c.fullLeafIndexSha256+"'");
 one("bundle-header-parameter","def canonical_bundle_header(raw):","def canonical_bundle_header(raw, prerequisite):");
 one("bundle-header-prerequisite","assert prerequisites == [BASE_COMMIT]","assert prerequisites == [prerequisite]");
 const start=after.indexOf("    canonical_path = CONTROL / 'canonical-hb-5767739c-from02b.bundle'\n");
 const end=after.indexOf("    assert freeze(SOURCE) == {'commit': COMMIT, 'tree': TREE, 'status': ''}\n",start);
 if(start<0||end<0)throw Error("bundle-original-block");
 const oldBlock=after.slice(start,end);
 let body=oldBlock.replace("CONTROL / 'canonical-hb-5767739c-from02b.bundle'","CONTROL / bundle_name")
   .replace("'HEAD', '^' + BASE_COMMIT","'HEAD', '^' + prerequisite")
   .replace("canonical_header = canonical_bundle_header(canonical_raw)","canonical_header = canonical_bundle_header(canonical_raw, prerequisite)")
   .replace("result['canonical_bundle'] =","result[result_key] =");
 body=body.replaceAll("stable_read(canonical_path, 4 * 1024 * 1024)","stable_read(canonical_path, bundle_remaining)");
 body=body.replace("    assert 0 < len(canonical_raw) <= 4 * 1024 * 1024\n","    assert 0 < len(canonical_raw) <= bundle_remaining\n    canonical_total_bytes += len(canonical_raw)\n");
 const loop="    canonical_total_bytes = 0\n    for bundle_name, prerequisite, result_key in (\n        ('canonical-hb-4a49405b-from576.bundle', PARENT, 'canonical_bundle'),\n        ('canonical-hb-4a49405b-from02b.bundle', BASE_COMMIT, 'canonical_x230_bundle'),\n    ):\n        bundle_remaining = 4 * 1024 * 1024 - canonical_total_bytes\n        assert bundle_remaining > 0\n"+body.split("\n").map(l=>l?"    "+l:l).join("\n")+"    result['canonical_bundle_total_bytes'] = canonical_total_bytes\n    result['canonical_bundle_total_cap_bytes'] = 4 * 1024 * 1024\n";
 one("two-fixed-bundles-shared-cap",oldBlock,loop);
 const request=JSON.parse(I.beforeRequestRaw);
 if(request.args[4]!==I.before)throw Error("before-source-request");
 request.args[4]=after;request.args[6]=gitBlobMeta(after).sha256;
 request.idempotency_key="heptabao-combined-4a49405b-rog-source-20261106-r1-"+gitBlobMeta(after).sha256.slice(0,8);
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=gitBlobMeta(requestRaw);
 let journal=I.beforeJournal;
 const oldPin=gitBlobMeta(I.beforeRequestRaw);
 for(const [oldText,newText] of [
 ["combined_5767739c_rog_source_gitfirst_r1","combined_4a49405b_rog_source_gitfirst_r1"],
 [oldPin.blob,requestPin.blob],[String(oldPin.bytes),String(requestPin.bytes)],[oldPin.sha256,requestPin.sha256],
 ["heptabao-combined-5767739c-rog-source-observe-r1-","heptabao-combined-4a49405b-rog-source-observe-r1-"]]){
  if(journal.split(oldText).length!==2)throw Error("journal-binding:"+oldText);
  journal=journal.replace(oldText,newText);
 }
 return {after,edits,requestRaw,requestPin,journal,binding:processStartBinding(request)};
}
