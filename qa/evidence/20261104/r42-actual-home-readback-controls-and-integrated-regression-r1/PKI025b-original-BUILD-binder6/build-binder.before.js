function bindActualJwtPkiBuild({bodies,infos,bodyTexts,closedObservers,template,journalBefore},h,correctBinding,d) {
 function need(v,k){if(!v)throw Error(k);}
 need(Array.isArray(bodies)&&bodies.length===4&&Array.isArray(infos)&&infos.length===4,"all_four_actual_bodies_required");
 const contentPins=[
 ["cf25a5f2a3f75b63374f99f7b0245ecfdf2c13e9",30397,"023f6f3ad71b8909a46da632767044de44ec2ea6fcb11692a2160e2cec518add"],
 ["4c90f7e5dba00636f7e08840e892db679c7d2600",38565,"5d639fbde4aa09663be694d9322bc4f598f4cd9594f9a3c09c61c21013b98056"],
 ["5d563b1c7a1b7070395f6d8a03b512ddb019fae0",19789,"35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869"],
 ["514dda8c5a69d4ed96123d788e4e1cf672e6a0ef",1854,"f1e1f3a2576fcb2ecd05cdb9b8f4fbebd6bb849eddb48536eb5c66ed5be109e2"]];
 for(let i=0;i<4;i++){
  const b=bodies[i],m=infos[i],p=h.gitBlobMeta(bodyTexts[i]),o=closedObservers.find(x=>x.id===b.originalOperation);
  need(b.index===i&&m.index===i&&b.path===m.path&&b.version===m.version&&b.metadataOperation===m.originalOperation
   &&o?.tool==="binary_read"&&o.completedInactive===true&&p.blob===contentPins[i][0]
   &&p.bytes===contentPins[i][1]&&p.sha256===contentPins[i][2]
   &&b.body.blob===p.blob&&m.sha256===p.sha256&&m.size===p.bytes,"exact_actual_published_body:"+i);
 }
 const receipt=h.parseLosslessIntegers(bodyTexts[3]),groups=JSON.parse(bodyTexts[2]);
 need(receipt.schema==="heptabao.native-jwt-pki-build-controls-inert.v1"&&receipt.status==="prepared"&&receipt.python_compile_only===true
  &&receipt.stdin_bytes===118531&&receipt.stdin_sha256==="7afbd432447feee5fbee147c747baa6f084f8286aaea0b427bc19952f83cdf44"
  &&["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"].every(k=>receipt[k]===false),"actual_receipt_prepared_compile_only");
 need(receipt.files.length===3&&receipt.files.every((row,i)=>row.path===infos[i].path&&row.bytes===infos[i].size&&row.sha256===infos[i].sha256
  &&row.mode==="0600"&&row.publication==="created"&&JSON.stringify(row.identity.map(x=>typeof x==="number"?String(x):x.$exactInteger))===JSON.stringify(infos[i].full9Strings)),"actual_receipt_independent_full9_match");
 need(new Set(groups.flatMap(x=>x.tests)).size===149&&groups.reduce((n,x)=>n+x.tests.length,0)===166,"original149_166");
 need(template.ready===false&&template.requestShape.args.length===18&&template.requestShape.args[17]===null,"original_unbound_build_template");
 const request=JSON.parse(JSON.stringify(template.requestShape));request.args[17]=contentPins[3][2];
 need(request.host==="rog"&&request.executable==="/usr/bin/python3"&&request.cwd==="/home/qian-qi"&&request.timeout_seconds===12000
  &&request.args[3]==="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/launch_native_jwt_build.py","original_build_interface");
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=h.gitBlobMeta(requestRaw),binding=correctBinding(request);
 need(h.gitBlobMeta(journalBefore).blob==="d61f0eb0d9773af4f7808f2a850d2ae325cea989","exact_original_generic_journal");
 const replacements=[
 ["jwt_pki_33b814c7_build_controls_inert_gitfirst_r1","jwt_pki_33b814c7_build149_gitfirst_r1"],
 ["b304be2ede7fccc0c7013e7b2974d2637a7f7667",requestPin.blob],["124154",String(requestPin.bytes)],
 ["b3982988fe15b71e804524b13c1d5e5ac5b462930446ef492e3f65585dac9e03",requestPin.sha256],
 ["heptabao-native-jwt-pki-33b814c7-controls-observe-r1-","heptabao-native-jwt-pki-33b814c7-build149-observe-r1-"]];
 let journal=journalBefore;
 for(const[a,b]of replacements){need(journal.split(a).length===2,"single_exact_build_literal");journal=journal.replace(a,b);}
 const diff=d.makeStrictUnified(journalBefore,journal,"journal.inert.before.js","journal.build.after.js");
 need(d.applyStrictUnified(journalBefore,diff).text===journal&&d.applyStrictUnified(journal,diff,true).text===journalBefore,"strict_build_journal_binding");
 return {request,requestRaw,requestPin,typedBinding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,canonicalBytes:h.gitBlobMeta(binding.canonical).bytes},
 journalBefore,journal,journalPin:h.gitBlobMeta(journal),replacements,diff,diffPin:h.gitBlobMeta(diff),slot:"jwt_pki_33b814c7_build149_gitfirst_r1",
 actualBodyPins:bodyTexts.map(x=>h.gitBlobMeta(x)),requiresExactRootBuildGO:true,Native:0,Cargo:0};
}
