function bindActualJwtPkiBuild({bodies,infos,bodyTexts,closedObservers,template,journalBefore},h,correctBinding,d) {
 function need(v,k){if(!v)throw Error(k);}
 need(Array.isArray(bodies)&&bodies.length===4&&Array.isArray(infos)&&infos.length===4,"all_four_actual_bodies_required");
 const contentPins=[
 ["f8b36c8adccb493dfc6aa507856150ce8a6a764d",30397,"d76b3d392c20bf4a7bbb7e8d8ea69abdfe3bb11f71a35075ba26ab948e778a50"],
 ["419a805247448d46180890fb9cdd69c2832d4811",38565,"efec176c08804a91adfd0160cdc092fad879d64ff594debe2fffe8008488d00c"],
 ["5d563b1c7a1b7070395f6d8a03b512ddb019fae0",19789,"35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869"],
 ["9fff12f23126ba08a5f4a3e137faefcdf689c1af",1854,"30cd7315341a685f3bf0b95b3938dd12e717d880ded7161d462f14e75c0eac61"]];
 for(let i=0;i<4;i++){
  const b=bodies[i],m=infos[i],p=h.gitBlobMeta(bodyTexts[i]),o=closedObservers.find(x=>x.id===b.originalOperation);
  need(b.index===i&&m.index===i&&b.path===m.path&&b.version===m.version&&b.metadataOperation===m.originalOperation
   &&o?.tool==="binary_read"&&o.completedInactive===true&&p.blob===contentPins[i][0]
   &&p.bytes===contentPins[i][1]&&p.sha256===contentPins[i][2]
   &&b.body.blob===p.blob&&m.sha256===p.sha256&&m.size===p.bytes,"exact_actual_published_body:"+i);
 }
 const receipt=h.parseLosslessIntegers(bodyTexts[3]),groups=JSON.parse(bodyTexts[2]);
 need(receipt.schema==="heptabao.native-jwt-pki-build-controls-inert.v1"&&receipt.status==="prepared"&&receipt.python_compile_only===true
  &&receipt.stdin_bytes===118531&&receipt.stdin_sha256==="712b5ce14c6920fa35935109be44d1ca027a8d02259fbf172b783efa8ec6c08d"
  &&["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"].every(k=>receipt[k]===false),"actual_receipt_prepared_compile_only");
 need(receipt.files.length===3&&receipt.files.every((row,i)=>row.path===infos[i].path&&row.bytes===infos[i].size&&row.sha256===infos[i].sha256
  &&row.mode==="0600"&&row.publication==="created"&&JSON.stringify(row.identity.map(x=>typeof x==="number"?String(x):x.$exactInteger))===JSON.stringify(infos[i].full9Strings)),"actual_receipt_independent_full9_match");
 need(new Set(groups.flatMap(x=>x.tests)).size===149&&groups.reduce((n,x)=>n+x.tests.length,0)===166,"original149_166");
 need(template.ready===false&&template.requestShape.args.length===18&&template.requestShape.args[17]===null,"original_unbound_build_template");
 const request=JSON.parse(JSON.stringify(template.requestShape));request.args[17]=contentPins[3][2];
 need(request.host==="rog"&&request.executable==="/usr/bin/python3"&&request.cwd==="/home/qian-qi"&&request.timeout_seconds===12000
  &&request.args[3]==="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/launch_native_jwt_build.py","original_build_interface");
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=h.gitBlobMeta(requestRaw),binding=correctBinding(request);
 need(h.gitBlobMeta(journalBefore).blob==="510a46984f60f31458cdcb95dc7f36b9b83454ce","exact_original_generic_journal");
 const replacements=[
 ["jwt_pki_025b05a3_build_controls_inert_gitfirst_r2","jwt_pki_025b05a3_build149_gitfirst_r2"],
 ["4ef00cfaaeb93943db9aa93d7f3a864db4ec12ea",requestPin.blob],["124154",String(requestPin.bytes)],
 ["4730410592ed61808d13341ef5dd4f22f4317ff2947c27697f258b9fea56fb07",requestPin.sha256],
 ["heptabao-native-jwt-pki-025b05a3-controls-observe-r2-","heptabao-native-jwt-pki-025b05a3-build149-observe-r2-"]];
 let journal=journalBefore;
 for(const[a,b]of replacements){need(journal.split(a).length===2,"single_exact_build_literal");journal=journal.replace(a,b);}
 const diff=d.makeStrictUnified(journalBefore,journal,"journal.inert.before.js","journal.build.after.js");
 need(d.applyStrictUnified(journalBefore,diff).text===journal&&d.applyStrictUnified(journal,diff,true).text===journalBefore,"strict_build_journal_binding");
 return {request,requestRaw,requestPin,typedBinding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,canonicalBytes:h.gitBlobMeta(binding.canonical).bytes},
 journalBefore,journal,journalPin:h.gitBlobMeta(journal),replacements,diff,diffPin:h.gitBlobMeta(diff),slot:"jwt_pki_025b05a3_build149_gitfirst_r2",
 actualBodyPins:bodyTexts.map(x=>h.gitBlobMeta(x)),requiresExactRootBuildGO:true,Native:0,Cargo:0};
}
