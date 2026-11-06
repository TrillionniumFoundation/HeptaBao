function bindReadyJwtPkiControls({before,files,actualStageRaw,actualStagePin,rootQualificationPin,rootQualificationWhole,rootQualificationRaw},h,d) {
 function need(x,n){if(!x)throw Error(n);}
 need(rootQualificationWhole===true&&/^[a-f0-9]{40}$/.test(rootQualificationPin?.blob)&&/^[a-f0-9]{64}$/.test(rootQualificationPin?.sha256),"actual_root_stage_qualification_required");
 need(h.gitBlobMeta(actualStageRaw).blob===actualStagePin.blob&&h.gitBlobMeta(actualStageRaw).sha256===actualStagePin.sha256&&actualStagePin.bytes===27931,"whole_current_stage_body");
 const qual=h.parseLosslessIntegers(rootQualificationRaw);
 need(h.gitBlobMeta(rootQualificationRaw).blob===rootQualificationPin.blob&&qual.evidence_qualified===true&&qual.source_prepared===true&&qual.report?.blob===actualStagePin.blob&&qual.compile_executed===false&&qual.product_tests_executed===false,"exact_current_root_qualification_body");
 const stage=h.parseLosslessIntegers(actualStageRaw);
 need(stage.status==="prepared"&&stage.source_commit==="33b814c7034ec853151b1ff13e7529c83f65ea70"&&stage.source_tree==="b7f276f70e0da1a33306564f385ab7bc12fd44f6"&&stage.within_new_stage_deadline===true&&stage.compiler_started===false&&stage.rust_tests_executed===false,"only_current_qualified_source");
 const pins={runner:"5d0e1456e090404ab48e8684551ed19b61dd88cf",launcher:"6ffca443ea8ba24f52ac1b115ef28a6f191fd0e7",publisher:"7cd29794df32fcd9492e2ea9b1c676426f54eeb0"};
 const after={},replacements={};function one(x,a,b){need(x.split(a).length===2,"single_literal");return x.replace(a,b);}
 for(const name of Object.keys(pins)){need(h.gitBlobMeta(before[name]).blob===pins[name],"exact_prebound:"+name);replacements[name]=[["BINDING_READY = False","BINDING_READY = True"]];after[name]=one(before[name],...replacements[name][0]);}
 const readyFiles={"native_jwt_build.py":after.runner,"launch_native_jwt_build.py":after.launcher,"jwt-test-groups.public.json":files["jwt-test-groups.public.json"]};
 need(h.gitBlobMeta(readyFiles["jwt-test-groups.public.json"]).blob==="5d563b1c7a1b7070395f6d8a03b512ddb019fae0","groups_35153_exact_unchanged");
 for(const role of ["runner","launcher"]){const old=h.gitBlobMeta(before[role]),now=h.gitBlobMeta(after[role]);const a="        "+old.bytes+",\n        \""+old.sha256+"\"",b="        "+now.bytes+",\n        \""+now.sha256+"\"";after.publisher=one(after.publisher,a,b);replacements.publisher.push([a,b]);}
 const payload=JSON.stringify({schema:"heptabao.native-jwt-pki-build-control-inputs.v1",files:Object.fromEntries(Object.entries(readyFiles).map(([name,raw])=>[name,h.encodeBase64Bytes(h.utf8Bytes(raw))]))},null,2)+"\n";
 need(h.gitBlobMeta(payload).bytes<=262144,"original_publisher_stdin_cap");
 const diffs={};for(const name of Object.keys(after)){let reverse=after[name];for(const[a,b]of replacements[name].slice().reverse())reverse=one(reverse,b,a);need(reverse===before[name],"whole_inverse:"+name);diffs[name]=d.makeStrictUnified(before[name],after[name],name+".before.py",name+".after.py");need(d.applyStrictUnified(before[name],diffs[name]).text===after[name]&&d.applyStrictUnified(after[name],diffs[name],true).text===before[name],"strict_both_directions:"+name);}
 return {before,after,files:readyFiles,payload,replacements,diffs,pins:Object.fromEntries(Object.entries(after).map(([name,raw])=>[name,h.gitBlobMeta(raw)])),payloadPin:h.gitBlobMeta(payload),actualStage:actualStagePin,rootQualification:rootQualificationPin,Native:0,Cargo:0,needsSeparatePublisherGO:true,controlsPublication:null,buildRequest:null};
}
