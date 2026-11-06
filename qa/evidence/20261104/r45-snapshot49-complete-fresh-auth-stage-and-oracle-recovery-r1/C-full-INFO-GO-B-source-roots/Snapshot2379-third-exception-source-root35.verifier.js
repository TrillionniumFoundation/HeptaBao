function rootFinalVerifierSuccessorSource(f2,f3,base,actual16){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta;
 ck("R2_before_root_qualified_SOURCE12",p(f2["verifier.before.js"]).blob==="6b10754735685ad3708c60f6baec369a3ac88359");
 const a=f2["verifier.before.js"],b=f2["verifier.UNBOUND.js"],c=f3["verifier.R2-actual-BODY16-binding.js"],d=f3["verifier.R3-UNBOUND.js"];
 ck("R2_strict_roundtrip",strictApply(a,f2["forward.diff"]).text===b&&strictApply(b,f2["reverse.diff"]).text===a);
 let replay=a;const edits2=JSON.parse(f2["structural-replacements.public.json"]);
 for(const e of edits2){const old=e.before??e.old,neu=e.after??e.new;ck("R2_unique_"+e.label,replay.split(old).length===2);replay=replay.replace(old,neu);}
 ck("R2_only13_structural_edits",edits2.length===13&&replay===b);
 ck("R2_literal_predecessor_exact",f3["verifier.R2-before-binding.js"]===b);
 ck("R2_literal_binding_roundtrip",strictApply(b,f3["R2-literal-binding.forward.diff"]).text===c&&strictApply(c,f3["R2-literal-binding.reverse.diff"]).text===b);
 const binding=JSON.parse(f3["BODY16.actual-binding.json"]);
 ck("BODY16_actual_binding_exact",JSON.stringify(binding)===JSON.stringify(actual16)&&c===b.replace("const BODY16_RECOVERY_BINDING = null;","const BODY16_RECOVERY_BINDING = "+JSON.stringify(binding)+";"));
 ck("R3_strict9_hunk_roundtrip",strictApply(c,f3["R3.forward.diff"]).text===d&&strictApply(c,f3["R3.forward.diff"]).hunks===9&&strictApply(d,f3["R3.reverse.diff"]).text===c);
 replay=c;const edits3=JSON.parse(f3["R3.structural-replacements.json"]);
 for(const e of edits3){ck("R3_unique_"+e.label,replay.split(e.before).length===2);replay=replay.replace(e.before,e.after);}
 ck("R3_only12_structural_edits",edits3.length===12&&replay===d);
 const vf=new Function(f3["pure-helper.original.js"]+"\n"+d+"\nreturn verifyFormatted23ActualEngine;")();
 for(const mode of ["history","final"]){let error=null;try{vf({state:{calls:{}},blobs:{}},mode);}catch(e){error=String(e.message);}ck("R3_unbound_refuses_"+mode,error==="body20_actual_recovery_binding_available");}
 return {schema:"heptabao.root-final-formatted23-third-exception-source.r1",passed:true,checks:rows.length,rows,R2SourceTree:"ea92d27e12a7b4540f275a9e5c422084ae60016a",R3SourceTree:"2267531443d68cfe073c92feb118a332d323721e",sourceOnly:true,actualThirdBindingPresent:false,targeted28Executed:false,final23Qualified:false,newNativeCalls:0};
}