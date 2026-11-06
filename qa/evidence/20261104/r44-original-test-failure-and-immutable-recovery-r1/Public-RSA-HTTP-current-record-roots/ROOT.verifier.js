function rootQualifyPublicRsa(f){
 const p=f.packet,r=JSON.parse(p.raw["PROVENANCE.public.json"]),jwk=JSON.parse(p.raw["PUBLIC-JWK.original-values.json"]),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),checks=[],ck=(name,pass)=>checks.push({name,pass:!!pass});
 ck("whole_original_public_key7",p.audit.whole&&p.audit.files===7);
 const clean=f.rootExcerpt.replace(/^L[0-9]+: /gm,"");
 const object=JSON.parse(clean.replace(/"n":\s*"([\s\S]*?)"/,(_m,n)=>'"n":"'+n.replace(/\s/g,"")+'"'));
 ck("root_primary_A1_public_parameters_exact",eq(object,jwk)&&Object.keys(object).join(",")==="kty,n,e,alg,kid"&&object.kty==="RSA"&&object.alg==="RS256");
 function encodeBase64Bytes(data){const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let out="";for(let i=0;i<data.length;i+=3){const a=data[i],b=data[i+1],c=data[i+2],v=(a<<16)|((b||0)<<8)|(c||0);out+=chars[(v>>>18)&63]+chars[(v>>>12)&63]+(b===undefined?"=":chars[(v>>>6)&63])+(c===undefined?"=":chars[v&63]);}return out;}
 const derive=new Function("unb64","encodeBase64Bytes","gitBlobMeta",p.raw["derive.source.js"]+"\nreturn derivePublicRsaSpki;")(unb64,encodeBase64Bytes,gitBlobMeta);
 const actual=derive(jwk);
 ck("author_derivation_exact_reproduced",eq(actual,JSON.parse(p.raw["derive.actual.json"])));
 ck("PEM_451_whole_exact",actual.pem===p.raw["PUBLIC-KEY.pem"]&&eq(gitBlobMeta(actual.pem),r.actualPureDerivation.pem)&&gitBlobMeta(actual.pem).bytes===451);
 const lines=actual.pem.trimEnd().split("\n"),der=unb64(lines.slice(1,-1).join(""));
 ck("strict_PEM_frame_and_DER294",lines[0]==="-----BEGIN PUBLIC KEY-----"&&lines.at(-1)==="-----END PUBLIC KEY-----"&&lines.slice(1,-2).every(x=>x.length===64)&&der.length===294);
 function tlv(offset,limit){const tag=der[offset++];let size=der[offset++];if(size>=128){const k=size&127;if(k<1||k>2||der[offset]===0)throw Error("DER length");size=0;for(let i=0;i<k;i++)size=256*size+der[offset++];if(size<128)throw Error("nonminimal");}const end=offset+size;if(end>limit)throw Error("DER bound");return {tag,begin:offset,end,body:der.slice(offset,end)};}
 const seq=tlv(0,der.length),alg=tlv(seq.begin,seq.end),bits=tlv(alg.end,seq.end);
 ck("outer_sequence_algorithm_and_bitstring",seq.tag===48&&seq.end===der.length&&alg.tag===48&&bits.tag===3&&bits.end===seq.end&&bits.body[0]===0);
 const oid=tlv(alg.begin,alg.end),nil=tlv(oid.end,alg.end);
 ck("rsaEncryption_oid_and_NULL_exact",oid.tag===6&&oid.body.join(",")==="42,134,72,134,247,13,1,1,1"&&nil.tag===5&&nil.body.length===0&&nil.end===alg.end);
 const rsa=tlv(bits.begin+1,bits.end),n=tlv(rsa.begin,rsa.end),e=tlv(n.end,rsa.end),nraw=n.body.slice(1);
 ck("PKCS1_canonical270_and_two_positive_integers",rsa.tag===48&&rsa.end===bits.end&&rsa.end-(bits.begin+1)===270&&n.tag===2&&e.tag===2&&e.end===rsa.end&&n.body.length===257&&n.body[0]===0&&nraw[0]>=128&&e.body.join(",")==="1,0,1");
 const n64=encodeBase64Bytes(nraw).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
 ck("modulus2048_and_exponent65537_roundtrip",nraw.length===256&&(nraw.at(-1)&1)===1&&n64===jwk.n&&jwk.e==="AQAB"&&BigInt("0x"+nraw.map(x=>x.toString(16).padStart(2,"0")).join("")).toString(2).length===2048);
 ck("public_config_only_no_runtime_parse_claim",r.runtimeParseObserved===false&&r.NativeCalls===0);
 return {schema:"heptabao.root.public-RSA-SPKI-source-qualification.r44",pass:checks.every(x=>x.pass),checks:checks.length,results:checks,packet:p.audit.tree,primary_source:"https://www.rfc-editor.org/rfc/rfc7517.txt",section:"Appendix A.1, public RSA example only",root_excerpt:gitBlobMeta(f.rootExcerpt),pem:gitBlobMeta(actual.pem),DER_bytes:294,RSA_bits:2048,exponent:65537,qualification:"Pure public derivation and independent DER parsing; runtime OpenSSL/OpenBao parsing remains pending",private_key_used:false,new_HTTP_requests:0,product_tests:0,root_Runtime_calls:0};
}
function rootReviewHttpComponent(f){
 const p=f.packet,plan=JSON.parse(p.raw["PLAN.public.json"]),s=p.raw["component.py"],obs=p.raw["observer.original.py"],checks=[],ck=(name,pass)=>checks.push({name,pass:!!pass}),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 ck("whole_component3",p.audit.whole&&p.audit.files===3);
 ck("component_and_original_observer_exact",eq(gitBlobMeta(s),plan.component)&&eq(gitBlobMeta(obs),plan.observer)&&obs===f.originalObserver);
 ck("unchanged_real_run_original_pki12_routing",s.includes("observer.run_original_pki12(suite, calls)")&&!s.includes("def run_original_pki12("));
 ck("four_classes_eight_variants_source",plan.classes.length===4&&plan.variants===8&&s.includes('("precheck_without_append", (), None)')&&s.includes('("wrong_case_only", (("pki.other_case", 409),), None)')&&["null","400","403","404","405"].every(x=>s.includes('"one_matching_'+x+'"'))&&s.includes('"multiple_matching"'));
 ck("stale_same_case_418_history_and_wrong_case_429",s.includes('"status": 418')&&s.includes('"status": 429')&&s.includes("calls.records[:2] != prior_records"));
 ck("original_exception_object_and_single_routing",s.includes("if error is not failure:")&&s.includes("if not propagated or original_calls or suite.pki_cases_calls != 1:")&&s.includes("if calls.invocations != 1"));
 ck("finally_restores_original_suite_call",s.includes("finally:\n            if suite.call is not original_call:"));
 ck("exact_case_local_record_selector_in_original",obs.includes("record_start = len(calls.records)")&&obs.includes('calls.records[record_start:]')&&obs.includes('if row.get("case_id") == case')&&obs.includes('if len(new_records) == 1 else None'));
 ck("each_original_status_or_null_checked_exactly",s.includes('"http_status": expected_status')&&s.includes("if actual != expected:"));
 ck("no_Client_socket_fixture_or_subprocess_creation",!s.includes("Client(")&&!s.includes("subprocess.")&&!s.includes("socket.")&&!s.includes("start_oracle(")&&plan.HTTPRequests===0&&plan.productCases===0&&plan.testsExecuted===0);
 ck("source_identity_must_be_verified_by_future_caller",s.includes("verified_source_sha256 != OBSERVER_SOURCE_SHA256")&&s.includes(plan.observer.sha256));
 return {schema:"heptabao.root.HTTP-current-record-component-SOURCE-review.r44",pass:checks.every(x=>x.pass),checks:checks.length,results:checks,packet:p.audit.tree,component:plan.component,observer:plan.observer,planned_classes:4,planned_variants:8,actual_Python_tests_executed:0,actual_HTTP_requests:0,product_case_count:0,qualification:"Source review only; actual Python component execution pending",root_Runtime_calls:0};
}