function rootIdentityFixtureSource(f,leaves,guard,identity,serializer){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta;
 const expected={engine_identity:"crates/heptabao-server/src/engine_identity.rs",service_native_jwt_tests:"crates/heptabao-server/src/service_native_jwt_tests.rs"};
 for(const [stem,path] of Object.entries(expected)){
 const before=f[stem+".before.rs"],after=f[stem+".after.rs"],diff=f[stem+".strict.diff"],leaf=leaves.find(x=>x.path===path);
 ck(stem+"_exact_025b_base",p(before).blob===leaf.sha);
 const fw=strictApply(before,diff),rv=strictApply(after,diff,true);
 ck(stem+"_one_exact_hunk",fw.hunks===1&&rv.hunks===1&&fw.text===after&&rv.text===before);
 }
 const added="    /// Borrow the complete root Identity object without traversing live KV owners.\n    /// Missing root Identity is an error for the fixture, never an empty fallback.\n    #[cfg(test)]\n    pub(crate) fn fixture_root_identity(&self) -> Option<&impl serde::Serialize> {\n        self.namespaces.get(\"\").map(|state| &state.identity)\n    }\n\n";
 ck("engine_only_test_helper_added",f["engine_identity.after.rs"].replace(added,"")===f["engine_identity.before.rs"]&&f["engine_identity.after.rs"].split(added).length===2);
 const getParts=raw=>{const start=raw.indexOf("    fn snapshot(&self)"),end=raw.indexOf("    fn begin_login(",start);if(start<0||end<start)throw Error("snapshot_boundaries");return[raw.slice(0,start),raw.slice(start,end),raw.slice(end)];};
 const before=getParts(f["service_native_jwt_tests.before.rs"]),after=getParts(f["service_native_jwt_tests.after.rs"]);
 ck("all_source_outside_snapshot_exact",before[0]===after[0]&&before[2]===after[2]);
 ck("original_fifteen_test_names_unchanged",JSON.stringify([...f["service_native_jwt_tests.before.rs"].matchAll(/fn (native_jwt_[a-z0-9_]+)\(/g)].map(x=>x[1]))===JSON.stringify([...f["service_native_jwt_tests.after.rs"].matchAll(/fn (native_jwt_[a-z0-9_]+)\(/g)].map(x=>x[1]))&&[...f["service_native_jwt_tests.after.rs"].matchAll(/fn (native_jwt_[a-z0-9_]+)\(/g)].length===15);
 ck("same_bounded_owner_serializer",after[1].includes('owner_store::serialize_owner(identity).map_err(|_| "Identity projection")?')&&after[1].includes("owner_store::serialize_owner(&state.auth)")&&serializer.text.includes("secret_serde::to_vec(value, MAX_SERIALIZED_STATE_BYTES)"));
 ck("missing_root_explicit_failure",after[1].includes('.ok_or("root Identity absent")?')&&!after[1].includes("unwrap_or"));
 ck("whole_identity_taken_no_subset",after[1].includes('assert!(identity.is_object());')&&after[1].includes('"identity":identity.take()')&&after[1].includes('serde_json::from_slice(&identity_bytes)?'));
 ck("auth_mount_JWT_token_whole_preserved",['"mounts":auth["auth_mounts"].take()','"jwt":auth["jwt_mounts"].take()','"tokens":auth["tokens"].take()'].every(x=>after[1].includes(x)));
 ck("same_zeroization_flow",after[1].includes("Zeroizing::new(serde_json::to_vec(&projection)?)")&&after[1].includes("erase_json(&mut projection);")&&after[1].includes("erase_json(&mut auth);")&&after[1].includes("erase_json(&mut identity);"));
 ck("explicit_native_guard_intact",guard.blob==="f96c4cb6e19bd78d436060c81115423fda9bc8cc"&&guard.text.includes("native KV2 owner requires separate authenticated records"));
 ck("full_identity_serialize_type_intact",identity.blob==="ff2f31625ebe4023716afae8225a2f87092928e7"&&identity.text.includes("#[derive(Clone, Serialize, Deserialize, Default)]\npub(super) struct IdentityState"));
 const review=JSON.parse(f["REVIEW.public.json"]);
 ck("source_only_claims",review.validation.rustfmtExecuted===false&&review.validation.rustCompiled===false&&review.validation.testsExecuted===false&&review.validation.productCommitCreated===false&&review.validation.NativeCallsForPatch===0);
 return {schema:"heptabao.root-JWT-full-Identity-test-projection-source.r1",passed:true,checks:rows.length,rows,sourceTree:"4a424e3a39f96a1fb94fc2b721478673a4afa58d",baseCommit:"025b05a340de841b8161c1120344e86eae30eb97",files:Object.fromEntries(Object.keys(expected).map(k=>[expected[k],p(f[k+".after.rs"])])),productSourceBehaviorChanged:false,completeRootIdentityComparisonRetained:true,originalStatusAssertionsUnchanged:true,rustFormatted:false,rustCompiled:false,newProductTests:0,fullReplacement:false};
}