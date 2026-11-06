function reviewFixed4SourceRoot(p,actual,rootQ,expectedReceipt,ready,author,h) {
 const rows=[];const ck=(id,v)=>{rows.push({id,pass:!!v});if(!v)throw Error(id);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b), pin=t=>h.gitBlobMeta(t);
 const f=p.raw,plan=JSON.parse(f["PLAN.public.json"]),g=JSON.parse(f["GO-SHAPE.REVIEW-ONLY.json"]),b=JSON.parse(f["info-binding.public.json"]),s=JSON.parse(f["original-closed-state.public.json"]);
 ck("whole_source35",p.audit.whole&&p.audit.files===35&&p.audit.tree==="92cc5fcc4111411ac5028728cb3773506920a057");
 ck("author73_exact_reproduced",author.pass&&author.checks===73&&same(author,JSON.parse(f["verifier.actual.json"])));
 ck("root43_exact_original",f["ROOT-INERT-qualification.original.json"]===rootQ.text&&same(pin(f["ROOT-INERT-qualification.original.json"]),rootQ.pins));
 ck("root43_pinned_in_plan",same(plan.originalInert.rootQualification,rootQ.pins)&&same(b.rootQualification,rootQ.pins));
 ck("same_actual_job_original_closed",s.job==="1a1b0ade81d-fc05-7220"&&s.startCalled===true&&!s.pending&&!s.activeObserver&&!s.nativeCallInFlight&&!s.paused&&Object.keys(s.calls).length===7&&s.completedObservers.length===2&&s.completedObservers.every(o=>o.completedInactive));
 ck("unsubmitted_fixed4",s.controlsInfoGO===undefined&&s.publishedInfos===undefined&&s.publishedBodyStarted===undefined);
 const authFile=Object.keys(actual.raw).find(k=>k==="authority.original.json");
 ck("actual_authority_source_exact",pin(f["authority.native.original.json"]).blob==="15690bdf2a0078dcce3bb2d76863cf353d76b2dc"&&Object.values(actual.raw).includes(f["authority.native.original.json"]));
 ck("actual_streams_source_exact",pin(f["streams.native.original.json"]).blob==="4142bf162a672bf0553a6a17815442ff09f1bd9c"&&Object.values(actual.raw).includes(f["streams.native.original.json"]));
 ck("actual_stdout_exact",f["publication.stdout.original.json"]===actual.raw["stdout.original.txt"]);
 ck("expected_receipt_reproduced_not_host_body",f["receipt.expected-derived.json"]===expectedReceipt&&["blob","bytes","sha256"].every(k=>pin(expectedReceipt)[k]===plan.derivedReceipt[k])&&plan.derivedReceipt.actualBody===null);
 const e=plan.stages[0].expected,pub=h.parseLosslessIntegers(f["publication.stdout.original.json"]);
 const int=x=>typeof x==="object"?x.$exactInteger:String(x);
 ck("publisher_3_exact_full9",e.slice(0,3).every((x,i)=>x.path===pub.files[i].path&&x.bytes===pub.files[i].bytes&&x.sha256===pub.files[i].sha256&&same(x.publisherFull9,pub.files[i].identity.map(int))));
 ck("current_ready_controls_bytes",e.slice(0,3).every((x,i)=>{let t=ready.raw[["runner.ready.py","launcher.ready.py","jwt-test-groups.public.json"][i]];return pin(t).bytes===x.bytes&&pin(t).sha256===x.sha256;}));
 ck("receipt_unobserved_metadata",e[3].publisherFull9===null&&e[3].bytes===1854&&e[3].sha256===pin(expectedReceipt).sha256&&plan.stages[0].independentActualMetadata.every(x=>x===null));
 for(const [stem,n] of [["info4",2],["body4",4]]) {
 const before=f["journal."+stem+".original.js"],after=f["journal."+stem+(stem==="info4"?".current.js":".conditional-template.js")],d=f["journal."+stem+".strict.diff"];
 const fw=h.strictApply(before,d),rv=h.strictApply(after,d,true);
 ck(stem+"_strict_forward_reverse",fw.text===after&&rv.text===before&&fw.hunks===n&&rv.hunks===n);
 }
 ck("original_info_source_pin",pin(f["journal.info4.original.js"]).blob==="80e33a52cc2b2d5a4c781de1521432c0eb56d6de");
 ck("original_body_source_pin",pin(f["journal.body4.original.js"]).blob==="4b0790aa5c365b6e386c6e05a735e733c383b57d");
 ck("exact_info_source_binding",same(pin(f["journal.info4.current.js"]),plan.stages[0].source));
 ck("body_template_and_deriver_bound",same(pin(f["journal.body4.conditional-template.js"]),g.conditional_body_authorization.journal_template)&&same(pin(f["body-deriver.source.js"]),g.conditional_body_authorization.deriver));
 const root="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/";
 for(let i=0;i<4;i++) {
 const ir=f["info"+i+".PROPOSED.request.json"],br=f["body"+i+".NULL-VERSION.template.json"],iq=JSON.parse(ir),bq=JSON.parse(br);
 ck("info_request_"+i, same(pin(ir),g.exact_requests[i])&&iq.operation.tool==="file_info"&&iq.operation.arguments.host==="rog"&&iq.operation.arguments.path===root+e[i].name);
 ck("body_template_"+i,same(pin(br),g.conditional_body_authorization.exact_templates[i])&&bq.operation.tool==="binary_read"&&bq.operation.arguments.host==="rog"&&bq.operation.arguments.path===root+e[i].name&&bq.operation.arguments.expected_version===null&&bq.operation.arguments.offset===0&&bq.operation.arguments.limit===e[i].bytes);
 }
 ck("only_fixed_ranges",e.reduce((n,x)=>n+x.bytes,0)===90605&&e.every(x=>x.bytes<=65536));
 ck("body_two_tables_unbound",f["journal.body4.conditional-template.js"].includes("const GF_CONTROLS_BODY_REQUESTS = null;")&&f["journal.body4.conditional-template.js"].includes("const GF_CONTROLS_BODY_EXPECTED = null;"));
 ck("explicit_conditional_no_implicit_binary",g.authorization==="REVIEW_ONLY_NOT_GO"&&g.binary_read_authorized===false&&g.maximum_file_info_starts===4&&g.conditional_body_authorization.authorization==="REVIEW_ONLY_NOT_GO"&&g.conditional_body_authorization.maximum_binary_read_starts===4);
 return {schema:"heptabao.root-source-review.fixed4-controls.r1",pass:true,checks:rows.length,rows,sourcePacket:p.audit,originalInertQualification:rootQ.pins,authorChecksReproduced:73,reviewScope:"Exact public metadata plus conditional public bodies; source and original publication provenance only.",actualIndependentFiles:false,normalBuild:false,tests149_166:false,fullReplacement:false};
}