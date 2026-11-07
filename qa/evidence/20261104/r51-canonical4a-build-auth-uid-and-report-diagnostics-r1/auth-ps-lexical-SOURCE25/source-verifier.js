/* Pure V8 exact-source checks only. Preload pure-helper, strict-diff-helper,
 * actual-stdin-binding, then call verifyFixedPsLexicalSourceR2(files).
 * No Python, Native, source module, SDK or example table is executed. */
function verifyFixedPsLexicalSourceR2(files) {
 const checks=[];const check=(name,passed)=>checks.push({name,passed:passed===true});
 const eq=(name,a,b)=>check(name,JSON.stringify(a)===JSON.stringify(b));
 const whole=(raw,pin)=>{const x=gitBlobMeta(raw);return x.blob===pin.blob&&x.bytes===pin.bytes&&x.sha256===pin.sha256;};
 const c=JSON.parse(files["CONTRACT.public.json"]),bc=JSON.parse(files["CONTRACT.before.json"]);
 const s=files["controller.py"],before=files["controller.before.py"],j=files["journal.js"],bj=files["journal.before.js"];
 const q=JSON.parse(files["request.exact.public.json"]),bq=JSON.parse(files["request.before.json"]);
 check("controller whole",whole(s,c.source));check("request whole",whole(files["request.exact.public.json"],c.exact_request));check("journal whole",whole(j,c.journal));
 check("before source whole",whole(before,c.predecessor.beforeSource));check("before request whole",whole(files["request.before.json"],c.predecessor.beforeRequest));check("before journal whole",whole(bj,c.predecessor.beforeJournal));
 let a=strictApplySource(before,files["controller.forward.diff"]),b=strictApplySource(s,files["controller.inverse.diff"]);
 eq("controller forward whole+hunks",[a.raw,a.hunks],[s,2]);eq("controller inverse whole+hunks",[b.raw,b.hunks],[before,2]);
 a=strictApplySource(bj,files["journal.forward.diff"]);b=strictApplySource(j,files["journal.inverse.diff"]);
 eq("journal forward whole+hunks",[a.raw,a.hunks],[j,2]);eq("journal inverse whole+hunks",[b.raw,b.hunks],[bj,2]);
 const projection=files["lexical-projection.original.py"];
 check("single exact projector",s.split(projection).length===2);
 const restored=s.replace(projection,"").replace("'heptabao.fixed-setuid-ps-lexical-diagnostic.r2'","'heptabao.fixed-setuid-ps-custody-validation.r1'")
 .replace("        report['tableLexicalProjection']=table_lexical_projection(out)\n","");
 eq("all original source except exact additions preserved",restored,before);
 check("projection exact call count",s.split("report['tableLexicalProjection']=table_lexical_projection(out)").length===2);
 check("projection after primary closed and before original table guard",s.indexOf("need(value['exitCode']==0 and not err,'complete_group_observation')")<s.indexOf("report['tableLexicalProjection']")&&s.indexOf("report['tableLexicalProjection']")<s.indexOf("count=0;self_rows=[]"));
 const guard="need(len(fields)==5 and all(x.isdecimal() for x in fields[:4]),'typed_process_row')";
 check("original guard literal remains",before.includes(guard)&&s.includes(guard));
 check("current manager shares original guard",files["manager.original.py"].includes(guard));
 check("manager before group selection",files["manager.original.py"].indexOf(guard)<files["manager.original.py"].indexOf("if pgid in groups:values.append"));
 check("manager whole pin",whole(files["manager.original.py"],c.sourceBasis.currentManager));
 const {stdin, idempotency_key,...rest}=q,{stdin:bs,idempotency_key:bk,...brest}=bq;
 eq("request only stdin/fresh key",rest,brest);
 eq("request stdin exact",stdin,s);eq("request key exact",idempotency_key,c.idempotency_key);
 check("key differs from original",idempotency_key!==bk&&!Object.hasOwn(q,"stdin_text"));
 const binding=actualStdinProcessStartBinding(q);
 eq("correct stdin typed binding",[binding.sha256,binding.native_fingerprint,utf8Bytes(binding.canonical).length],[c.nativeBinding.sha256,c.nativeBinding.native_fingerprint,c.nativeBinding.canonicalBytes]);
 check("journal descriptor exact",j.includes("const GF_SLOT = "+JSON.stringify(c.slot)+";")&&j.includes("const GF_REQUEST = "+JSON.stringify(c.exact_request)+";"));
 const jr=j.replace(c.slot,bc.slot).replace(JSON.stringify(c.exact_request),JSON.stringify(bc.exact_request))
 .replaceAll(c.observer_prefix,"heptabao-mac-fixed-setuid-ps-custody-c0c5f671-");
 eq("journal only three fixed literal replacements",jr,bj);
 eq("original budgets unchanged",c.budgets,bc.budgets);eq("original observer caps unchanged",c.observe,bc.observe);
 eq("fixed two inputs unchanged",c.fixedPublicInputPins,bc.fixedPublicInputPins);
 eq("exact one primary unchanged",c.primaryCommand,bc.primaryCommand);
 check("only one original command call",s.split("commands.run(").length===2);
 check("original full9/two helper sources unchanged",s.slice(0,s.indexOf("def table_lexical_projection("))===before.slice(0,before.indexOf("def main():")));
 check("projection finite loop and remaining",projection.includes("total<=8192")&&projection.includes("remaining()")&&projection.includes("for index in range(4):"));
 check("only five closed token classes",projection.includes("classes=('ascii_decimal','negative_decimal','positive_decimal','other_ascii','missing')"));
 check("only closed field-width buckets",projection.includes("widths={str(n):0 for n in range(6)}")&&projection.includes("widths['more_than_5']=0"));
 check("first failure contains no row/index value",projection.includes("first_rejected={'fieldCount':width,'failedNumericColumns':failed}")&&projection.includes("failed.append(index+1)"));
 check("projection returns no token/line/out value",!projection.slice(projection.indexOf("    return ")).match(/:(?:token|line|out|fields)(?:[,}\n])/));
 check("projection has no IO/import/hash/signal",!projection.match(/\b(?:open|write|print|sha256|Popen|run|signal|kill|import)\(/));
 check("original guard not replaced by signed acceptance",s.includes(guard)&&projection.includes("'originalPredicateAllPassed':rejected==0"));
 const actual=JSON.parse(files["actual-before.stdout.original.json"]);
 check("actual original failure retained",actual.error.code==="typed_process_row"&&actual.ok===false&&actual.executionSucceeded===false&&actual.allFixedHeldNamedFencesPassed===false);
 check("actual primary custody finite positive retained",actual.command.exitCode===0&&actual.command.expectedEffectiveUid===0&&actual.command.fixedPsAdmissionEvidence.effectiveUidMatches===true&&actual.command.cleanup.directChildReaped===true&&actual.outcomeUnknown===false);
 check("actual original stdout pin",whole(files["actual-before.stdout.original.json"],c.predecessor.stdout));
 check("actual original release pin",whole(files["actual-before.RELEASE.public.json"],c.predecessor.release));
 const refs=JSON.parse(files["PRIMARY-SOURCES.public.json"]);
 eq("primary fixed commit",refs.commit,"6bed8737a34dbb54782a18f47dccf933a9967a12");
 const keyword=files["Apple-ps-keyword.original.c"],kp=refs.sources.find(x=>x.path==="Apple-ps-keyword.original.c").pin;
 check("Apple keyword whole",whole(keyword,kp));
 check("Apple signed format conditional",keyword.includes('#ifdef __APPLE__\n#define\tUIDFMT\t"d"\n#else\n#define\tUIDFMT\t"u"\n#endif')&&keyword.includes('#define\tPIDFMT\t"d"'));
 check("no old failure/SDK qualification",c.actualBusinessQualified===false&&c.historicalUnknownPreserved===true&&c.sourceComponentsDispatchable===false&&c.predecessor.offendingFieldOrValueObserved===false);
 return {schema:"heptabao.fixed-ps-lexical-source-r2-pure-checks",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,PythonExecuted:false,NativeCalls:0,oldRawTableRecovered:false,prospectiveOnly:true};
}
