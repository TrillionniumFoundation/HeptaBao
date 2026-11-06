function buildInfoVerifierInput(files){
 const plan=JSON.parse(files["PLAN.public.json"]),state=JSON.parse(files["verifier.state-input.public.json"]);
 return {before:files["journal.33b.info.before.js"],after:files["journal.025b.info.after.js"],diff:files["journal.strict.diff"],replacements:JSON.parse(files["literal-bindings.public.json"]),requestRaw:files["request.025b.exact.json"],requestPin:plan.exact_request,plan,state,pure:files["helper.pure.original.js"],prior:{
 [plan.slot+":closed_native:"+plan.prerequisites[0].id]:files["reference.authority.native.json"],
 [plan.slot+":closed_native:"+plan.prerequisites[1].id]:files["reference.streams.native.json"]
 }};
}
