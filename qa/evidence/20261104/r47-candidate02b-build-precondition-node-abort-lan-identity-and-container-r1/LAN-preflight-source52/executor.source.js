function execute(files) {
 const mk=new Function(files["pure_helpers.original.js"]+"\n"+files["process_start_binding.correct.js"]+"\n"+
   files["strict_diff.original.js"]+"\n"+files["generate.source.js"]+"\nreturn makeFinalLanRequests;")();
 const made=mk(files["identity-probe.source.py"],files["gitfirst-native.before.js"]);
 for(const r of made.observations) {
  const stem=String(r.index).padStart(2,"0")+"-"+r.role+"-"+r.route;
  if(files["request."+stem+".json"]!==r.raw||files["journal."+stem+".js"]!==r.journal||
     files["journal."+stem+".diff"]!==r.journal_diff)throw Error("frozen_generated_file_differs_"+stem);
 }
 const input={
  source:files["identity-probe.source.py"],observations:made.observations,
  binaryTemplates:JSON.parse(files["BINARY.INFO.UNBOUND.public.json"]),
  baseJournal:files["gitfirst-native.before.js"],pure:files["pure_helpers.original.js"],
  archive:files["git_archive_once.original.js"],comparison:files["compare.source.js"]
 };
 const check=new Function(files["pure_helpers.original.js"]+"\n"+files["process_start_binding.correct.js"]+
  "\n"+files["strict_diff.original.js"]+"\n"+files["verifier.source.js"]+"\nreturn verifyFinalLanSource;")();
 return check(input);
}
