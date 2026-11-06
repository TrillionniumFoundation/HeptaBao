function cleanupInputsFromFiles(files,H) {
  const read=k=>{if(typeof files[k]!=="string")throw Error("missing_input:"+k);return files[k];};
  const body=s=>s.slice(s.indexOf("PARENT_START_NS = time.monotonic_ns()\n"));
  const before={source:read("baseline.libproc.r3.py"),request:read("baseline.request.r3.json"),
    journal:read("baseline.journal.r3.js")};
  before.body=body(before.source);before.sourcePin=H.pin(before.source);
  before.requestPin=H.pin(before.request);before.journalPin=H.pin(before.journal);
  const after={source:read("cleanup.fixed-label.r1.py"),request:read("cleanup.exact-request.r1.json"),
    journal:read("cleanup.journal.r1.js")};
  after.body=body(after.source);after.sourcePin=H.pin(after.source);
  after.requestPin=H.pin(after.request);after.journalPin=H.pin(after.journal);
  const constStart=after.source.indexOf("CLEANUP_OBSERVED = json.loads(r'''");
  after.constText=after.source.slice(constStart,after.source.indexOf("PARENT_START_NS = time.monotonic_ns()\n"));
  after.observed=JSON.parse(after.constText.slice(after.constText.indexOf("r'''")+4,after.constText.lastIndexOf("'''")));
  after.control=after.body.slice(after.body.indexOf("class OneLabelCleanup("),after.body.indexOf("def check_leaf_metadata("));
  after.sequence=after.body.slice(after.body.indexOf("        stage = 'current_preflight_print'\n"),
    after.body.indexOf("    except BaseException as error:\n",after.body.indexOf("def main():\n")));
  after.newFinish=after.body.slice(after.body.indexOf("        result['bootoutAttempted'] = "),
    after.body.indexOf("        final_raw = encoded(result)\n"));
  for(const [key,path] of [["diff","cleanup.forward.diff"],["reverse","cleanup.reverse.diff"],
    ["jdiff","journal.forward.diff"],["jreverse","journal.reverse.diff"]]) {
    const raw=read(path);after[key]={raw,hunks:(raw.match(/^@@ /gm)||[]).length};
  }
  return {before,after,originalValidators:read("reference.original-child-validators.py"),
    actualStdout:read("reference.r3.stdout.original.json"),
    rootQualification:read("reference.r3.root-qualification.original.json"),slotInitialized:false};
}
