function make576CompileLogInfoInput(t) {
 const p=JSON.parse(t["PLAN.public.json"]),logs=JSON.parse(t["LOGS.public.json"]);
 return {before:t["journal.before.js"],after:t["journal.after.js"],beforePin:p.exactBeforeJournal,afterPin:p.exactJournal,
 forward:t["journal.forward.diff"],reverse:t["journal.reverse.diff"],edits:JSON.parse(t["journal.edits.json"]),
 reportRaw:t["actual.report.original.json"],reportPin:p.actualReport,files:logs.files.map(f=>({...f,requestRaw:t["REQUEST."+f.stream+".json"]})),
 state:JSON.parse(t["actual.STATE.original.json"]),stateRaw:t["actual.STATE.original.json"],slot:p.slot,
 pure:t["pure_helpers.js"],archive:t["git_archive_once.js"],bodyRequestRaw:t["original.BODY-REQUEST.json"],
 runner:t["executed.runner.py"],launcher:t["executed.launcher.py"]};
}
