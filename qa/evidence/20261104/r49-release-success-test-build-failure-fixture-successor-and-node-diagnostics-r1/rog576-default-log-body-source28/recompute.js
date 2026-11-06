function make576CompileLogBodiesInput(t){
 const p=JSON.parse(t["PLAN.public.json"]),rr=JSON.parse(t["RANGES.public.json"]);
 return {before:t["journal.before.js"],after:t["journal.after.js"],beforePin:p.exactBeforeJournal,afterPin:p.exactJournal,
 forward:t["journal.forward.diff"],reverse:t["journal.reverse.diff"],edits:JSON.parse(t["journal.edits.json"]),
 ranges:rr.map(r=>({...r,requestRaw:t["REQUEST."+String(r.index).padStart(2,"0")+"."+r.stream+".json"]})),infos:JSON.parse(t["INFOS.public.json"]),
 infoNativeRaws:{stderr:t["actual.stderr.INFO.native.json"],stdout:t["actual.stdout.INFO.native.json"]},
 state:JSON.parse(t["actual.STATE.original.json"]),stateRaw:t["actual.STATE.original.json"],slot:p.slot,
 pure:t["pure_helpers.js"],archive:t["git_archive_once.js"],toolContract:t["operation-result.tool-contract.public.json"]};
}
