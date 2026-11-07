
function reproduceStage4a(F) {
 const I={before:F["BEFORE.py"],beforeRequestRaw:F["REQUEST.before.json"],beforeJournal:F["JOURNAL.before.js"],candidateRaw:F["CANDIDATE.original.json"],indexRaw:F["INDEX.original.txt"],baseQualificationRaw:F["BASE-QUAL.original.json"]};
 const plan=JSON.parse(F["PLAN.public.json"]);
 const O={after:F["AFTER.py"],requestRaw:F["REQUEST.after.json"],journal:F["JOURNAL.after.js"],sourceDiff:F["source.forward.diff"],journalDiff:F["journal.forward.diff"],edits:JSON.parse(F["EDITS.public.json"]),binding:plan.native_binding};
 return verifyStage4a(I,O);
}
