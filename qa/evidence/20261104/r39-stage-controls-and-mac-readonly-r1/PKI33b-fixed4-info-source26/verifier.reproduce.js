// Reproduction only; no original call transcript is synthesized.
const h=new Function(f["pure.original.js"]+"\nreturn {gitBlobMeta,parseLosslessIntegers};")();
const d=new Function(f["strict-diff.helpers.js"]+"\nreturn {makeStrictUnified,applyStrictUnified};")();
const plan=JSON.parse(f["PLAN.public.json"]);
const input={before:f["journal.before.js"],source:f["journal.info4.after.js"],diff:f["journal.strict.diff"],replacements:JSON.parse(f["replacements.public.json"]),requests:[0,1,2,3].map(i=>f["info"+i+".PROPOSED.request.json"]),requestPins:plan.rootGOSchema.exact_requests,expected:JSON.parse(f["expected-files.public.json"]),originalJob:plan.originalJob,pure:f["pure.original.js"],archive:f["archive.original.js"],fixtureStore:JSON.parse(f["original-closed-native-fixture.public.json"]),closedState:JSON.parse(f["original-closed-state.public.json"]),slot:plan.originalSlot,initialRequest:f["initial-request.original.json"],receiptDeriver:f["receipt-deriver.source.js"],stdout:f["stdout.original.txt"],expectedReceipt:f["receipt.expected-DERIVED-NOT-ACTUAL.json"]};
const actual=new Function(f["verifier.source.js"]+"\nreturn verifyControlsInfo4Source;")()(input,h,d);
if(JSON.stringify(actual)!==JSON.stringify(JSON.parse(f["verifier.actual.json"])))throw Error("exact_recorded_result");
