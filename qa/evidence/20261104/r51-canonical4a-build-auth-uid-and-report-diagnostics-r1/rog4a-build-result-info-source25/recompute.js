function recompute4aBuildInfoSource(files) {
 const x={before:files["journal.before.js"],after:files["journal.after.js"],fwd:files["journal.forward.diff"],rev:files["journal.reverse.diff"],edits:JSON.parse(files["EDITS.public.json"]),stateRaw:files["actual.STATE.original.json"],oldBuildRaw:files["history.old-build.STATE.original.json"],oldInfoRaw:files["history.old-info.STATE.original.json"],requestRaw:files["request.exact.json"],prereqs:JSON.parse(files["PREREQUISITES.public.json"]),closed:JSON.parse(files["actual.closed-native-map.public.json"])};
 return eval(files["pure_helpers.js"]+"\n"+files["strict_diff.js"]+"\n"+files["SOURCE-VERIFIER.js"]+";verify4aBuildInfoSource")(x);
}
