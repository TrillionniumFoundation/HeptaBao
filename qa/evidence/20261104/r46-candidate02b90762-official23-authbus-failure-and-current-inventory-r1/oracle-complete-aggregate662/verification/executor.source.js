/* Input is the aggregate's full relative path -> exact UTF-8 text map. V8 only. */
function execute(files) {
 const subtree=prefix=>Object.fromEntries(Object.entries(files).filter(([path])=>path.startsWith(prefix+"/")).map(([path,text])=>[path.slice(prefix.length+1),text]));
 const units={};for(const i of [0,1,3,4,5,6,7,8,9])units[i]=subtree("body"+String(i).padStart(2,"0"));
 const input={units,recovery:subtree("body02-recovery"),actual:subtree("actual"),handback:subtree("handback"),
 payloadRaw:files["verification/SOURCE-PAYLOAD.original.json"],matrixRaw:files["verification/MATRIX23.original.public.json"],pemRaw:files["verification/PUBLIC-KEY.pem"]};
 return new Function(files["verification/pure_helpers.js"]+"\n"+files["verification/verifier.source.js"]+"\nreturn verifyOfficialAcl23R2Final;")()(input);
}
