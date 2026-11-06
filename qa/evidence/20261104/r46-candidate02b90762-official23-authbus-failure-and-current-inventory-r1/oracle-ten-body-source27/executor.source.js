async function executeOracleBodyTenSource(files) {
 const cfg=JSON.parse(files["PARAMETERS.public.json"]);
 const input={...cfg,before:files["journal.before.js"],after:files["journal.after.js"],
 diff:files["journal.strict.diff"],priorStateRaw:files["PRIOR-STATE.original.closed.json"],
 infoNativeRaw:files["INFO.native.original.json"],reference:files["reference.CLI13.original.js"],
 pure:files["pure.original.js"],
 requests:cfg.ranges.map((r,i)=>{const raw=files["request-"+String(i).padStart(2,"0")+".exact.json"];
 return {q:JSON.parse(raw),raw,pin:gitBlobMeta(raw)};})};
 return await verifyOracleR2TenBodySource(input);
}

