async function executeBody02RecoverySource(files) {
 const params=JSON.parse(files["PARAMETERS.public.json"]);
 return await verifyOracleR2Body02RecoverySource({...params,
 before:files["journal.before.js"],after:files["journal.after.js"],diff:files["journal.strict.diff"],
 pausedRaw:files["STATE.original.paused.json"],requestRaw:files["REQUEST.status.exact.json"],
 originalAdmitRaw:files["ORIGINAL-ADMISSION.request.json"],oldStatusSDK:files["ORIGINAL-STATUS.sdk.json"],
 pure:files["pure.original.js"]});
}

