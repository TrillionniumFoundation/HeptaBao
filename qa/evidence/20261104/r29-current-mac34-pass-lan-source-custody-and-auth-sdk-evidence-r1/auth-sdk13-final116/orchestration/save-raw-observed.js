async function saveRawObserved(raw) {
 const bytestring=unescape(encodeURIComponent(raw)),pin={raw,bytes:bytestring.length,sha256:sha(bytestring),blob:h1("blob "+bytestring.length+"\0"+bytestring)};
 const n=load(p+"archive_observed_count")||0;store(p+"archive_observed_count",n+1);store(p+"archive_observed_"+n+"_expected",pin);
 const r=await tools.mcp__codex_apps__github_create_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",content:raw,encoding:"utf-8"});store(p+"archive_observed_"+n+"_sdk",r);
 if(r.isError||r.structuredContent?.sha!==pin.blob){store(p+"archive_observed_"+n+"_failed",true);throw Error("External raw pin; retained archive response "+n);}
 store(p+"archive_observed_"+n+"_complete",true);return pin;
}
