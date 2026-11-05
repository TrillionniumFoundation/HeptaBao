async function saveRawBase64Observed(raw) {
 const bytestring=unescape(encodeURIComponent(raw)),pin={raw,bytes:bytestring.length,sha256:sha(bytestring),blob:h1("blob "+bytestring.length+"\0"+bytestring)};
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let encoded="";
 for(let i=0;i<bytestring.length;i+=3){const a=bytestring.charCodeAt(i),hasB=i+1<bytestring.length,hasC=i+2<bytestring.length,b=hasB?bytestring.charCodeAt(i+1):0,c=hasC?bytestring.charCodeAt(i+2):0;encoded+=alphabet[a>>2]+alphabet[((a&3)<<4)|(b>>4)]+(hasB?alphabet[((b&15)<<2)|(c>>6)]:"=")+(hasC?alphabet[c&63]:"=");}
 const n=load(p+"archive_observed_count")||0;store(p+"archive_observed_count",n+1);store(p+"archive_observed_"+n+"_expected",pin);store(p+"archive_observed_"+n+"_encoding","base64");
 const r=await tools.mcp__codex_apps__github_create_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",content:encoded,encoding:"base64"});store(p+"archive_observed_"+n+"_sdk",r);
 if(r.isError||r.structuredContent?.sha!==pin.blob){store(p+"archive_observed_"+n+"_failed",true);throw Error("External base64 raw pin; retained archive response "+n);}
 const check=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:pin.blob});store(p+"archive_observed_"+n+"_whole_fetch",check);
 if(check.isError||check.structuredContent?.content!==raw)throw Error("External base64 whole readback "+n);
 const actual=unescape(encodeURIComponent(check.structuredContent.content));if(actual.length!==pin.bytes||sha(actual)!==pin.sha256||h1("blob "+actual.length+"\0"+actual)!==pin.blob)throw Error("External base64 whole hash "+n);
 store(p+"archive_observed_"+n+"_complete",true);return pin;
}
