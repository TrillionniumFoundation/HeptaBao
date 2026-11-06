async function fetchPublicBlobDuringExecutorOutage(sha,label){
 if(!/^[0-9a-f]{40}$/.test(sha))throw Error("bad Git blob");
 const hit=load("r32_recovered_blob_"+sha);if(hit)return hit;
 const sdk=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:sha});
 const raw=JSON.stringify(sdk,null,2)+"\n";store("r34_outage_Git_SDK_"+label,{...gitBlobMeta(raw),text:raw});
 if(sdk.isError)throw Error("read-only Git blob failed "+sha);
 const text=sdk.structuredContent?.content;if(typeof text!=="string")throw Error("Git blob missing text");
 const out={...gitBlobMeta(text),text};if(out.blob!==sha)throw Error("Git blob mismatch");
 store("r32_recovered_blob_"+sha,out);return out;
}