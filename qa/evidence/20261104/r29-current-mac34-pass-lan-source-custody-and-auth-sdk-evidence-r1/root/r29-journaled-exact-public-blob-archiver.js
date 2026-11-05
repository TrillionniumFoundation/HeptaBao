async function saveVerifiedPublicBlobJournaled(name,content){
 const u=eval(load("root_utf8_bytes_r1_source")+";utf8Bytes"),bs=eval(load("root_byte_string_r1_source")+";byteString"),s1=eval(load("root_sha1_bytes_r1_source")+";sha1Bytes"),s256=eval(load("root_sha256_latin1_r1_source")+";sha256Latin1");
 const b=u(content),expected=s1(u("blob "+b.length+"\0").concat(b)),key="r29_git_blob_journal_"+expected,prior=load(key)||[],entry={name,expected,bytes:b.length,create:null,read:null};
 prior.push(entry);store(key,prior);
 const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",parts=[];for(let i=0;i<b.length;i+=3){const n=(b[i]<<16)|((b[i+1]||0)<<8)|(b[i+2]||0);parts.push(chars[n>>>18&63],chars[n>>>12&63],i+1<b.length?chars[n>>>6&63]:"=",i+2<b.length?chars[n&63]:"=");}const created=await tools.mcp__codex_apps__github_create_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",content:parts.join(""),encoding:"base64"});
 entry.create=created;store(key,prior);
 if(!created.isError&&created.structuredContent?.sha!==expected)throw Error("created SHA mismatch; original SDK journaled "+key);
 const read=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:expected});
 entry.read=read;entry.create_error_reconciled_by_exact_content_address=created.isError===true&&!read.isError&&read.structuredContent?.content===content;store(key,prior);
 if(read.isError||read.structuredContent?.content!==content)throw Error("readback failed; original SDKs journaled "+key);
 const result={name,blob:expected,bytes:b.length,sha256:s256(bs(b))};store("r12_saved_"+name,result);if(b.length<=262144)store("r12_small_blob_"+expected,content);return result;
}
