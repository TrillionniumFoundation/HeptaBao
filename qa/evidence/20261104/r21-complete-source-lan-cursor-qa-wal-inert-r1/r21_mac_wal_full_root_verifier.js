function rootTopJsonTokens(raw){
 let s="",inside=false,escape=false;for(const ch of raw){if(inside){s+=ch;if(escape)escape=false;else if(ch==="\\")escape=true;else if(ch==='"')inside=false;}else{if(ch==='"'){inside=true;s+=ch;}else if(!/\s/.test(ch))s+=ch;}}
 if(s[0]!=="{"||s[s.length-1]!=="}")throw Error("object token boundary");
 const out={};let i=1;while(i<s.length-1){const kstart=i;if(s[i++]!=='"')throw Error("key");escape=false;while(i<s.length){const ch=s[i++];if(escape)escape=false;else if(ch==="\\")escape=true;else if(ch==='"')break;}
 const key=JSON.parse(s.slice(kstart,i));if(Object.hasOwn(out,key)||s[i++]!==":")throw Error("duplicate or separator");const start=i;let depth=0;inside=false;escape=false;
 while(i<s.length){const ch=s[i];if(inside){if(escape)escape=false;else if(ch==="\\")escape=true;else if(ch==='"')inside=false;}else if(ch==='"')inside=true;else if(ch==="{"||ch==="[")depth++;else if(ch==="}"||ch==="]"){if(depth===0)break;depth--;}else if(ch===","&&depth===0)break;i++;}
 out[key]=s.slice(start,i);if(s[i]===",")i++;else if(s[i]==="}")break;else throw Error("value boundary");
 }return out;
}

function verifyWalFull(a,get,parse,u,bs,h,unb64,top,core){
 const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},rec=p=>a.records.find(r=>r.path===p),raw=p=>get(rec(p).blob),j=p=>parse(raw(p));
 const rows=[...core.files,core.candidateReceipt],root=core.createdRoot;let total=0;
 for(let n=0;n<13;n++){
  const x=rows[n],name=x.name.startsWith("qa/")?x.name.slice(3):x.name,stem=String(n).padStart(2,"0")+"-"+name,ip="file-info/"+stem,info=j(ip+".native.public.json"),infosdk=j(ip+".mcp.public.json"),ireq=j(ip+".request.public.json");
  ck("file info native "+n,!infosdk.isError&&infosdk.content.length===1&&infosdk.content[0].text===raw(ip+".native.public.json"));
  ck("fixed file path "+n,ireq.host==="mac"&&ireq.path===root+"/"+x.name&&info.path===ireq.path);
  ck("full9 to version and metadata "+n,info.version===[x.identity[0],x.identity[1],x.identity[6],x.identity[7],x.identity[8]].join(":")&&info.metadata.uid===Number(x.identity[2])&&info.metadata.gid===Number(x.identity[3])&&info.metadata.mode===384&&info.mode===384&&x.identity[4]==="33152"&&info.metadata.link_count===Number(x.identity[5])&&info.size===x.bytes&&info.sha256===x.sha256);
  const bp="binary-read/"+stem+"-attempt-"+(n===5?"01":"00"),rq=j(bp+".request.public.json"),nat=j(bp+".native.public.json"),sdk=j(bp+".mcp.public.json"),b=Array.from(unb64(nat.data_base64)),rbody=raw("readback/"+x.name);
  ck("binary request pinned "+n,rq.host==="mac"&&rq.path===ireq.path&&rq.expected_version===info.version&&rq.offset===0&&rq.limit===65536);
  ck("binary original SDK "+n,!sdk.isError&&sdk.content.length===1&&sdk.content[0].text===raw(bp+".native.public.json"));
  ck("binary whole "+n,nat.version===info.version&&nat.path===rq.path&&nat.offset===0&&nat.next_offset===x.bytes&&nat.size===x.bytes&&nat.eof&&b.length===x.bytes&&h(bs(b))===nat.chunk_sha256&&nat.chunk_sha256===x.sha256&&bs(b)===bs(u(rbody))&&rec("readback/"+x.name).sha256===x.sha256);
  total+=b.length;
 }
 ck("body count total",total===176462&&rows.length===13);
 const refusal="binary-read/05-mac_darwin_owned_projection_r1.py-attempt-00",first=j(refusal+".mcp.public.json"),firstreq=j(refusal+".request.public.json"),later=j("binary-read/05-mac_darwin_owned_projection_r1.py-attempt-01.request.public.json");
 ck("preserved pre-dispatch capacity refusal",first.isError===true&&first.content[0].text===raw(refusal+".native.public.json")&&first.content[0].text==="direct SSH admitted capacity exhausted; no child submitted; no automatic retry"&&JSON.stringify(firstreq)===JSON.stringify(later));
 const token=top(raw("readback/inert-owned-registry-wal-result.public.json")),final=top(raw("stdout.public.json"));
 ck("candidate status intentionally not final",token.ok==="false"&&final.ok==="true"&&token.preparedCandidate==="true"&&final.preparedCandidate==="true"&&Object.keys(token).length===27);
 for(const [k,v]of Object.entries(token))if(k!=="ok")ck("original receipt raw token "+k,final[k]===v);
 return{checks,total,raw_token_equal_fields:26,receipt_ok_before_cleanup:false,final_stdout_ok_after_cleanup:true,independent_infos:13,independent_bodies:13};
}
