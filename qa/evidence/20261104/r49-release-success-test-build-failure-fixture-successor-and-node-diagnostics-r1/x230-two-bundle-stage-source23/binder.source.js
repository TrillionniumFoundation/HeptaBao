function bindX230TwoBundleSource(input) {
 function need(v,s){if(!v)throw Error(s);}
 const b=input.binding,c=b.candidate;
 need(b.schema==="heptabao.x230.two-incremental-bundle-source-binding.v1","binding schema");
 need(JSON.stringify(c)===JSON.stringify(input.acceptedCandidate),"exact accepted candidate data");
 need(b.readonly_base==="/home/qian/heptabao-same-root-publication-normal-20261105-r1/source","fixed historical read-only base");
 need(b.base_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&b.base_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&b.base_history===3763,"fixed base identity");
 need(b.first_prerequisite==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc"&&b.intermediate_commit==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270","fixed bridge");
 need(b.fresh_root==="/home/qian/hb-"+c.commit.slice(0,8)+"-src-20261106-r1","fixed isolated root");
 need(b.bundles.length===2&&b.bundles[0].prerequisite===b.first_prerequisite&&b.bundles[0].head===b.intermediate_commit&&b.bundles[1].prerequisite===b.intermediate_commit&&b.bundles[1].head===c.commit,"two exact linked bundles");
 const m=gitBlobMeta(input.carrier);
 need(m.blob===b.carrier.blob&&m.bytes===b.carrier.bytes&&m.sha256===b.carrier.sha256&&m.bytes<=262144,"whole carrier and original cap");
 const q=JSON.parse(input.carrier),keys=["schema",...b.bundles.map(x=>x.field)].sort();
 need(JSON.stringify(Object.keys(q).sort())===JSON.stringify(keys)&&q.schema===b.carrier.schema,"closed carrier keys");
 for(const f of b.bundles){
  const bytes=unb64(q[f.field]);need(encodeBase64Bytes(bytes)===q[f.field],"canonical base64");
  need(bytes.length===f.bytes&&sha256Latin1(byteString(bytes))===f.sha256,"whole binary bytes");
  const head=utf8Bytes(f.header);
  need(bytes.slice(0,head.length).every((v,i)=>v===head[i])&&utf8Text(bytes.slice(head.length,head.length+4))==="PACK","exact binary header and PACK");
  need(sha256Latin1(byteString(head))===f.header_sha256,"header SHA");
  const lines=f.header.split("\n");
  need(lines.length===5&&lines[0]==="# v2 git bundle"&&lines[1].startsWith("-"+f.prerequisite+" ")&&lines[2]===f.head+" HEAD"&&lines[3]===""&&lines[4]==="","sole prerequisite and HEAD");
 }
 const marker="BINDING = None  # EXACT_PUBLIC_SOURCE_BINDING";
 need(input.template.split(marker).length===2,"single binding marker");
 const source=input.template.replace(marker,"BINDING = json.loads("+JSON.stringify(JSON.stringify(b))+")");
 const sourcePin=gitBlobMeta(source);
 const request={host:"x230",executable:"/usr/bin/python3",args:["-I","-S","-B","-c",source,sourcePin.sha256],cwd:"/home/qian",env:{},stdin:input.carrier,timeout_seconds:360,idempotency_key:"heptabao-"+c.commit.slice(0,8)+"-x230-two-bundle-source-20261106-r1-"+sourcePin.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(request,null,2)+"\n";
 const typed=processStartBinding(request);
 return {source,sourcePin,requestRaw,requestPin:gitBlobMeta(requestRaw),typed:{sha256:typed.sha256,native_fingerprint:typed.native_fingerprint,canonical_bytes:utf8Bytes(typed.canonical).length},carrierPin:m,candidate:c,NativeGO:null,NativeExecuted:false};
}