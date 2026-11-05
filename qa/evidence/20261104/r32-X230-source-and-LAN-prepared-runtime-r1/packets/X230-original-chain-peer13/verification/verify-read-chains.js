function verifyX230ReadChains(input) {
  const utf8 = (function utf8binary(text) {
  let out="";
  for (const ch of text) {
    const n=ch.codePointAt(0);
    if(n>=0xd800&&n<=0xdfff) throw new Error("unpaired UTF-16 surrogate");
    if(n<0x80)out+=String.fromCharCode(n);
    else if(n<0x800)out+=String.fromCharCode(0xc0|(n>>6),0x80|(n&63));
    else if(n<0x10000)out+=String.fromCharCode(0xe0|(n>>12),0x80|((n>>6)&63),0x80|(n&63));
    else out+=String.fromCharCode(0xf0|(n>>18),0x80|((n>>12)&63),0x80|((n>>6)&63),0x80|(n&63));
  }
  return out;
});
const sha256 = (function sha256binary(s) {
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const len=s.length, n=Math.ceil((len+9)/64)*64,buf=new Uint8Array(n),dv=new DataView(buf.buffer);
  for(let i=0;i<len;i++){let b=s.charCodeAt(i);if(b>255)throw new Error("binary input only");buf[i]=b;}
  buf[len]=0x80;dv.setUint32(n-8,Math.floor(len/0x20000000));dv.setUint32(n-4,(len*8)>>>0);
  const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Uint32Array(64);
  const R=(x,n)=>(x>>>n)|(x<<(32-n));
  for(let off=0;off<n;off+=64){
    for(let j=0;j<16;j++)w[j]=dv.getUint32(off+j*4);
    for(let j=16;j<64;j++){const x=w[j-15],y=w[j-2];w[j]=(w[j-16]+(R(x,7)^R(x,18)^(x>>>3))+w[j-7]+(R(y,17)^R(y,19)^(y>>>10)))>>>0;}
    let [a,b,c,d,e,f,g,h]=H;
    for(let j=0;j<64;j++){const t1=(h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+K[j]+w[j])>>>0;const t2=((R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c)))>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
    const v=[a,b,c,d,e,f,g,h];for(let j=0;j<8;j++)H[j]=(H[j]+v[j])>>>0;
  }
  return H.map(x=>x.toString(16).padStart(8,"0")).join("");
});
const sha1 = (function sha1binary(s) {
  const len=s.length,n=Math.ceil((len+9)/64)*64,buf=new Uint8Array(n),dv=new DataView(buf.buffer);
  for(let i=0;i<len;i++){const b=s.charCodeAt(i);if(b>255)throw new Error("binary input only");buf[i]=b;}
  buf[len]=0x80;dv.setUint32(n-8,Math.floor(len/0x20000000));dv.setUint32(n-4,(len*8)>>>0);
  const H=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0],w=new Uint32Array(80);const L=(x,n)=>(x<<n)|(x>>>(32-n));
  for(let off=0;off<n;off+=64){
    for(let j=0;j<16;j++)w[j]=dv.getUint32(off+j*4);
    for(let j=16;j<80;j++)w[j]=L(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);
    let[a,b,c,d,e]=H;
    for(let j=0;j<80;j++){let f,k;if(j<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(j<40){f=b^c^d;k=0x6ed9eba1;}else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(L(a,5)+f+e+k+w[j])>>>0;e=d;d=c;c=L(b,30);b=a;a=t;}
    const v=[a,b,c,d,e];for(let j=0;j<5;j++)H[j]=(H[j]+v[j])>>>0;
  }
  return H.map(x=>x.toString(16).padStart(8,"0")).join("");
});
const lossless = (function losslessJson(s){let out="",i=0;while(i<s.length){if(s[i]==='"'){const start=i++;let closed=false;while(i<s.length){if(s[i]==="\\"){i+=2;continue;}if(s[i++]==='"'){closed=true;break;}}if(!closed)throw new Error("unterminated JSON string");out+=s.slice(start,i);continue;}if(s[i]==="-"||(s[i]>="0"&&s[i]<="9")){const m=s.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);if(!m)throw new Error("bad number");const n=m[0];if(!/[.eE]/.test(n)&&(BigInt(n)>9007199254740991n||BigInt(n)<-9007199254740991n))out+=JSON.stringify(n);else out+=n;i+=n.length;continue;}out+=s[i++];}return JSON.parse(out);});
const decode64 = (function decodeBase64Binary(s){if(typeof s!=="string"||s.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw new Error("base64 syntax");const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let acc=0,bits=0,out="";for(const c of s){if(c==="=")break;acc=(acc<<6)|chars.indexOf(c);bits+=6;if(bits>=8){bits-=8;out+=String.fromCharCode((acc>>>bits)&255);}}if(bits>0&&(acc&((1<<bits)-1))!==0)throw new Error("base64 nonzero pad bits");return out;});
  const files=input.files, selected=input.index, tree=input.subject_tree, inheritedTree=input.inherited_tree;
  const checks=[], obs=[], extractions=[], inherited=[], ids=new Set(), keys=new Set();
  function ok(name, value) { if(!value) throw new Error("FAILED "+name); checks.push(name); }
  function equal(a,b) { return JSON.stringify(a)===JSON.stringify(b); }
  function canonical(v) { if(v===null||typeof v!=="object")return JSON.stringify(v);if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}"; }
  function objEqual(a,b) { return canonical(a)===canonical(b); }
  function json(path) { if(typeof files[path]!=="string") throw Error("missing input "+path);return lossless(files[path]); }
  function originalSDK(path, nativePath, label) { const sdk=json(path);ok(label+":SDK-not-error",sdk.isError===false);ok(label+":SDK-one-original-text",Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text"&&typeof sdk.content[0].text==="string");ok(label+":original-text-byte-equality",sdk.content[0].text===files[nativePath]);return lossless(sdk.content[0].text); }
  const pins=new Map(selected.map(e=>[e.path,e]));
  const leafEntries=new Map(tree.tree.filter(e=>e.type==="blob").map(e=>[e.path,e]));
  function pin(path) { const e=pins.get(path);if(!e)throw Error("missing pin "+path);return e; }
  function checkRef(ref,label) { const e=pin(ref.path);ok(label,ref.blob===e.blob&&ref.bytes===e.bytes&&ref.sha256===e.sha256); }
  function verifyTree(t,label) {
    ok(label+":not-truncated",t.truncated===false);
    const paths=new Set(t.tree.map(e=>e.path));ok(label+":unique-paths",paths.size===t.tree.length);
    const dirs=[...t.tree.filter(e=>e.type==="tree"),{path:"",type:"tree",sha:t.sha}];let count=0;
    for(const dir of dirs){const prefix=dir.path?dir.path+"/":"";const children=t.tree.filter(e=>e.path.startsWith(prefix)&&!e.path.slice(prefix.length).includes("/"));
      children.sort((a,b)=>{const x=a.path.slice(prefix.length)+(a.type==="tree"?"/":""),y=b.path.slice(prefix.length)+(b.type==="tree"?"/":"");return x<y?-1:x>y?1:0;});
      let raw="";for(const e of children){const mode=e.type==="tree"?"40000":e.mode;let hex="";for(let i=0;i<40;i+=2)hex+=String.fromCharCode(parseInt(e.sha.slice(i,i+2),16));raw+=utf8(mode+" "+e.path.slice(prefix.length))+"\0"+hex;}
      ok(label+":Merkle:"+(dir.path||"/"),sha1("tree "+raw.length+"\0"+raw)===dir.sha);count++;
    }return count;
  }
  ok("subject exact final298 tree",tree.sha==="ed4e8240614998ae9b11d8cb03b5b9c3047d04ff");
  const merkleCount=verifyTree(tree,"subject");
  ok("subject 298 leaves",leafEntries.size===298);
  ok("selected exact unique inputs",selected.length===Object.keys(files).length&&new Set(selected.map(e=>e.path)).size===selected.length);
  let bytes=0;
  for(const e of selected){const b=utf8(files[e.path]);const declared=leafEntries.get(e.path);ok("input whole:"+e.path,!!declared&&declared.sha===e.blob&&declared.size===e.bytes&&b.length===e.bytes&&sha256(b)===e.sha256&&sha1("blob "+b.length+"\0"+b)===e.blob);bytes+=b.length;}
  const handoff=json("LINE_B_HANDOFF.public.json"),plan=json("READPLAN.fixed-original-logs.public.json"),provenance=json("actual/command-file-provenance.public.json");
  const job="1a1ad0a9524-fc05-5839",D="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-x230-transfer-r1/control",X="/home/qian/heptabao-same-root-publication-normal-20261105-r1";
  const corePath=D+"/result.public.json",receiptPath=X+"/artifacts/transfer.result.public.json";
  ok("original job in handoff",handoff.job_id===job);
  ok("fixed-plan pin",pin("READPLAN.fixed-original-logs.public.json").blob==="99770e25ee67d5fd192b913c3a0871125e036557");
  ok("plan only 69 actual small and 2 NUL info",plan.receiver_small_actual_reads.length===61&&plan.desktop_fixed_logs.length===8&&plan.receiver_large_info_only.length===2&&plan.nul_body_submitted===false&&plan.new_product_actions===false);
  const batchByName=new Map(plan.batches.map(b=>[b.label,b]));ok("five original fixed batches",equal(plan.batches.map(b=>b.label),["receiver-logs-01","receiver-logs-02","receiver-logs-03","receiver-logs-04","desktop-logs-01"]));
  const allNames=[...new Set(Object.keys(files).filter(k=>k.startsWith("observations/")).map(k=>k.split("/")[1]))].sort();
  const inheritedNames=["nul-index-info","nul-tree-info"];
  const names=allNames.filter(x=>!inheritedNames.includes(x));
  ok("18 new chains and 2 inherited",allNames.length===20&&names.length===18&&inheritedNames.every(n=>allNames.includes(n)));
  const nativeByName={},reqByName={};let pageCount=0,payloadBytes=0;
  for(const name of names) {
    const dir="observations/"+name+"/",req=json(dir+"request.original.json"),a=originalSDK(dir+"admission.original.sdk.json",dir+"admission.original.json",name+":ACK"),s=originalSDK(dir+"status.original.sdk.json",dir+"status.original.json",name+":status");
    ok(name+":exact request outer shape",equal(Object.keys(req).sort(),["idempotency_key","operation"])&&equal(Object.keys(req.operation).sort(),["arguments","tool"]));
    ok(name+":unique request key",typeof req.idempotency_key==="string"&&!keys.has(req.idempotency_key));keys.add(req.idempotency_key);
    ok(name+":ACK distinct operation ID",/^[0-9a-f]{64}$/.test(a.operation_id)&&!ids.has(a.operation_id));ids.add(a.operation_id);
    ok(name+":ACK tool-binding and no retry",a.tool_name===req.operation.tool&&a.automatic_retry===false&&a.reused===false&&a.admission_is_not_dispatch_completion===true);
    ok(name+":same-ID closed inactive status",s.operation_id===a.operation_id&&s.tool_name===req.operation.tool&&s.async_state==="completed"&&s.result_state==="stored_observed"&&s.owned_future_active===false&&s.payload_available===true&&s.automatic_retry===false);
    const paths=Object.keys(files).filter(k=>k.startsWith(dir+"pages/")&&/\/\d{6}\.original\.json$/.test(k)).sort();
    const sdkPaths=Object.keys(files).filter(k=>k.startsWith(dir+"pages/")&&/\/\d{6}\.original\.sdk\.json$/.test(k)).sort();
    ok(name+":all page pairs only",equal(sdkPaths,paths.map(k=>k.replace(/\.original\.json$/,".original.sdk.json")))&&paths.length>0);
    let payload="",expectedTotal=null,expectedHash=null;
    for(let i=0;i<paths.length;i++){
      const path=paths[i],pg=originalSDK(path.replace(/\.original\.json$/,".original.sdk.json"),path,name+":page"+i),chunk=decode64(pg.data_base64),offset=Number(path.match(/\/(\d{6})\.original\.json$/)[1]);
      if(i===0){expectedTotal=pg.total_bytes;expectedHash=pg.result_sha256;}
      ok(name+":page"+i+":same-ID immutable original",pg.operation_id===a.operation_id&&pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      ok(name+":page"+i+":contiguous bounded range",Number.isSafeInteger(pg.offset)&&pg.offset===offset&&pg.offset===payload.length&&chunk.length>0&&chunk.length<=16384&&pg.next_offset===pg.offset+chunk.length&&pg.next_offset<=pg.total_bytes);
      ok(name+":page"+i+":whole identity and exact EOF",pg.total_bytes===expectedTotal&&pg.result_sha256===expectedHash&&pg.eof===(i===paths.length-1)&&(pg.eof?pg.next_offset===pg.total_bytes:pg.next_offset<pg.total_bytes));
      payload+=chunk;pageCount++;
    }
    ok(name+":full payload exact bytes and hash",payload.length===expectedTotal&&sha256(payload)===expectedHash&&payload===utf8(files[dir+"payload.original.json"]));
    const original=json(dir+"payload.original.json");
    ok(name+":original native success one text",original.resultType==="complete"&&original.isError===false&&Array.isArray(original.content)&&original.content.length===1&&original.content[0].type==="text");
    ok(name+":native original text byteexact",original.content[0].text===files[dir+"native.original.json"]);
    const native=lossless(original.content[0].text);nativeByName[name]=native;reqByName[name]=req;
    const h=handoff.observations.filter(x=>x.label===name);ok(name+":one handoff chain",h.length===1&&h[0].operation_id===a.operation_id&&h[0].pages===paths.length);
    for(const field of ["status_native","status_sdk","payload","native"])checkRef(h[0][field],name+":handoff "+field+" pin");
    obs.push({name,operation_id:a.operation_id,tool:req.operation.tool,request_blob:pin(dir+"request.original.json").blob,payload_blob:pin(dir+"payload.original.json").blob,payload_bytes:payload.length,payload_sha256:expectedHash,native_blob:pin(dir+"native.original.json").blob,pages:paths.length,completed_stored_inactive:true});
    payloadBytes+=payload.length;
  }
  ok("26 new immutable pages",pageCount===26);
  const roleNames=["heptabao-server","native-build.public.json","result.public.json","canonical-4e808-full.bundle","source-export.result.public.json","normal61-result.public.json","groups.json"];
  for(const name of names) {
    let expectedOp,expectedKey="heptabao-4e808-x230-relay-"+name+"-r1";
    if(name==="authority"){expectedOp={tool:"process_status",arguments:{host:"desktop",job_id:job}};expectedKey="heptabao-4e808-x230-relay-observe-authority-r1";}
    else if(name==="streams"){expectedOp={tool:"process_read",arguments:{host:"desktop",job_id:job,limit:16384,stdout_offset:0,stderr_offset:0}};expectedKey="heptabao-4e808-x230-relay-observe-streams-r1";}
    else if(name==="core-info"){expectedOp={tool:"file_info",arguments:{host:"desktop",path:corePath}};expectedKey="heptabao-4e808-x230-relay-observe-core-info-r1";}
    else if(name==="core-body"){expectedOp={tool:"binary_read",arguments:{host:"desktop",path:corePath,expected_version:nativeByName["core-info"].version,offset:0,limit:65536}};expectedKey="heptabao-4e808-x230-relay-observe-core-body-r1";}
    else if(name==="receiver-receipt-info")expectedOp={tool:"file_info",arguments:{host:"x230",path:receiptPath}};
    else if(name==="receiver-receipt-body")expectedOp={tool:"binary_read",arguments:{host:"x230",path:receiptPath,expected_version:nativeByName["receiver-receipt-info"].version,offset:0,limit:65536}};
    else if(/^dest-info-[0-6]$/.test(name))expectedOp={tool:"file_info",arguments:{host:"x230",path:X+"/artifacts/"+roleNames[Number(name.slice(-1))]}};
    else if(batchByName.has(name)){const b=batchByName.get(name);expectedOp={tool:"read_multiple_files",arguments:{host:b.host,paths:b.paths,max_file_bytes:65536,max_response_bytes:131072}};}
    else throw Error("unexpected observer "+name);
    ok(name+":exact typed request matches fixed scope",objEqual(reqByName[name],{idempotency_key:expectedKey,operation:expectedOp}));
  }
  const authority=nativeByName.authority,streams=nativeByName.streams;
  ok("authority original job and complete durable",authority.job_id===job&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false);
  ok("streams original job",streams.job_id===job);
  for(const role of ["stdout","stderr"]){const x=streams[role];let b="";ok(role+":valid original hex",/^(?:[0-9a-f]{2})*$/.test(x.bytes_hex));for(let i=0;i<x.bytes_hex.length;i+=2)b+=String.fromCharCode(parseInt(x.bytes_hex.slice(i,i+2),16));ok(role+":whole terminal stream bytes",x.offset===0&&x.next_offset===x.size&&x.eof===true&&b.length===x.size&&b===utf8(x.text)&&x.text===files["actual/"+role+".original.txt"]&&authority.log_bytes[role].seen===x.size&&authority.log_bytes[role].stored===x.size);}
  for(const [bodyName,infoName,outPath] of [["core-body","core-info","actual/result.public.json"],["receiver-receipt-body","receiver-receipt-info","actual/receiver.result.original.json"]]){
    const n=nativeByName[bodyName],info=nativeByName[infoName],b=decode64(n.data_base64);
    ok(bodyName+":version-bound whole body",n.path===info.path&&n.version===info.version&&n.offset===0&&n.next_offset===n.size&&n.eof===true&&n.size===info.size&&b.length===info.size&&sha256(b)===info.sha256&&n.chunk_sha256===info.sha256&&b===utf8(files[outPath]));
  }
  function full9(info){const v=info.version.split(":");if(v.length!==5||!v.every(x=>/^\d+$/.test(x)))throw Error("bad full version");return[v[0],v[1],String(info.metadata.uid),String(info.metadata.gid),String(32768+info.mode),String(info.metadata.link_count),String(info.size),v[3],v[4]];}
  for(const name of ["core-info","receiver-receipt-info",...roleNames.map((_,i)=>"dest-info-"+i)]){
    const n=nativeByName[name];ok(name+":native returned exact requested path",n.path===reqByName[name].operation.arguments.path);
    ok(name+":unrounded version size and metadata",n.version.split(":")[2]===String(n.size)&&n.metadata.mode===n.mode&&n.metadata.link_count===1&&n.metadata.uid===1000&&n.metadata.gid===1000&&/^[0-9a-f]{64}$/.test(n.sha256));
  }
  const dest=json("actual/seven-destination-bindings.public.json");ok("seven destination table length",dest.files.length===7&&dest.atomic_snapshot===false);
  for(let i=0;i<7;i++){const row=dest.files[i],n=nativeByName["dest-info-"+i];ok("destination table exact native projection:"+i,row.index===i&&row.path===n.path&&row.bytes===n.size&&row.sha256===n.sha256&&row.version===n.version&&row.mode===n.mode&&equal(row.full9_decimal,full9(n)));checkRef(row.native,"destination native pin:"+i);}
  ok("receiver receipt handoff exact metadata projection",handoff.receiver_receipt_independent_info.path===nativeByName["receiver-receipt-info"].path&&handoff.receiver_receipt_independent_info.bytes===nativeByName["receiver-receipt-info"].size&&handoff.receiver_receipt_independent_info.sha256===nativeByName["receiver-receipt-info"].sha256&&handoff.receiver_receipt_independent_info.version===nativeByName["receiver-receipt-info"].version&&equal(handoff.receiver_receipt_independent_info.full9_decimal,full9(nativeByName["receiver-receipt-info"])));
  const expectedSmall=[...plan.receiver_small_actual_reads,...plan.desktop_fixed_logs];
  ok("fixed small path set 69 unique",expectedSmall.length===69&&new Set(expectedSmall.map(x=>x.path)).size===69);
  const nativeSmall=new Map();
  for(const batch of plan.batches){const n=nativeByName[batch.label];ok(batch.label+":independent complete UTF8 files",n.encoding==="utf-8"&&n.truncated===false&&n.atomic_snapshot===false&&n.snapshot_scope==="independent_file"&&Array.isArray(n.files)&&equal(n.files.map(x=>x.path),batch.paths));
    for(const f of n.files){const b=utf8(f.text);ok(batch.label+":file whole:"+f.path,!nativeSmall.has(f.path)&&f.eof===true&&b.length===f.size&&sha256(b)===f.sha256&&typeof f.version==="string"&&f.version.split(":").length===5&&f.version.split(":")[2]===String(f.size));nativeSmall.set(f.path,{file:f,observation:batch.label});}
  }
  ok("only exact 69 requested small paths returned",nativeSmall.size===69&&expectedSmall.every(x=>nativeSmall.has(x.path)));
  ok("provenance origin counts",provenance.actual_small_files===69&&provenance.reused_canonical_nul_files===2&&provenance.current_native_nul_body_rpc_count===0&&provenance.files.length===71);
  const smallRows=provenance.files.filter(x=>x.method==="actual-native-read_multiple_files");
  ok("exact 69 unique archived small representations",smallRows.length===69&&new Set(smallRows.map(x=>x.archive_path)).size===69&&new Set(smallRows.map(x=>x.native_path)).size===69);
  let smallBytes=0;
  for(const row of smallRows){const n=nativeSmall.get(row.native_path);ok("small archive:"+row.archive_path,!!n&&n.observation===row.observation&&n.file.text===files[row.archive_path]&&row.bytes===n.file.size&&row.sha256===n.file.sha256&&row.version===n.file.version&&pin(row.archive_path).sha256===row.sha256&&pin(row.archive_path).bytes===row.bytes);const expectedPrefix=row.observation==="desktop-logs-01"?"commands/desktop/":"commands/receiver/";ok("small archive mapping:"+row.archive_path,row.archive_path===expectedPrefix+row.native_path.split("/").pop());smallBytes+=row.bytes;extractions.push({archive_path:row.archive_path,native_path:row.native_path,observation:row.observation,bytes:row.bytes,sha256:row.sha256,version:row.version,blob:pin(row.archive_path).blob});}
  ok("no extra command body archives",Object.keys(files).filter(k=>k.startsWith("commands/")).length===69);
  const reviewPath="reference/NUL-current-info-root-review.original.json",goPath="reference/NUL-content-reuse-GO.original.json",review=json(reviewPath),go=json(goPath);
  ok("exact inherited root27 review pin",pin(reviewPath).blob==="71591cba75f3e978f82579524d6ab3163cd2450e"&&review.checks_passed===27&&review.metadata_packet==="77a457ec134d50f03e388e629953d67cc302e9d8");
  ok("exact content-only separate GO",pin(goPath).blob==="200c32f98fe0bf5885a2cb90e7f407119bdbef92"&&go.current_X230_info_root_review.blob===pin(reviewPath).blob&&go.current_X230_info_root_review.sha256===pin(reviewPath).sha256&&go.original_relay_job==="desktop/"+job&&go.authorized_delta.current_host_large_body_RPC_count===0);
  ok("inherited metadata exact tree",inheritedTree.sha===review.metadata_packet);
  const inheritedMerkle=verifyTree(inheritedTree,"inherited metadata");
  for(const name of inheritedNames){const prefix="observations/"+name+"/";const old=inheritedTree.tree.filter(e=>e.type==="blob"&&e.path.startsWith(prefix)),now=tree.tree.filter(e=>e.type==="blob"&&e.path.startsWith(prefix));ok(name+":entire old metadata chain unchanged",old.length===9&&equal(old.map(e=>[e.path,e.sha,e.size]),now.map(e=>[e.path,e.sha,e.size])));const m=review.files.find(x=>x.current_info_blob===pin(prefix+"native.original.json").blob);ok(name+":root27 exact native and operation inherited",!!m&&m.current_host_body_RPC_count===0);ok(name+":unique inherited operation",!ids.has(m.current_info_operation));ids.add(m.current_info_operation);inherited.push({name,operation_id:m.current_info_operation,pages:1,root_review_blob:pin(reviewPath).blob,original_metadata_packet:inheritedTree.sha,exact_original_files:old.map(e=>({path:e.path,blob:e.sha,bytes:e.size})),current_native_body_rpc_count:0});}
  const reused=provenance.files.filter(x=>x.method==="root-approved-canonical-complete-bytes-reuse");
  ok("two explicit reuse rows only",reused.length===2&&review.files.length===2);
  for(const row of reused){const r=review.files.find(x=>x.path===row.native_path);const leaf=leafEntries.get(row.archive_path);ok("reused provenance:"+row.archive_path,!!r&&row.bytes===r.bytes&&row.sha256===r.sha256&&row.version===r.version&&row.current_file_info===r.current_info_blob&&row.current_native_body_rpc_count===0&&row.approval===pin(goPath).blob&&leaf.sha===r.reconstructed_content_blob&&leaf.size===r.bytes);ok("separate GO repeats current X230 binding:"+row.archive_path,go.files.some(x=>objEqual(x,r)));}
  ok("aggregate20/28 original chains",obs.length+inherited.length===20&&pageCount+inherited.length===28&&handoff.returned_native_operations===20&&handoff.immutable_page_count===28&&ids.size===20);
  ok("old relay UNKNOWN and no product claim unchanged",handoff.original_relay_state==="UNKNOWN"&&handoff.original_relay_termination_proven===false&&handoff.product_processes_started===0);
  return {schema:"heptabao.ha-validation.x230-independent-read-chain-peer.r1",status:"PASS_SCOPED_ORIGINAL_READ_CHAINS",subject_tree:tree.sha,input_files:selected.length,input_bytes:bytes,subject_Merkle_nodes_verified:merkleCount,inherited_Merkle_nodes_verified:inheritedMerkle,checks_passed:checks.length,checks,new_chains:obs,new_original_operations:18,new_immutable_pages:26,new_payload_bytes:payloadBytes,inherited_chains:inherited,inherited_original_operations:2,inherited_immutable_pages:2,aggregate_original_operations:20,aggregate_immutable_pages:28,small_files:69,small_bytes:smallBytes,small_extractions:extractions,NUL_content_source:"existing deterministic canonical representations, separately approved and tied to current X230 metadata; not current-host body reads",current_host_NUL_body_RPC_count:0,Runtime_calls:0,product_cases_executed:0,author_1013_verifier_executed:false,core_Git_semantics_rechecked:false,held_fence_semantics_rechecked:false,old_relay_state:"UNKNOWN",scope_limits:["Original SDK archives and payload bytes are verified; delivery_proven=false is not promoted to proof of external effects.","Independent-file observations are not one atomic filesystem snapshot.","No X230 product/full34/comparison69/HA or LAN live qualification is granted.","Two NUL metadata chains inherit exact root27 qualification; this execution newly checks only the other18 chains."]};
}
