(function verify(raws){
const u=function utf8(s){const b=unescape(encodeURIComponent(s));return Array.from(b,c=>c.charCodeAt(0));};
const h=function sha256(bytes){const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],m=bytes.slice();const len=bytes.length*8;m.push(128);while(m.length%64!==56)m.push(0);const hi=Math.floor(len/4294967296),lo=len>>>0;for(const v of [hi,lo])for(let i=3;i>=0;i--)m.push((v>>>(i*8))&255);const rr=(x,n)=>(x>>>n)|(x<<(32-n));for(let j=0;j<m.length;j+=64){const w=new Array(64);for(let t=0;t<16;t++)w[t]=((m[j+4*t]<<24)|(m[j+4*t+1]<<16)|(m[j+4*t+2]<<8)|m[j+4*t+3])>>>0;for(let t=16;t<64;t++){const s0=rr(w[t-15],7)^rr(w[t-15],18)^(w[t-15]>>>3),s1=rr(w[t-2],17)^rr(w[t-2],19)^(w[t-2]>>>10);w[t]=(w[t-16]+s0+w[t-7]+s1)>>>0;}let [a,b,c,d,e,f,g,h]=H;for(let t=0;t<64;t++){const x=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[t]+w[t])>>>0,y=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;h=g;g=f;f=e;e=(d+x)>>>0;d=c;c=b;b=a;a=(x+y)>>>0;}const v=[a,b,c,d,e,f,g,h];for(let t=0;t<8;t++)H[t]=(H[t]+v[t])>>>0;}return H.map(x=>x.toString(16).padStart(8,"0")).join("");};
const h1=function sha1(bytes){const m=bytes.slice(),len=bytes.length*8;m.push(128);while(m.length%64!==56)m.push(0);for(const v of [Math.floor(len/4294967296),len>>>0])for(let i=3;i>=0;i--)m.push((v>>>(i*8))&255);const H=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0],rot=(x,n)=>(x<<n)|(x>>>(32-n));for(let j=0;j<m.length;j+=64){const w=new Array(80);for(let t=0;t<16;t++)w[t]=((m[j+4*t]<<24)|(m[j+4*t+1]<<16)|(m[j+4*t+2]<<8)|m[j+4*t+3])>>>0;for(let t=16;t<80;t++)w[t]=rot(w[t-3]^w[t-8]^w[t-14]^w[t-16],1);let[a,b,c,d,e]=H;for(let t=0;t<80;t++){let f,k;if(t<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(t<40){f=b^c^d;k=0x6ed9eba1;}else if(t<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const x=(rot(a,5)+f+e+k+w[t])>>>0;e=d;d=c;c=rot(b,30);b=a;a=x;}for(let t=0;t<5;t++)H[t]=(H[t]+[a,b,c,d,e][t])>>>0;}return H.map(x=>x.toString(16).padStart(8,"0")).join("");};
const decode=function decodeBase64(s){if(typeof s!=="string"||s.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw Error("invalid base64");const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",out=[];let n=0,bits=0;for(const c of s){if(c==="=")break;n=(n<<6)|alphabet.indexOf(c);bits+=6;if(bits>=8){bits-=8;out.push((n>>bits)&255);n&=(1<<bits)-1;}}if(n!==0)throw Error("noncanonical base64 tail");return out;};
const core=function verifyPublication(raws,u,h,h1,decode){
 const checks=[];
 function ck(ok,label){checks.push({label,ok:!!ok});if(!ok)throw Error(label);}
 function raw(path){ck(typeof raws[path]==="string","present:"+path);return raws[path];}
 function parse(path){return JSON.parse(raw(path));}
 function objEq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function blobOf(v){const b=u(v);return h1([...u("blob "+b.length+"\0"),...b]);}
 function pin(v,p,label){ck(u(v).length===p.bytes&&h(u(v))===p.sha256&&blobOf(v)===p.blob,label);}
 function nativeFromSDK(sdk,label){ck(sdk.isError===false,label+":not-error");ck(Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text",label+":one-native-text");return sdk.content[0].text;}
 const go=parse("reference/ROOT_GO.original.json"),state=parse("STATE.public.json"),closure=parse("CLOSURE.public.json");
 pin(raw("reference/ROOT_GO.original.json"),{bytes:15242,sha256:"f1fab25e085a1009c8649a0ba30a7b5ec234341cbbd4ec921f910bea69618cf5",blob:"f518cb97d0e05ff4916d64a7647aa130920d1f28"},"exact-root-GO");
 const calls=parse("calls/index.public.json").submitted_order,observers=parse("observations/index.public.json").observations;
 ck(calls.length===30&&new Set(calls.map(c=>c.label)).size===30,"thirty-unique-original-calls");
 ck(observers.length===8&&new Set(observers.map(o=>o.operation_id)).size===8,"eight-unique-original-observers");
 ck(state.runtime_call_inflight===null&&state.active_operation_id===null&&state.halted===false,"no-inflight-no-active-future");
 ck(closure.product_execution===false&&closure.process_start_submitted===0&&closure.compiled===false,"source-only");
 ck(objEq(calls.map(c=>c.label),state.submitted_requests),"submitted-order-index");
 const callMap={}; const methodCounts={};
 for(const c of calls){
  const reqRaw=raw(c.request.path),req=JSON.parse(reqRaw),intent=parse(c.intent.path),sdk=parse(c.sdk.path),nativeRaw=raw(c.native.path);
  for(const p of [c.request,c.intent,c.sdk,c.native])pin(raw(p.path),p,"whole:"+p.path);
  ck(c.ok===true&&nativeFromSDK(sdk,c.label)===nativeRaw,c.label+":original-sdk-native-exact");
  ck(intent.GO==="f518cb97d0e05ff4916d64a7647aa130920d1f28"&&intent.label===c.label&&intent.method===c.method&&objEq(intent.request,req),c.label+":intent-exact-request");
  ck(intent.request_blob===c.request.blob&&intent.request_sha256===c.request.sha256&&intent.request_bytes===c.request.bytes&&intent.process_start_authorized===false,c.label+":intent-pins");
  ck(["operation_start","operation_status","operation_result","binary_write"].includes(c.method),c.label+":method-whitelist");
  callMap[c.label]={...c,request:req,native:JSON.parse(nativeRaw),nativeRaw};
  methodCounts[c.method]=(methodCounts[c.method]||0)+1;
 }
 ck(methodCounts.operation_start===8&&methodCounts.operation_status===8&&methodCounts.operation_result===11&&methodCounts.binary_write===3,"exact-call-counts");
 const nativeMap={};let totalPages=0,totalPayload=0;
 for(const o of observers){
  const a=callMap[o.admissionLabel],s=callMap[o.statusLabel],id=o.operation_id;
  ck(a.method==="operation_start"&&a.native.operation_id===id&&a.native.reused===false,o.label+":original-admission");
  ck(s.method==="operation_status"&&s.request.operation_id===id&&s.native.operation_id===id&&s.native.async_state==="completed"&&s.native.result_state==="stored_observed"&&s.native.owned_future_active===false,o.label+":closed-status");
  ck(s.native.tool_name===a.request.operation.tool&&a.native.tool_name===a.request.operation.tool,o.label+":tool-name");
  let bytes=[],next=0,sha=null,total=null;
  for(const [i,label]of o.pageLabels.entries()){
   const p=callMap[label],n=p.native,b=decode(n.data_base64);
   ck(p.method==="operation_result"&&p.request.operation_id===id&&p.request.offset===next&&p.request.limit===8192,o.label+":page-request:"+i);
   ck(n.operation_id===id&&n.offset===next&&n.next_offset===next+b.length&&b.length<=8192&&n.immutable_snapshot===true&&n.payload_kind==="native_result",o.label+":page-range:"+i);
   if(i===0){sha=n.result_sha256;total=n.total_bytes;}
   ck(sha===n.result_sha256&&total===n.total_bytes&&n.eof===(n.next_offset===total)&&n.eof===(i===o.pageLabels.length-1),o.label+":page-whole-eof:"+i);
   bytes.push(...b);next=n.next_offset;totalPages++;
  }
  const payloadRaw=raw(o.payload.path);
  ck(objEq(bytes,u(payloadRaw))&&bytes.length===total&&h(bytes)===sha,o.label+":payload-reconstruction");
  pin(payloadRaw,o.payload,o.label+":payload-git");
  const sdk=JSON.parse(payloadRaw),nativeRaw=raw(o.native.path);
  ck(sdk.resultType==="complete"&&nativeFromSDK(sdk,o.label+":payload")===nativeRaw,o.label+":payload-native-exact");
  pin(nativeRaw,o.native,o.label+":native-git");
  nativeMap[o.label]=JSON.parse(nativeRaw);totalPayload+=bytes.length;
 }
 ck(totalPages===11,"eleven-immutable-pages");
 for(const o of go.oracle_requests){
  const req=callMap[o.role+"-admission"].request,n=nativeMap[o.role];
  pin(raw("calls/"+o.role+"-admission/request.original.json"),o.request,o.role+":fixed-request");
  ck(objEq(req,o.value)&&n.path===req.operation.arguments.path&&n.sha256===o.expected_sha256,o.role+":expected-oracle-whole");
 }
 const identities=parse("actual/input-identities.public.json").inputs;
 for(const identity of identities){
  const n=nativeMap[identity.role],v=n.version.split(":");
  ck(v.length===5&&v.every(x=>/^[0-9]+$/.test(x))&&v[2]===String(n.size),identity.role+":version-decimal-tokens");
  ck(n.mode===n.metadata.mode&&n.metadata.metadata_platform==="linux",identity.role+":metadata-mode");
  const expected=[v[0],v[1],String(n.metadata.uid),String(n.metadata.gid),String(0o100000|n.mode),String(n.metadata.link_count),v[2],v[3],v[4]];
  ck(objEq(identity.full9_decimal,expected)&&identity.version===n.version&&identity.bytes===n.size&&identity.sha256===n.sha256&&identity.path===n.path,identity.role+":lossless-full9");
 }
 for(const [i,p]of go.publication_requests.entries()){
  const role=p.role,write=callMap[role+"-write"],info=callMap[role+"-info-admission"],n=nativeMap[role+"-info"],body=callMap[role+"-body-admission"],b=nativeMap[role+"-body"];
  pin(raw("calls/"+role+"-write/request.original.json"),p.request,role+":exact-write-request");
  ck(write.request.host==="x230"&&write.request.path===p.path&&write.request.expected_version==="absent",role+":absent-write");
  const bytes=decode(write.request.data_base64),actualPath="actual/source/"+p.path.split("/").at(-1),actual=raw(actualPath);
  ck(objEq(bytes,u(actual))&&bytes.length===p.source.bytes&&h(bytes)===p.source.sha256&&blobOf(actual)===p.source.blob,role+":write-source-exact");
  ck(write.native.written===p.source.bytes&&write.native.size===p.source.bytes&&write.native.sha256===p.source.sha256&&write.native.version===n.version,role+":known-write-and-info");
  pin(raw("calls/"+role+"-info-admission/request.original.json"),go.postpublication_file_info_requests[i].request,role+":root-info-request");
  ck(objEq(info.request,go.postpublication_file_info_requests[i].value)&&n.path===p.path&&n.size===p.source.bytes&&n.sha256===p.source.sha256,role+":independent-info");
  ck(n.mode===384&&n.metadata.uid===1000&&n.metadata.gid===1000&&n.metadata.link_count===1&&(n.mode&0o022)===0,role+":actual-source-mode-owner-single-link");
  const expected=JSON.parse(JSON.stringify(go.conditional_three_body_read_requests[i].request_derivation));expected.operation.arguments.expected_version=n.version;
  ck(objEq(body.request,expected),role+":only-actual-version-derived");
  const read=decode(b.data_base64);
  ck(b.path===p.path&&b.version===n.version&&b.offset===0&&b.next_offset===p.source.bytes&&b.eof===true&&b.size===p.source.bytes&&b.chunk_sha256===p.source.sha256,role+":read-contract");
  ck(objEq(read,bytes)&&h(read)===p.source.sha256,role+":actual-full-body-exact");
 }
 const expectedOrder=[];
 for(const role of ["oracle-binary","oracle-archive"])expectedOrder.push(role+"-admission",role+"-status",role+"-page-000000");
 for(const role of ["full34","comparison69","comparison-driver"])expectedOrder.push(role+"-write",role+"-info-admission",role+"-info-status",role+"-info-page-000000",role+"-body-admission",role+"-body-status",role+"-body-page-000000",role+"-body-page-008192");
 ck(objEq(state.submitted_requests,expectedOrder),"exact-original-serial-order");
 return{schema:"heptabao.x230-publication-offline-evidence-verification.v1",status:"PASS",checks_passed:checks.length,checks,original_calls:30,original_observers:8,immutable_pages:11,payload_bytes:totalPayload,source_bytes:31119,host_io:false,product_qualification:false};
};
return core(raws,u,h,h1,decode);
})
