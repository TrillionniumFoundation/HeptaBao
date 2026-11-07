async function verifyDualBundleBodySource(files) {
 const checks=[];function ok(v,label){checks.push({label,pass:!!v});if(!v)throw Error(label);}
 const p=JSON.parse(files["PLAN.public.json"]),bindings=JSON.parse(files["BINDINGS.public.json"]);
 const donor=files["donor-body-journal.original.js"],pure=files["pure_helpers.original.js"];
 function pinEq(raw,pin){return JSON.stringify(gitBlobMeta(raw))===JSON.stringify(pin);}
 ok(bindings.length===2&&bindings.map(x=>x.tag).join(",")==="mac,x230","two ordered bindings");
 ok(pinEq(donor,p.donorJournal),"whole donor journal");
 const actual=JSON.parse(files["INFO-ACTUAL-BINDINGS.original.json"]);
 for(const b of bindings) {
  const t=b.tag,source=files[t+".journal.source.js"],stateRaw=files[t+".INFO-state.original.json"],s=JSON.parse(stateRaw);
  let expected=donor;for(const e of b.edits){ok(expected.split(e.before).length===2,t+" unique "+e.name);expected=expected.replace(e.before,e.after);}
  ok(expected===source&&b.edits.length===6,t+" only six fixed constants");
  const marker="const GF_BUNDLE_BODY_PAGE_BYTES = 16384;";
  ok(source.slice(source.indexOf(marker))===donor.slice(donor.indexOf(marker)),t+" every function byte unchanged");
  ok(pinEq(source,b.journal)&&pinEq(files[t+".request.exact.json"],b.request),t+" exact request and journal");
  ok(applyStrict(donor,files[t+".donor.forward.diff"])===source&&applyStrict(source,files[t+".donor.reverse.diff"])===donor,t+" strict donor bidirectional");
  const before=files[t+".INFO-journal.original.js"];
  ok(applyStrict(before,files[t+".INFO-to-BODY.forward.diff"])===source&&applyStrict(source,files[t+".INFO-to-BODY.reverse.diff"])===before,t+" exact executed INFO to BODY bidirectional");
  ok(pinEq(stateRaw,b.state)&&pinEq(files[t+".INFO-native.original.json"],b.expected.infoNative),t+" original actual state and native");
  const a=actual.find(x=>x.tag===t),v=JSON.parse(files[t+".INFO-native.original.json"]),q=JSON.parse(files[t+".request.exact.json"]);
  ok(a.operation===b.expected.infoOperation&&v.version===b.expected.version&&v.sha256===b.expected.sha256&&v.size===b.expected.bytes,t+" actual original operation version size SHA");
  ok(Object.keys(s.calls).length===3&&s.completedObservers.length===1&&!s.paused&&s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight,t+" three original calls closed");
  ok(s.goRaw===files["INFO-GO.original.json"]&&s.bundleBodyGO===undefined,t+" old INFO GO retained no BODY admission");
  ok(JSON.stringify(s.bundleInfo.derivedFull9)===JSON.stringify(b.expected.full9),t+" lossless actual full9");
  ok(q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===v.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===v.size&&q.operation.arguments.expected_version===v.version,t+" one exact original version whole-file range");
  const privateMap=new Map([[b.slot,JSON.parse(stateRaw)],[b.slot+":closed_native:"+a.operation,files[t+".INFO-native.original.json"]]]);
  const archived=[];const fakeArchive=async x=>{archived.push(x);return {whole:true,tree:"pure-only",entries:[]};};
  const noTools=new Proxy({}, {get(){throw Error("pure verifier has no tools");}});
  const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",pure+"\n"+source+"\nreturn {gfRun};")((k,v)=>privateMap.set(k,v),k=>privateMap.get(k),noTools,fakeArchive);
  const go={authorization:"GO",scope:"canonical_bundle_binary_read_ranges_only",info_operation:a.operation,maximum_binary_read_starts:1,immutable_body_page_bytes:16384,fixed_bundle:{path:v.path,bytes:v.size,sha256:v.sha256,version:v.version},exact_requests:[b.request],pureVerifierOnly:true};
  const goRaw=JSON.stringify(go,null,2)+"\n",goPin=gitBlobMeta(goRaw);
  const authorization=await api.gfRun("authorize_bundle_body",{goRaw,goPin,goWholeReadback:true});
  ok(authorization.ok&&JSON.stringify(privateMap.get(b.slot).calls)===JSON.stringify(s.calls),t+" private authorize preserves original call map");
  const prep=await api.gfRun("prepare",{kind:"operation_start",requestRaw:files[t+".request.exact.json"],callKey:"pure-body-only"});
  ok(prep.ok&&archived.length===1&&JSON.parse(archived[0].texts["armed.json"]).rootGo.blob===goPin.blob,t+" actual prepare selects new BODY GO");
  ok(JSON.stringify(Object.fromEntries(Object.keys(s.calls).map(k=>[k,privateMap.get(b.slot).calls[k]])))===JSON.stringify(s.calls),t+" private prepare keeps all three old calls");
 }
 ok(p.totalWholeBinaryBytes===bindings.reduce((n,b)=>n+b.expected.bytes,0)&&p.totalBodyRanges===2,"two bodies 8068 bytes");
 ok(p.limits.immutableBodyPageBytes===16384&&p.limits.oldInfoPageBytes===8192&&p.limits.statusPerOriginalID===8&&p.limits.pagesPerOriginalID===128&&p.limits.payloadPerOriginalID===1048576&&p.limits.MacCarrierCap===262144,"original bounded limits unchanged");
 return {schema:"heptabao.source-verification.v1",pass:true,check_count:checks.length,checks,NativeCalls:0,realSlotsMutated:false,purePrivateArchiveOnly:true};
}
