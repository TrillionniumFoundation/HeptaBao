function verifyDefaultLibtestMinimalFix(files) {
 const proposal=JSON.parse(files["PROPOSAL.original.json"]), checks=[];
 function check(name,value,evidence){if(!value)throw Error(name);checks.push({name,pass:true,evidence});}
 const names=[["deadline.before.rs","deadline.after.rs"],["support.before.rs","support.after.rs"],["audit.before.rs","audit.after.rs"]];
 const canonical=new Map(files["candidate-index.original.txt"].trimEnd().split("\n").map(l=>{const [p,mode,blob,bytes]=l.split("\0");return[p,{mode,blob,bytes:Number(bytes)}];}));
 for(let i=0;i<3;i++){
  const [b,a]=names[i],c=proposal.changes[i],bm=gitBlobMeta(files[b]),am=gitBlobMeta(files[a]),d=files["change"+i+".forward.diff"];
  check("before whole "+i,JSON.stringify(bm)===JSON.stringify(c.before),bm);
  check("after whole "+i,JSON.stringify(am)===JSON.stringify(c.after),am);
  const e=canonical.get(c.path);
  check("canonical 576 before "+i,e?.blob===bm.blob&&e?.bytes===bm.bytes&&e?.mode==="100644",e);
  check("diff whole "+i,JSON.stringify(gitBlobMeta(d))===JSON.stringify(c.forward),c.forward);
  check("strict forward "+i,applyStrict(files[b],d,false)===files[a],c.path);
  check("strict reverse "+i,applyStrict(files[a],d,true)===files[b],c.path);
  check("hunks "+i,(d.match(/^@@ /gm)||[]).length===c.hunks,c.hunks);
  const fn=s=>Array.from(s.matchAll(/\bfn\s+([A-Za-z_][A-Za-z_0-9]*)/g),m=>m[1]);
  check("function names "+i,JSON.stringify(fn(files[b]))===JSON.stringify(fn(files[a])),fn(files[a]));
 }
 for(let i=0;i<2;i++){
  const [b,a]=names[i],pad=i===0?"        ":"                ";
  const anchor=pad+"forward_handler: Arc::new(Mutex::new(None)),\n";
  const added=pad+'#[cfg(feature = "native-v6-ha")]\n'+pad+"snapshot_forward_handler: Arc::new(Mutex::new(None)),\n"+pad+'#[cfg(feature = "native-v6-ha")]\n'+pad+"snapshot_server_pins: BTreeMap::new(),\n";
  check("only gated empty fields "+i,files[b].split(anchor).length===2&&files[b].replace(anchor,anchor+added)===files[a],{handler:"Arc<Mutex<Option<SnapshotForwardHandler>>> = Arc::new(Mutex::new(None))",pins:"BTreeMap<u64,Vec<[u8;32]>> = BTreeMap::new()"});
  check("original fixture native and listener absent "+i,files[b].includes("native_v6: None,")&&files[b].includes("listener: None,"),b);
 }
 const expected=files["audit.before.rs"].replace("assert!(before.1.epoch_transitions().is_empty());","assert_eq!(before.1.epoch_transitions().len(), 0);").replace("assert!(after.1.epoch_transitions().is_empty());","assert_eq!(after.1.epoch_transitions().len(), 0);");
 check("only two exact zero-length predicates",expected===files["audit.after.rs"],"all remaining bytes unchanged, including deadlines, scope drops, reads and assertions");
 check("two exact assertions retained",(files["audit.after.rs"].match(/assert_eq!\((before|after)\.1\.epoch_transitions\(\)\.len\(\), 0\);/g)||[]).length===2,2);
 return {schema:"heptabao.c.default-libtest-minimal-fix-independent-source-checks.r1",pass:true,check_count:checks.length,checks,scope:"SOURCE_ONLY",rust_compiled:false,rust_tests_executed:false,native_calls:0};
}
