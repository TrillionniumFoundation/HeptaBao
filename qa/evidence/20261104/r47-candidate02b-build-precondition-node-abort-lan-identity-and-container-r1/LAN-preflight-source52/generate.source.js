function makeFinalLanRequests(probe, baseJournal) {
 const sourcePin=gitBlobMeta(probe);
 const roles={
  mac:{native:"mac",alias:"mac-ts",python:"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"},
  rog:{native:"rog",alias:"rog-ts",python:"/usr/bin/python3"},
  pocket4:{native:"pocket4",alias:"pocket4-ts",python:"/usr/bin/python3"}
 };
 const out=[];
 for(const role of ["pocket4","rog","mac"]) {
  const r=roles[role];
  for(const route of ["native","ssh"]) {
   const key="heptabao-final-lan-identity-"+role+"-"+route+"-20261106-r1-"+sourcePin.sha256.slice(0,8);
   const q=route==="native"
    ?{host:r.native,executable:r.python,args:["-I","-S","-B","-c",probe,role],cwd:"/",timeout_seconds:30,idempotency_key:key}
    :{host:"desktop",executable:"/usr/bin/ssh",args:[
      "-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes",
      "-o","ConnectTimeout=5","-o","ConnectionAttempts=1",
      "-o","ControlMaster=no","-o","ControlPath=none",
      "-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no",
      "-o","ProxyCommand=none","-o","ProxyJump=none",
      "-o","CanonicalizeHostname=no","-o","RequestTTY=no",
      r.alias,"exec "+r.python+" -I -S -B - "+role
     ],cwd:"/",stdin:probe,timeout_seconds:30,idempotency_key:key};
   const raw=JSON.stringify(q,null,2)+"\n",pin=gitBlobMeta(raw),binding=processStartBinding(q);
   const slot="final_lan_identity_"+role+"_"+route+"_20261106_r1";
   const observerPrefix="heptabao-final-lan-identity-"+role+"-"+route+"-"+sourcePin.sha256.slice(0,8)+"-";
   let journal=baseJournal;
   const replace=(before,after)=>{
    if(journal.split(before).length!==2)throw Error("one_exact_binding");
    journal=journal.replace(before,after);
   };
   replace('const GF_SLOT = "owner_launchd_gitfirst_r1";','const GF_SLOT = "'+slot+'";');
   replace('const GF_REQUEST = {blob:"d14f62155b86924edd5632673d2e73832f7b0af5",\n bytes:76816,sha256:"ab9afbcbbdc150acd11ad9451e35e2785f8fe086d4a371c3a63d4cf0f2a087b4"};',
     "const GF_REQUEST = "+JSON.stringify(pin)+";");
   replace("^heptabao-mac-owned-launchd-readonly-e573407b-","^"+observerPrefix);
   if(q.host!=="mac") {
    replace('a.host==="mac"','a.host==="'+q.host+'"');
    replace('v.job?.host==="mac"','v.job?.host==="'+q.host+'"');
   }
   const diff=strictDiff(baseJournal,journal,"gitfirst-native-"+role+"-"+route+".js");
   if(applyStrict(baseJournal,diff)!==journal||applyStrict(journal,diff,true)!==baseJournal)
    throw Error("journal_strict_roundtrip");
   out.push({
    index:out.length,role,route,request:q,raw,pin,
    typed:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,
      canonical_bytes:gitBlobMeta(binding.canonical).bytes},
    slot,observer_key_prefix:observerPrefix,
    journal,journal_pin:gitBlobMeta(journal),journal_diff:diff,journal_diff_pin:gitBlobMeta(diff),
    submitted:false
   });
  }
 }
 return {sourcePin,observations:out};
}
