function makeOracleFixtureR2(originalRequestRaw,originalJournal) {
 const meta=gitBlobMeta,prior=JSON.parse(originalRequestRaw),payload=JSON.parse(prior.stdin);
 if(JSON.stringify(payload)+"\n"!==prior.stdin)throw Error("original compact payload serializer");
 const path="source/qa/openbao-acceptance/acl23_executor.py",before=payload.files[path];
 let after=before;
 const aclChanges=[
  ['"jwt_validation_pubkeys": [public_pem],','"jwt_validation_pubkeys": [public_pem[:-1]],  # Only the validated source PEM final LF.'],
  ["        self.setup_completed = False\n","        self.setup_completed = False\n        self.setup_config_projection = None\n"],
  ['        state = self.snapshot()\n        if state["config"] != self.baseline_config:\n','        state = self.snapshot()\n        self.setup_config_projection = state["config"]\n        if state["config"] != self.baseline_config:\n'],
  ['                "raw_status_normalization": False, "parity_qualified": False,\n','                "setup_config_projection": self.setup_config_projection,\n                "raw_status_normalization": False, "parity_qualified": False,\n'],
  ['                "stopped_reason": self.stopped_reason, "parity_qualified": False,\n','                "stopped_reason": self.stopped_reason, "parity_qualified": False,\n                "setup_config_projection": self.setup_config_projection,\n']
 ];
 for(const[a,b]of aclChanges){if(after.split(a).length!==2)throw Error("unique ACL change");after=after.replace(a,b);}
 const diff=strictDiff(before,after,"acl23_executor.fixture-r2.py");
 const nextPayload=JSON.parse(prior.stdin);nextPayload.files[path]=after;
 const payloadRaw=JSON.stringify(nextPayload)+"\n",payloadPin=meta(payloadRaw),aclPin=meta(after);
 const publicPem=payload.files["PUBLIC-KEY.pem"],publicRequest=publicPem.slice(0,-1);
 if(meta(publicPem).bytes!==451||!publicPem.endsWith("-----END PUBLIC KEY-----\n")
  ||meta(publicRequest).bytes!==450||publicRequest+"\n"!==publicPem)throw Error("fixed one LF public input");
 const entryBefore=prior.args[4];let entry=entryBefore;
 const sourceBytes=Object.values(nextPayload.files).reduce((n,s)=>n+meta(s).bytes,0);
 const entryBindings=[
  ["PORT = 23623","PORT = 23625"],
  ["/home/qian/heptabao-official271-acl23-oracle-20261106-r1","/home/qian/heptabao-official271-acl23-oracle-20261106-r2"],
  ['RUN_ID = "official271-acl23-r1"','RUN_ID = "official271-acl23-r2"'],
  ["PAYLOAD_BYTES = 134374","PAYLOAD_BYTES = "+payloadPin.bytes],
  ['PAYLOAD_SHA256 = "'+meta(prior.stdin).sha256+'"','PAYLOAD_SHA256 = "'+payloadPin.sha256+'"'],
  ['    "source/qa/openbao-acceptance/acl23_executor.py",\n    15599,\n    "e96451d450224abfa7eeda34622b26b1d21493867b4344aa254709348515bfc4"','    "source/qa/openbao-acceptance/acl23_executor.py",\n    '+aclPin.bytes+',\n    "'+aclPin.sha256+'"'],
  ["SOURCE_BYTES = 127119","SOURCE_BYTES = "+sourceBytes]
 ];
 for(const[a,b]of entryBindings){if(entry.split(a).length!==2)throw Error("unique entry data change");entry=entry.replace(a,b);}
 const entryPin=meta(entry),entryDiff=strictDiff(entryBefore,entry,"official271.acl23.fixture-r2.entry.py");
 const request={...prior,args:prior.args.map((x,i)=>i===4?entry:i===5?entryPin.sha256:x),stdin:payloadRaw,
  idempotency_key:"heptabao-official271-x230-acl23-oracle-r2-"+entryPin.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=meta(requestRaw),binding=processStartBinding(request);
 let journal=originalJournal;
 const journalBindings=[
  ['const GF_SLOT = "official271_x230_acl23_oracle_gitfirst_r1";','const GF_SLOT = "official271_x230_acl23_oracle_gitfirst_r2";'],
  ["const GF_REQUEST = "+JSON.stringify(meta(originalRequestRaw))+";","const GF_REQUEST = "+JSON.stringify(requestPin)+";"],
  ["/^heptabao-official271-x230-acl23-oracle-observe-r1-/","/^heptabao-official271-x230-acl23-oracle-observe-r2-/"]
 ];
 for(const[a,b]of journalBindings){if(journal.split(a).length!==2)throw Error("unique journal data binding");journal=journal.replace(a,b);}
 const journalDiff=strictDiff(originalJournal,journal,"official271.fixture-r2.journal.js");
 for(const[a,b,d]of [[before,after,diff],[entryBefore,entry,entryDiff],[originalJournal,journal,journalDiff]])if(applyStrict(a,d,false)!==b||applyStrict(b,d,true)!==a)throw Error("strict bidirectional reconstruction");
 return {before,after,diff,aclPin,aclChanges,entryBefore,entry,entryPin,entryDiff,entryBindings,
  originalJournal,journal,journalDiff,journalBindings,payload:nextPayload,payloadRaw,payloadPin,
  request,requestRaw,requestPin,typed:{sha256:binding.sha256,fingerprint_decimal:binding.native_fingerprint,canonical_bytes:utf8Bytes(binding.canonical).length},
  publicPem,publicRequest,publicPemPin:meta(publicPem),publicRequestPin:meta(publicRequest),sourceBytes};
}