function verifyMetadata5(files,utf8,sha1,sha256){
 const checks=[], eq=(n,a,b)=>{if(JSON.stringify(a)!==JSON.stringify(b))throw Error(n);checks.push(n);};
 const pl=JSON.parse(files["PLAN.public.json"]), table=JSON.parse(files["reference/instrument12-known-and-unobserved.public.json"]);
 const old=JSON.parse(files["reference/old-index6.operation-start.request.json"]);
 eq("twelve roles",table.rows.length,12);eq("seven previously accepted",pl.accepted_independent_indices,[0,1,2,3,4,5,6]);
 eq("remaining fixed indices",pl.rows.map(x=>x.index),[7,8,9,10,11]);
 const keys=[];
 for(let i=0;i<7;i++){const info=JSON.parse(files["reference/accepted-info-"+i+".public.json"]),r=table.rows[i];eq("accepted "+i+" body",info,r.independent_desktop_incoming_info);eq("accepted "+i+" observed",r.independent_info_observed,true);}
 for(const row of pl.rows){const i=row.index,r=table.rows[i],raw=files[row.request.path],request=JSON.parse(raw),b=utf8(raw);
  eq("request "+i+" all typed fields",request,row.exact_request);
  eq("request "+i+" exact keys",Object.keys(request),["idempotency_key","operation"]);
  eq("request "+i+" operation shape",Object.keys(request.operation),["tool","arguments"]);
  eq("request "+i+" argument shape",Object.keys(request.operation.arguments),["host","path"]);
  eq("request "+i+" file_info",request.operation.tool,"file_info");
  eq("request "+i+" host","desktop",request.operation.arguments.host);
  eq("request "+i+" path",request.operation.arguments.path,r.desktop_incoming_receiver.path);
  eq("request "+i+" index key",request.idempotency_key,old.idempotency_key.replace("-6-","-"+i+"-"));
  if(request.idempotency_key.length<1||request.idempotency_key.length>128)throw Error("key bytes");keys.push(request.idempotency_key);
  eq("request "+i+" pin",{blob:sha1("blob "+b.length+"\0"+b),bytes:b.length,sha256:sha256(b)},{blob:row.request.blob,bytes:row.request.bytes,sha256:row.request.sha256});
  eq("request "+i+" historical receiver",row.expected_historical_receiver,r.desktop_incoming_receiver);
  eq("request "+i+" still no independent info",r.independent_desktop_incoming_info,null);
  eq("request "+i+" no claimed new observation",row.new_observed_info,null);
  eq("request "+i+" no submission",row.submitted,false);
  eq("request "+i+" no operation ID",row.actual_operation_id,null);
 }
 eq("five unique keys",new Set(keys).size,5);
 const direct7=JSON.parse(files["history/direct7.request.json"]);
 eq("historical direct7 has no key",Object.prototype.hasOwnProperty.call(direct7,"idempotency_key"),false);
 eq("historical direct7 same fixed path",direct7.path,pl.rows[0].exact_request.operation.arguments.path);
 eq("historical UNKNOWN retained",pl.historical_unknowns.two_direct_file_info_timeouts.status,"UNKNOWN_PRESERVED");
 eq("index6 earlier lost ACK retained",pl.historical_unknowns.index6_operation_start_lost_ACK.first_lost_ACK_future_not_proved_closed,true);
 eq("no Runtime",pl.Runtime_calls,0);eq("no target actuals",pl.H2_target_actual_identities,0);
 return {schema:"heptabao.h2.metadata5-source-checks.v1",status:"PASS_SOURCE_ONLY",checks_count:checks.length,checks,Runtime_calls:0,source_modules_executed:0,not_authorization:true};
}
