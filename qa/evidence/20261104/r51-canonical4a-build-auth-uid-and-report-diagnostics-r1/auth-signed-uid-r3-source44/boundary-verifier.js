function verifyFixedPsSignedUidBoundaries(controller,manager,cases){
 const guards=[controller,manager].map(text=>{
  const m=text.match(/re\.fullmatch\(r'([^']+)',fields\[3\]\) is not None,'typed_process_row'/);
  if(!m||m[1]!=="-?[0-9]{1,10}"||
     !text.includes("len(fields)==5 and all(x.isdecimal() for x in fields[:3])")||
     !text.includes("need(-(1<<31)<=uid<=(1<<32)-1,'typed_process_row')"))
   throw new Error("source_bound_UID_rule");
  return new RegExp("^(?:"+m[1]+")(?![\\s\\S])");
 });
 const checks=[];
 for(const c of cases){
  const outcomes=guards.map(re=>{
   const f=c.fields;
   const syntax=f.length===5&&f.every(x=>typeof x==="string"&&/^[\x00-\x7f]*$/.test(x))&&
    f.slice(0,3).every(x=>x.length>0&&[...x].every(c=>c>="0"&&c<="9"))&&re.test(f[3]);
   const value=syntax?BigInt(f[3]):null;
   const accepted=syntax&&value>=-(1n<<31n)&&value<=(1n<<32n)-1n;
   return {accepted,uid:accepted?value.toString():null};
  });
  const passed=outcomes.every(x=>x.accepted===c.accepted&&(!c.accepted||x.uid===c.uid));
  checks.push({name:c.name,passed,controller:outcomes[0],manager:outcomes[1]});
 }
 return {schema:"heptabao.fixed-ps-signed-uid-pure-boundaries.r3",passed:checks.every(x=>x.passed),
  caseCount:cases.length,checks,execution:"pure V8 model bound to both exact Python predicates; no Python/ps/host execution",
  acceptedUidValuesArePreservedSignedIntegers:true,NativeCallsAdded:0,productQualification:false};
}
