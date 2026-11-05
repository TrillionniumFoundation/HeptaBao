// Exact public receipt reconstruction from archived raw top-level JSON tokens.
// Does not read files, contact a host, evaluate a candidate module, or normalize numbers.
const need=(value,message)=>{if(!value)throw Error(message)};
function fields(raw){
 const t=raw.trim();need(t[0]==="{"&&t.at(-1)==="}","object");
 const result=[];let i=1;
 while(i<t.length-1){
  while(/\s/.test(t[i]))i++;
  const k0=i;need(t[i]==='"',"key");i++;let escape=false;
  for(;i<t.length;i++){const c=t[i];if(escape){escape=false;continue}if(c==="\\"){escape=true;continue}if(c==='"'){i++;break}}
  const key=JSON.parse(t.slice(k0,i));while(/\s/.test(t[i]))i++;need(t[i++]===":","colon");const v0=i;let depth=0,instr=false;escape=false;
  for(;i<t.length;i++){const c=t[i];if(instr){if(escape)escape=false;else if(c==="\\")escape=true;else if(c==='"')instr=false;continue}if(c==='"'){instr=true;continue}if(c==="["||c==="{")depth++;else if(c==="]"||c==="}"){if(depth===0)break;depth--}else if(c===","&&depth===0)break}
  result.push({key,value:t.slice(v0,i)});
  if(t[i]===","){i++;continue}need(t[i]==="}"&&i===t.length-1,"end");break;
 }
 need(new Set(result.map(x=>x.key)).size===result.length,"duplicate");return result;
}
const finalKeys=new Set(["heldT5Final","commands","allOwnedCommandsStopped","allOwnedDescriptorsClosed","outcomeUnknown","elapsedSeconds","candidateReceiptSha256","originalDeadlineMetAfterClosure","authoritativeExitZeroRequired"]);
function reconstruct_precleanup_candidate(raw){
  const whole=JSON.parse(raw);
  need(whole.ok===true && whole.preparedCandidate===true,"historical final success");
  const before=fields(raw).filter(x=>!finalKeys.has(x.key))
    .map(x=>JSON.stringify(x.key)+":"+(x.key==="ok"?"false":x.value));
  return "{"+before.join(",")+"}\n";
}
