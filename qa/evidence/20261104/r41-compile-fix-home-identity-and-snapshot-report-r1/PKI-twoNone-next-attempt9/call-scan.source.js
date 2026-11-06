function calls(raw) {
 const needle="dispatch_native_authorized_subrequest",out=[];
 for(let from=0;;) {
  const p=raw.indexOf(needle,from);if(p<0)break;from=p+needle.length;
  const line=raw.slice(0,p).split("\n").length;
  if(/\bfn\s+$/.test(raw.slice(Math.max(0,p-10),p))){out.push({line,kind:"definition",parameters:14});continue;}
  let i=from;while(/\s/.test(raw[i]))i++;if(raw[i]!=="(")throw Error("not direct call");
  const start=++i;let depth=0,quote=null,escape=false,argStart=start,args=[];
  for(;i<raw.length;i++){const c=raw[i];if(quote){if(escape){escape=false;continue;}if(c==="\\"){escape=true;continue;}if(c===quote)quote=null;continue;}if(c==='"'){quote=c;continue;}if("([{".includes(c)){depth++;continue;}if(")]}".includes(c)){if(c===")"&&depth===0){const tail=raw.slice(argStart,i).trim();if(tail)args.push(tail);break;}depth--;continue;}if(c===","&&depth===0){args.push(raw.slice(argStart,i).trim());argStart=i+1;}}
  if(i>=raw.length||depth!==0)throw Error("call syntax scan");
  out.push({line,kind:"call",arguments:args.length,lastArgument:args.at(-1),argumentList:args});
 }
 return out;
}
