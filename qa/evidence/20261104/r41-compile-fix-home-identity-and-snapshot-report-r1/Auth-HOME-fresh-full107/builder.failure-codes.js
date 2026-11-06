
function fixedPythonFailureCodes(source){
 const values=new Set();
 function skipString(i){
  const q=source[i],triple=source.slice(i,i+3)===q.repeat(3),width=triple?3:1;
  let j=i+width;
  while(j<source.length){if(source[j]==='\\'){j+=2;continue;}if(source.slice(j,j+width)===q.repeat(width))return j+width;j++;}
  throw Error('unterminated_source_string');
 }
 function argument(start){
  const stack=['('];let i=start+1,last=i;
  while(i<source.length){
   const c=source[i];
   if(c==="'"||c==='"'){i=skipString(i);continue;}
   if(c==='#'){const e=source.indexOf('\n',i);i=e<0?source.length:e+1;continue;}
   if('([{'.includes(c)){stack.push(c);i++;continue;}
   if(')]}'.includes(c)){
    const expected={')':'(',']':'[','}':'{'}[c];if(stack.pop()!==expected)throw Error('source_delimiter');
    if(stack.length===0)return{last:source.slice(last,i).trim(),end:i+1};
    i++;continue;
   }
   if(c===','&&stack.length===1)last=i+1;
   i++;
  }
  throw Error('unterminated_source_call');
 }
 for(let i=0;i<source.length;){
  const c=source[i];if(c==="'"||c==='"'){i=skipString(i);continue;}
  if(c==='#'){const e=source.indexOf('\n',i);i=e<0?source.length:e+1;continue;}
  if(/[A-Za-z_]/.test(c)){
   let j=i+1;while(j<source.length&&/[A-Za-z0-9_]/.test(source[j]))j++;
   const token=source.slice(i,j);let k=j;while(/\s/.test(source[k]||'')&&k<source.length)k++;
   if((token==='need'||token==='ManagerRefused')&&source[k]==='('){
    const a=argument(k),m=a.last.match(/^(['"])([a-z][a-z0-9_]+)\1$/);if(m)values.add(m[2]);i=a.end;
   }else i=j;
  }else i++;
 }
 return [...values].sort();
}
