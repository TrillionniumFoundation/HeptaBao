
function jwtMaskRust(source) {
  const a=source.split(""); let i=0;
  function erase(x,y){for(let k=x;k<y;k++)if(a[k]!=="\n"&&a[k]!=="\r")a[k]=" ";}
  while(i<source.length){
    if(source.startsWith("//",i)){let e=source.indexOf("\n",i+2);if(e<0)e=source.length;erase(i,e);i=e;continue;}
    if(source.startsWith("/*",i)){let j=i+2,d=1;while(j<source.length&&d){if(source.startsWith("/*",j)){d++;j+=2;}else if(source.startsWith("*/",j)){d--;j+=2;}else j++;}if(d)throw Error("unterminated block comment");erase(i,j);i=j;continue;}
    const raw=/^(?:br|cr|r)(#{0,255})"/.exec(source.slice(i,i+260));
    if(raw && (i===0||!/[A-Za-z0-9_]/.test(source[i-1]))){const end='"'+raw[1];let j=source.indexOf(end,i+raw[0].length);if(j<0)throw Error("unterminated raw string");j+=end.length;erase(i,j);i=j;continue;}
    if(source[i]==='"'){let j=i+1;while(j<source.length){if(source[j]==="\\"){j+=2;continue;}if(source[j++]==='"')break;}if(source[j-1]!=='"')throw Error("unterminated quoted string");erase(i,j);i=j;continue;}
    if(source[i]==="'"){const ch=/^'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\r\n])'/u.exec(source.slice(i,i+32));if(ch){erase(i,i+ch[0].length);i+=ch[0].length;continue;}}
    i++;
  }
  return a.join("");
}
function jwtFunctions(source) {
  const m=jwtMaskRust(source), out=[],re=/\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<|\()/g;
  let match;
  while((match=re.exec(m))){
    let i=match.index, j=re.lastIndex-1, round=0,square=0,brace=-1;
    for(;j<m.length;j++){const c=m[j];if(c==="(")round++;else if(c===")")round--;else if(c==="[")square++;else if(c==="]")square--;else if(c==="{"&&round===0&&square===0){brace=j;break;}else if(c===";"&&round===0&&square===0)break;}
    if(brace<0)continue;
    let d=1,e=brace+1;for(;e<m.length&&d;e++){if(m[e]==="{")d++;else if(m[e]==="}")d--;}if(d)throw Error("unbalanced function "+match[1]);
    out.push({name:match[1],start:i,bodyStart:brace,end:e,raw:source.slice(i,e)});
    re.lastIndex=e;
  }
  return out;
}
function jwtOneFunction(source,name) {
  const f=jwtFunctions(source).filter(f=>f.name===name);
  if(f.length!==1)throw Error("function cardinality "+name+"="+f.length);
  return f[0].raw;
}
function jwtTestNames(source) {
  const mask=jwtMaskRust(source), funcs=jwtFunctions(source),out=[];
  for(const f of funcs){const head=mask.slice(Math.max(0,f.start-300),f.start);if(/#\s*\[\s*test\s*\]\s*(?:#\[[^\]]*\]\s*)*$/.test(head))out.push(f.name);}
  return out;
}
function jwtAssert(c,label){if(!c)throw Error(label);}
function jwtBalanced(source){
 const m=jwtMaskRust(source),st=[],close={")":"(","]":"[","}":"{"};
 for(let i=0;i<m.length;i++){const c=m[i];if("([{".includes(c))st.push(c);else if(")]}".includes(c)){if(st.pop()!==close[c])throw Error("delimiter "+i);}}
 jwtAssert(st.length===0,"unclosed delimiter");return true;
}
