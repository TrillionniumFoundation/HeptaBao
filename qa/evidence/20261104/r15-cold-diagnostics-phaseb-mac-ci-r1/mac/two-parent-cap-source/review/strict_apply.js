function strictApply(before,diff) {
 const old=before.match(/[^\n]*\n|[^\n]+$/g)||[];
 const dl=diff.match(/[^\n]*\n|[^\n]+$/g)||[];
 let i=0,oldCursor=0,hunks=0;const out=[];
 while(i<dl.length && !dl[i].startsWith("@@ "))i++;
 while(i<dl.length){
  const m=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)\n?$/.exec(dl[i++]);
  if(!m)throw Error("invalid hunk header");
  const os=+m[1],oc=m[2]===undefined?1:+m[2],ns=+m[3],nc=m[4]===undefined?1:+m[4];
  const at=os===0?0:os-1;if(at<oldCursor)throw Error("overlap");
  out.push(...old.slice(oldCursor,at));oldCursor=at;
  if(out.length!==(ns===0?0:ns-1))throw Error("new position mismatch");
  let consumed=0,produced=0;
  while(i<dl.length&&!dl[i].startsWith("@@ ")){
   const row=dl[i++],op=row[0],content=row.slice(1);
   if(op===" "||op==="-"){if(old[oldCursor]!==content)throw Error("old context mismatch");oldCursor++;consumed++;}
   if(op===" "||op==="+"){out.push(content);produced++;}
   if(![" ","+","-"].includes(op))throw Error("unexpected diff row");
  }
  if(consumed!==oc||produced!==nc)throw Error("hunk counts mismatch");
  hunks++;
 }
 out.push(...old.slice(oldCursor));return {text:out.join(""),hunks};
}
