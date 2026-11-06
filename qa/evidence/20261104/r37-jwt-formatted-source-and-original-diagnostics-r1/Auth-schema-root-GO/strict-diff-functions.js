function unified(a,b,from,to){
 if(!a.endsWith("\n")||!b.endsWith("\n"))throw Error("newline_required");
 const A=a.slice(0,-1).split("\n"),B=b.slice(0,-1).split("\n"),dp=Array.from({length:A.length+1},()=>new Uint16Array(B.length+1));
 for(let i=A.length-1;i>=0;i--)for(let j=B.length-1;j>=0;j--)dp[i][j]=A[i]===B[j]?1+dp[i+1][j+1]:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<A.length||j<B.length){if(i<A.length&&j<B.length&&A[i]===B[j])ops.push([" ",A[i++],B[j++]]);else if(j<B.length&&(i===A.length||dp[i][j+1]>=dp[i+1][j]))ops.push(["+",B[j++]]);else ops.push(["-",A[i++]]);}
 const spans=[];for(let k=0;k<ops.length;k++)if(ops[k][0]!==" "){let lo=Math.max(0,k-3),hi=Math.min(ops.length,k+4);if(spans.length&&lo<=spans.at(-1)[1])spans.at(-1)[1]=Math.max(spans.at(-1)[1],hi);else spans.push([lo,hi]);}
 let out="--- "+from+"\n+++ "+to+"\n";
 for(const [lo,hi]of spans){const oldBefore=ops.slice(0,lo).filter(x=>x[0]!=="+").length,newBefore=ops.slice(0,lo).filter(x=>x[0]!=="-").length,oldCount=ops.slice(lo,hi).filter(x=>x[0]!=="+").length,newCount=ops.slice(lo,hi).filter(x=>x[0]!=="-").length;
  out+="@@ -"+(oldCount?oldBefore+1:oldBefore)+","+oldCount+" +"+(newCount?newBefore+1:newBefore)+","+newCount+" @@\n";
  for(const [kind,line]of ops.slice(lo,hi))out+=kind+line+"\n";
 }return out;
}
function strictApply(a,d,reverse=false){
 const A=a.slice(0,-1).split("\n"),lines=d.slice(0,-1).split("\n");let at=0,out=[],hunks=0,k=2;
 while(k<lines.length){
  const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(lines[k++]);if(!m)throw Error("hunk_header");
  const st=Number(m[reverse?3:1]),ct=Number(m[reverse?4:2]),nt=Number(m[reverse?2:4]),start=ct?st-1:st;
  if(start<at)throw Error("overlap");out.push(...A.slice(at,start));at=start;let consumed=0,produced=0;
  while(k<lines.length&&!lines[k].startsWith("@@ ")){let p=lines[k][0],v=lines[k++].slice(1);if(reverse)p=p==="+"?"-":p==="-"?"+":p;if(p===" "||p==="-"){if(A[at++]!==v)throw Error("strict_context");consumed++;}if(p===" "||p==="+"){out.push(v);produced++;}if(![" ","+","-"].includes(p))throw Error("prefix");}
  if(consumed!==ct||produced!==nt)throw Error("hunk_count");hunks++;
 }out.push(...A.slice(at));return {text:out.join("\n")+"\n",hunks};
}
