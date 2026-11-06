function unifiedStrictDiff(before,after,left,right) {
 if(!before.endsWith("\n")||!after.endsWith("\n"))throw Error("LF-terminated-source-required");
 const a=before.slice(0,-1).split("\n"),b=after.slice(0,-1).split("\n");
 const n=a.length,m=b.length;
 const dp=Array.from({length:n+1},()=>new Uint16Array(m+1));
 for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)dp[i][j]=a[i]===b[j]?1+dp[i+1][j+1]:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<n||j<m){
  if(i<n&&j<m&&a[i]===b[j]){ops.push({tag:" ",s:a[i],i,j});i++;j++;}
  else if(i<n&&(j===m||dp[i+1][j]>=dp[i][j+1])){ops.push({tag:"-",s:a[i],i,j});i++;}
  else{ops.push({tag:"+",s:b[j],i,j});j++;}
 }
 const spans=[];
 for(let k=0;k<ops.length;k++)if(ops[k].tag!==" "){
  const start=Math.max(0,k-3),end=Math.min(ops.length,k+4);
  if(spans.length&&start<=spans[spans.length-1][1])spans[spans.length-1][1]=end;
  else spans.push([start,end]);
 }
 let out="--- "+left+"\n+++ "+right+"\n";
 for(const [start,end] of spans){
  const part=ops.slice(start,end),oldCount=part.filter(x=>x.tag!=="+").length,newCount=part.filter(x=>x.tag!=="-").length;
  const oldStart=oldCount?ops[start].i+1:ops[start].i,newStart=newCount?ops[start].j+1:ops[start].j;
  out+="@@ -"+oldStart+","+oldCount+" +"+newStart+","+newCount+" @@\n";
  out+=part.map(x=>x.tag+x.s).join("\n")+"\n";
 }
 return out;
}
function strictApplyText(before,diff,reverse=false) {
 if(!before.endsWith("\n")||!diff.endsWith("\n"))throw Error("strict-LF");
 const source=before.slice(0,-1).split("\n"),lines=diff.slice(0,-1).split("\n");
 if(!lines[0].startsWith("--- ")||!lines[1].startsWith("+++ "))throw Error("strict-headers");
 const out=[];let cursor=0,hunks=0;
 for(let k=2;k<lines.length;){
  const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(lines[k++]);
  if(!m)throw Error("strict-hunk");
  const start=Number(m[reverse?3:1]),count=Number(m[reverse?4:2]),destStart=Number(m[reverse?1:3]),destCount=Number(m[reverse?2:4]);
  const index=count?start-1:start;
  if(index<cursor)throw Error("overlap");
  out.push(...source.slice(cursor,index));cursor=index;
  if(out.length!==(destCount?destStart-1:destStart))throw Error("destination-coordinate");
  let consumed=0,produced=0;
  while(k<lines.length&&!lines[k].startsWith("@@ ")){
   const l=lines[k++],rawtag=l[0],s=l.slice(1),tag=reverse?(rawtag==="+"?"-":rawtag==="-"?"+":rawtag):rawtag;
   if(![" ","+","-"].includes(tag))throw Error("strict-line");
   if(tag!="+"){if(source[cursor]!==s)throw Error("strict-context");cursor++;consumed++;}
   if(tag!="-"){out.push(s);produced++;}
  }
  if(consumed!==count||produced!==destCount)throw Error("strict-count");
  hunks++;
 }
 out.push(...source.slice(cursor));
 return {text:out.join("\n")+"\n",hunks};
}
