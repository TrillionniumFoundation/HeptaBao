function makeStrictUnified(a,b,labelA="journal.before.js",labelB="journal.after.js") {
 if(!a.endsWith("\n")||!b.endsWith("\n"))throw Error("complete_newline_required");
 const A=a.slice(0,-1).split("\n"),B=b.slice(0,-1).split("\n"),N=A.length,M=B.length;
 const dp=Array.from({length:N+1},()=>new Uint32Array(M+1));
 for(let i=N-1;i>=0;i--)for(let j=M-1;j>=0;j--)dp[i][j]=A[i]===B[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<N||j<M){if(i<N&&j<M&&A[i]===B[j]){ops.push([" ",A[i]]);i++;j++;}else if(j<M&&(i===N||dp[i][j+1]>=dp[i+1][j])){ops.push(["+",B[j++]]);}else ops.push(["-",A[i++]]);}
 const regions=[];for(let k=0;k<ops.length;k++)if(ops[k][0]!==" "){const start=Math.max(0,k-3),end=Math.min(ops.length,k+4);const p=regions[regions.length-1];if(p&&start<=p[1])p[1]=Math.max(p[1],end);else regions.push([start,end]);}
 let out="--- a/"+labelA+"\n+++ b/"+labelB+"\n";
 for(const [lo,hi]of regions){let old0=0,new0=0;for(let k=0;k<lo;k++){if(ops[k][0]!=="+")old0++;if(ops[k][0]!=="-")new0++;}const lines=ops.slice(lo,hi),oldN=lines.filter(x=>x[0]!=="+").length,newN=lines.filter(x=>x[0]!=="-").length;out+="@@ -"+(oldN?old0+1:old0)+","+oldN+" +"+(newN?new0+1:new0)+","+newN+" @@\n"+lines.map(x=>x[0]+x[1]+"\n").join("");}
 return out;
}
function applyStrictUnified(a,d,reverse=false){
 const A=a.slice(0,-1).split("\n"),D=d.split("\n"),out=[];let pos=0,hunks=0;
 for(let k=2;k<D.length;){if(D[k]===""&&k===D.length-1)break;const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(D[k++]);if(!m)throw Error("hunk_header");
 let oldStart=Number(m[reverse?3:1]),oldN=Number(m[reverse?4:2]),newStart=Number(m[reverse?1:3]),newN=Number(m[reverse?2:4]);const at=oldN?oldStart-1:oldStart; if(at<pos)throw Error("overlap");out.push(...A.slice(pos,at));pos=at;const newAt=newN?newStart-1:newStart;if(out.length!==newAt)throw Error("new_position");let consumed=0,produced=0;
 while(k<D.length&&!D[k].startsWith("@@ ")){if(D[k]===""&&k===D.length-1){k++;break;}const line=D[k++],rawMark=line[0],mark=reverse?(rawMark==="+"?"-":rawMark==="-"?"+":rawMark):rawMark,body=line.slice(1);if(mark===" "||mark==="-"){if(A[pos]!==body)throw Error("exact_context");pos++;consumed++;}if(mark===" "||mark==="+"){out.push(body);produced++;}if(![" ","+","-"].includes(mark))throw Error("line_marker");}if(consumed!==oldN||produced!==newN)throw Error("hunk_count");hunks++;}
 out.push(...A.slice(pos));return {text:out.join("\n")+"\n",hunks};
}