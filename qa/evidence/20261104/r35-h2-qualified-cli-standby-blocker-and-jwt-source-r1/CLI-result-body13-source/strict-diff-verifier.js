function diffLines(a,b) {
 const A=a.split("\n");if(A.at(-1)==="")A.pop(); const B=b.split("\n");if(B.at(-1)==="")B.pop();
 const n=A.length,m=B.length,dp=Array.from({length:n+1},()=>new Uint32Array(m+1));
 for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)dp[i][j]=A[i]===B[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<n||j<m){if(i<n&&j<m&&A[i]===B[j]){ops.push([" ",A[i]]);i++;j++;}
 else if(j<m&&(i===n||dp[i][j+1]>=dp[i+1][j])){ops.push(["+",B[j++]]);}
 else ops.push(["-",A[i++]]);}
 const changes=ops.map((x,k)=>x[0]!==" "?k:-1).filter(k=>k>=0),spans=[];
 for(const k of changes){const lo=Math.max(0,k-3),hi=Math.min(ops.length,k+4);
  if(spans.length&&lo<=spans.at(-1)[1])spans.at(-1)[1]=Math.max(hi,spans.at(-1)[1]);else spans.push([lo,hi]);}
 let out="--- a/native_gitfirst.info-only.js\n+++ b/native_gitfirst.body-ranges.js\n";
 for(const [lo,hi]of spans){
 const oldStart=1+ops.slice(0,lo).filter(x=>x[0]!=="+").length;
 const newStart=1+ops.slice(0,lo).filter(x=>x[0]!=="-").length;
 const oldN=ops.slice(lo,hi).filter(x=>x[0]!=="+").length,newN=ops.slice(lo,hi).filter(x=>x[0]!=="-").length;
 out+=`@@ -${oldStart},${oldN} +${newStart},${newN} @@\n`+ops.slice(lo,hi).map(x=>x[0]+x[1]+"\n").join("");
 }return {text:out,hunks:spans.length};
}
function strictApply(base,diff,reverse=false){
 const src=base.split("\n");if(src.at(-1)==="")src.pop();
 const lines=diff.split("\n"),out=[];let at=0;
 for(let i=2;i<lines.length;){
  if(lines[i]===""){i++;continue;}
  const m=lines[i++].match(/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/);if(!m)throw Error("hunk");
  const start=Number(reverse?m[3]:m[1])-1;while(at<start)out.push(src[at++]);
  let oldN=0,newN=0;
  while(i<lines.length&&!lines[i].startsWith("@@ ")&&lines[i]!==""){
   const l=lines[i++],mark=reverse?(l[0]==="+"?"-":l[0]==="-"?"+":" "):l[0],body=l.slice(1);
   if(mark!="+"){if(src[at++]!==body)throw Error("strict line");oldN++;}
   if(mark!=="-"){out.push(body);newN++;}
  }
  if(oldN!==Number(reverse?m[4]:m[2])||newN!==Number(reverse?m[2]:m[4]))throw Error("hunk extent");
 }
 return out.concat(src.slice(at)).join("\n")+"\n";
}
