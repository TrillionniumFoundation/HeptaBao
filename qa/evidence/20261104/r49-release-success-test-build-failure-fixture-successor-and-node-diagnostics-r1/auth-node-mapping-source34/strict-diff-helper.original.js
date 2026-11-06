function sourceUnified(before,after,oldName,newName){
 const a=before.split("\n"),b=after.split("\n");if(a.at(-1)==="")a.pop();if(b.at(-1)==="")b.pop();
 const dp=Array.from({length:a.length+1},()=>new Uint32Array(b.length+1));
 for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)dp[i][j]=a[i]===b[j]?1+dp[i+1][j+1]:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){ops.push([" ",a[i++]]);j++;}else if(j<b.length&&(i===a.length||dp[i][j+1]>=dp[i+1][j]))ops.push(["+",b[j++]]);else ops.push(["-",a[i++]]);}
 const ranges=[];for(let k=0;k<ops.length;k++)if(ops[k][0]!==" "){const lo=Math.max(0,k-3),hi=Math.min(ops.length,k+4);if(ranges.length&&lo<=ranges.at(-1)[1])ranges.at(-1)[1]=hi;else ranges.push([lo,hi]);}
 let raw="--- a/"+oldName+"\n+++ b/"+newName+"\n";
 for(const [lo,hi]of ranges){const o=ops.slice(0,lo).filter(x=>x[0]!=="+").length,n=ops.slice(0,lo).filter(x=>x[0]!=="-").length,oc=ops.slice(lo,hi).filter(x=>x[0]!=="+").length,nc=ops.slice(lo,hi).filter(x=>x[0]!=="-").length;raw+="@@ -"+(o+1)+","+oc+" +"+(n+1)+","+nc+" @@\n"+ops.slice(lo,hi).map(x=>x.join("")).join("\n")+"\n";}
 return {raw,hunks:ranges.length};
}
function strictApplySource(before,diff){
 const base=before.split("\n");if(base.at(-1)==="")base.pop();
 const lines=diff.split("\n");let i=2,pos=0,out=[],hunks=0;
 while(i<lines.length-1){const m=/^@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@$/.exec(lines[i++]);if(!m)throw Error("hunk_header");
 const start=Number(m[1])-1;out.push(...base.slice(pos,start));pos=start;let oldUsed=0,newUsed=0;
 while(i<lines.length-1&&!lines[i].startsWith("@@ ")){const x=lines[i++],sg=x[0],s=x.slice(1);if(![" ","+","-"].includes(sg))throw Error("hunk_sign");if(sg!=="+"){if(base[pos++]!==s)throw Error("exact_old_line");oldUsed++;}if(sg!=="-"){out.push(s);newUsed++;}}
 if(oldUsed!==Number(m[2])||newUsed!==Number(m[4]))throw Error("hunk_count");hunks++;}
 out.push(...base.slice(pos));return {raw:out.join("\n")+"\n",hunks};
}