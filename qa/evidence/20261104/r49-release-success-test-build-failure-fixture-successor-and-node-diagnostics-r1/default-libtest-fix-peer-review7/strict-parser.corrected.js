function strictDiff(before,after,label){
 const a=before.split("\n"),b=after.split("\n");if(a.pop()!==""||b.pop()!=="")throw Error("LF required");
 const d=Array.from({length:a.length+1},()=>new Uint16Array(b.length+1));
 for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)d[i][j]=a[i]===b[j]?1+d[i+1][j+1]:Math.max(d[i+1][j],d[i][j+1]);
 let i=0,j=0,ops=[];while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){ops.push([" ",a[i++]]);j++;}else if(j<b.length&&(i===a.length||d[i][j+1]>d[i+1][j]))ops.push(["+",b[j++]]);else ops.push(["-",a[i++]]);}
 const changed=ops.map((x,k)=>x[0]!==" "?k:-1).filter(k=>k>=0);if(!changed.length)return "";
 const spans=[];for(const k of changed){const z=[Math.max(0,k-3),Math.min(ops.length,k+4)];if(spans.length&&z[0]<=spans.at(-1)[1])spans.at(-1)[1]=Math.max(spans.at(-1)[1],z[1]);else spans.push(z);}
 let out="--- a/"+label+"\n+++ b/"+label+"\n";
 for(const [l,r]of spans){let old=0,neu=0,oc=0,nc=0;for(let k=0;k<l;k++){if(ops[k][0]!=="+")old++;if(ops[k][0]!=="-")neu++;}for(let k=l;k<r;k++){if(ops[k][0]!=="+")oc++;if(ops[k][0]!=="-")nc++;}out+="@@ -"+(old+(oc?1:0))+","+oc+" +"+(neu+(nc?1:0))+","+nc+" @@\n"+ops.slice(l,r).map(x=>x.join("")).join("\n")+"\n";}return out;
}
function applyStrict(before,diff,reverse){
 const src=before.split("\n");if(src.pop()!=="")throw Error("LF");if(diff==="")return before;
 if(!diff.endsWith("\n"))throw Error("diff LF required");const ls=diff.slice(0,-1).split("\n");let p=2,cursor=0,out=[];
 while(p<ls.length){const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(ls[p++]);if(!m)throw Error("hunk");
 const start=Number(m[reverse?3:1]),count=Number(m[reverse?4:2]),destCount=Number(m[reverse?2:4]);const at=start-(count?1:0);if(at<cursor)throw Error("overlap");out.push(...src.slice(cursor,at));cursor=at;let used=0,made=0;
 while(p<ls.length&&!ls[p].startsWith("@@ ")){const x=ls[p++],kind=reverse?({" ":" ","+":"-","-":"+"})[x[0]]:x[0],v=x.slice(1);if(kind===" "||kind==="-"){if(src[cursor++]!==v)throw Error("whole context");used++;}if(kind===" "||kind==="+"){out.push(v);made++;}if(![" ","-","+"].includes(kind))throw Error("kind");}
 if(used!==count||made!==destCount)throw Error("hunk counts");
 }out.push(...src.slice(cursor));return out.join("\n")+"\n";
}
