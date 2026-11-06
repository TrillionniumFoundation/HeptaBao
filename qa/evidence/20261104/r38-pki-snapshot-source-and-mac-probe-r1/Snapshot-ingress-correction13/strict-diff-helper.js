function snapshotSourceLines(s) {
 if(s!==""&&!s.endsWith("\n"))throw new Error("newline-terminated Rust input required");
 return s===""?[]:s.slice(0,-1).split("\n");
}
function snapshotLineEdits(before,after) {
 const a=snapshotSourceLines(before),b=snapshotSourceLines(after),n=a.length,m=b.length;
 let v=new Map([[1,0]]);const trace=[];
 for(let d=0;d<=n+m;d++) {
  trace.push(new Map(v));
  for(let k=-d;k<=d;k+=2) {
   let x;
   if(k===-d||(k!==d&&(v.get(k-1)??-Infinity)<(v.get(k+1)??-Infinity)))x=v.get(k+1)??0;
   else x=(v.get(k-1)??0)+1;
   let y=x-k;
   while(x<n&&y<m&&a[x]===b[y]){x++;y++;}
   v.set(k,x);
   if(x>=n&&y>=m) {
    const out=[];let xx=n,yy=m;
    for(let dd=d;dd>=0;dd--) {
     const vv=trace[dd],kk=xx-yy;
     const pk=kk===-dd||(kk!==dd&&(vv.get(kk-1)??-Infinity)<(vv.get(kk+1)??-Infinity))?kk+1:kk-1;
     const px=vv.get(pk)??0,py=px-pk;
     while(xx>px&&yy>py){out.push({tag:" ",line:a[xx-1]});xx--;yy--;}
     if(dd===0)break;
     if(xx===px){out.push({tag:"+",line:b[yy-1]});yy--;}
     else{out.push({tag:"-",line:a[xx-1]});xx--;}
    }
    return out.reverse();
   }
  }
 }
 throw new Error("diff traversal failed");
}
function snapshotUnified(before,after,path) {
 const ops=snapshotLineEdits(before,after);
 const changes=ops.map((x,i)=>x.tag===" "?-1:i).filter(i=>i>=0);
 if(!changes.length)return "";
 const spans=[];
 for(const i of changes){const s=Math.max(0,i-3),e=Math.min(ops.length,i+4);
  if(spans.length&&s<=spans[spans.length-1].end)spans[spans.length-1].end=e;
  else spans.push({start:s,end:e});}
 const oldAt=[1],newAt=[1];
 for(const o of ops){oldAt.push(oldAt.at(-1)+(o.tag!=="+"?1:0));newAt.push(newAt.at(-1)+(o.tag!=="-"?1:0));}
 let out="--- "+(before===""?"/dev/null":"a/"+path)+"\n+++ "+(after===""?"/dev/null":"b/"+path)+"\n";
 for(const span of spans){
  const oldCount=oldAt[span.end]-oldAt[span.start],newCount=newAt[span.end]-newAt[span.start];
  const oldStart=oldAt[span.start]-(oldCount===0?1:0),newStart=newAt[span.start]-(newCount===0?1:0);
  out+="@@ -"+oldStart+","+oldCount+" +"+newStart+","+newCount+" @@\n";
  for(const op of ops.slice(span.start,span.end))out+=op.tag+op.line+"\n";
 }
 return out;
}
function snapshotApply(before,diff,reverse=false) {
 if(diff==="")return before;
 const old=snapshotSourceLines(before),ls=snapshotSourceLines(diff),out=[];
 if(!ls[0].startsWith("--- ")||!ls[1].startsWith("+++ "))throw new Error("patch header");
 let cursor=0,i=2;
 while(i<ls.length) {
  const h=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(ls[i++]);
  if(!h)throw new Error("hunk header");
  const oldStart=Number(h[reverse?3:1]),oldCount=Number(h[reverse?4:2]);
  const newStart=Number(h[reverse?1:3]),newCount=Number(h[reverse?2:4]);
  const at=oldCount===0?oldStart:oldStart-1;
  if(at<cursor||at>old.length)throw new Error("hunk overlap/range");
  out.push(...old.slice(cursor,at));cursor=at;
  if(out.length!==(newCount===0?newStart:newStart-1))throw new Error("new hunk coordinate");
  let a=0,b=0;
  while(i<ls.length&&!ls[i].startsWith("@@ ")){
   let tag=ls[i][0];const line=ls[i++].slice(1);
   if(reverse)tag=tag==="+"?"-":tag==="-"?"+":tag;
   if(tag===" "||tag==="-"){if(old[cursor++]!==line)throw new Error("exact source context");a++;}
   if(tag===" "||tag==="+"){out.push(line);b++;}
   if(![" ","+","-"].includes(tag))throw new Error("hunk line");
  }
  if(a!==oldCount||b!==newCount)throw new Error("hunk counts");
 }
 out.push(...old.slice(cursor));
 return out.length?out.join("\n")+"\n":"";
}

