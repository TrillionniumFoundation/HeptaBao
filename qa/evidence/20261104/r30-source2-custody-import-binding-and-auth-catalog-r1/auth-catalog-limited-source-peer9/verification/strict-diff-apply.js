function(source,diff,reverse=false){
 if(!source.endsWith("\n")||!diff.endsWith("\n"))throw Error("LF source required");
 const src=source.slice(0,-1).split("\n"),ds=diff.slice(0,-1).split("\n"),out=[];let cursor=0,j=2,count=0;
 if(!ds[0].startsWith("--- ")||!ds[1].startsWith("+++ "))throw Error("headers");
 while(j<ds.length){
  const m=/^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@/.exec(ds[j++]);if(!m)throw Error("hunk");
  const oldStart=Number(m[reverse?3:1]),oldCount=Number(m[reverse?4:2]??1),newCount=Number(m[reverse?2:4]??1);
  if(oldStart-1<cursor)throw Error("overlap");
  out.push(...src.slice(cursor,oldStart-1));cursor=oldStart-1;let consumed=0,produced=0;
  while(j<ds.length&&!ds[j].startsWith("@@ ")){
   const line=ds[j++],c=line[0],s=line.slice(1);
   if(![" ","+","-"].includes(c))throw Error("invalid diff row");
   const remove=reverse?c==="+":c==="-",add=reverse?c==="-":c==="+";
   if(c===" "||remove){if(src[cursor++]!==s)throw Error("context mismatch");consumed++;}
   if(c===" "||add){out.push(s);produced++;}
  }
  if(consumed!==oldCount||produced!==newCount)throw Error("hunk cardinality");count++;
 }
 out.push(...src.slice(cursor));return{text:out.join("\n")+"\n",hunks:count};
}
