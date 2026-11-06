function applyStrict(source,diff){
 const src=source.split("\n");if(src.pop()!=="")throw Error("source final newline");
 const ls=diff.split("\n");if(ls.pop()!=="")throw Error("diff final newline");
 let out=[],cursor=0,i=2,hunks=0;
 while(i<ls.length){const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(ls[i++]);if(!m)throw Error("hunk header");
 const os=Number(m[1]),oc=Number(m[2]),ns=Number(m[3]),nc=Number(m[4]),idx=oc===0?os:os-1;
 if(idx<cursor)throw Error("overlap");
 out.push(...src.slice(cursor,idx));cursor=idx;
 const removed=[],added=[];while(i<ls.length&&!ls[i].startsWith("@@ ")){const line=ls[i++];if(line[0]==="-")removed.push(line.slice(1));else if(line[0]==="+")added.push(line.slice(1));else throw Error("unsupported nonzero context");}
 if(removed.length!==oc||added.length!==nc||JSON.stringify(src.slice(cursor,cursor+oc))!==JSON.stringify(removed))throw Error("hunk content");
 if(nc!==0&&out.length+1!==ns)throw Error("new coordinate");
 out.push(...added);cursor+=oc;hunks++;
 }
 out.push(...src.slice(cursor));return {raw:out.join("\n")+"\n",hunks};
}