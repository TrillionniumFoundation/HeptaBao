function strictApply(original,patch){
 const split=s=>s.match(/[^\n]*\n|[^\n]+$/g)||[];
 const lines=split(original),edits=split(patch);let out=[],pos=0,i=2,hunks=0;
 while(i<edits.length){const m=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n$/.exec(edits[i]);if(!m)throw Error("invalid hunk header");const oldStart=Number(m[1]),oldCount=m[2]===undefined?1:Number(m[2]),newCount=m[4]===undefined?1:Number(m[4]);const target=oldCount?oldStart-1:oldStart;if(target<pos)throw Error("overlap");out.push(...lines.slice(pos,target));pos=target;i++;let used=0,added=0;
 while(i<edits.length&&!edits[i].startsWith("@@ ")){const tag=edits[i][0],payload=edits[i].slice(1);if(!" +-".includes(tag))throw Error("invalid diff row");if(tag===" "||tag==="-"){if(lines[pos]!==payload)throw Error("old context mismatch");pos++;used++;}if(tag===" "||tag==="+"){out.push(payload);added++;}i++;}
 if(used!==oldCount||added!==newCount)throw Error("count mismatch");hunks++;
 }
 out.push(...lines.slice(pos));return {content:out.join(""),hunks};
}
