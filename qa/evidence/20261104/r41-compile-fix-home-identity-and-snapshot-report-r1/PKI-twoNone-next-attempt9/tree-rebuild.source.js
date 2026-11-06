function expectedTreeFromLeaves(t,updates){
 const rows=t.tree.map(r=>({...r})),dirs=new Map([["",[]]]);
 for(const r of rows)if(r.type==="tree")dirs.set(r.path,[]);
 for(const r of rows){if(updates[r.path]){if(r.type!=="blob")throw Error("not blob");r.sha=updates[r.path].blob;r.size=updates[r.path].bytes;}
 const j=r.path.lastIndexOf("/"),p=j<0?"":r.path.slice(0,j),name=r.path.slice(j+1);if(!dirs.has(p))throw Error("parent missing");dirs.get(p).push({row:r,name});}
 const hashes=new Map();
 for(const p of [...dirs.keys()].sort((a,b)=>b.split("/").length-a.split("/").length||b.length-a.length)){
  const E=dirs.get(p);E.sort((a,b)=>{const x=h.utf8Bytes(a.name+(a.row.type==="tree"?"/":"")),y=h.utf8Bytes(b.name+(b.row.type==="tree"?"/":""));for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];return x.length-y.length;});
  const data=[];
  for(const e of E){const r=e.row;if(r.type==="tree")r.sha=hashes.get(r.path);data.push(...h.utf8Bytes((r.type==="tree"?"40000":r.mode)+" "+e.name+"\0"));for(let i=0;i<40;i+=2)data.push(parseInt(r.sha.slice(i,i+2),16));}
  hashes.set(p,h.sha1Bytes(h.utf8Bytes("tree "+data.length+"\0").concat(data)));
 }
 const out={sha:hashes.get(""),tree:rows,truncated:false};
 const audit=h.gitTreeAudit(out);
 return {tree:out,audit};
}
