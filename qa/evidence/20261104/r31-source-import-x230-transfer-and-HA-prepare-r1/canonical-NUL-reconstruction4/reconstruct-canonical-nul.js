function reconstructCanonicalNulOutputs(api,sha1,sha256){
 function need(v,m){if(!v)throw Error(m);}
 function utf8(v){return unescape(encodeURIComponent(v));}
 function cmp(a,b){return a<b?-1:a>b?1:0;}
 function hashBytes(hex){need(/^[0-9a-f]{40}$/.test(hex),"object_id");let s="";for(let i=0;i<40;i+=2)s+=String.fromCharCode(parseInt(hex.slice(i,i+2),16));return s;}
 need(api.sha==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&api.truncated===false&&Array.isArray(api.tree),"exact_complete_tree");
 const entries=new Map(),children=new Map([["",[]]]),directories=[];
 for(const row of api.tree){
  need(typeof row.path==="string"&&row.path.length>0&&!row.path.includes("\0")&&!row.path.startsWith("/")&&!row.path.endsWith("/")&&row.path.split("/").every(x=>x!==""&&x!=="."&&x!==".."),"path");
  need(!entries.has(row.path),"duplicate_path");need(/^[0-9a-f]{40}$/.test(row.sha),"sha");
  need((row.type==="tree"&&row.mode==="040000")||(row.type==="blob"&&["100644","100755","120000"].includes(row.mode)),"mode_type");
  entries.set(row.path,row);if(row.type==="tree"){directories.push(row.path);children.set(row.path,[]);}
 }
 for(const row of entries.values()){
  const slash=row.path.lastIndexOf("/"),parent=slash<0?"":row.path.slice(0,slash),name=row.path.slice(slash+1);
  need(children.has(parent),"missing_parent");children.get(parent).push({...row,name});
 }
 const hashes={};
 for(const path of [...directories.sort((a,b)=>b.split("/").length-a.split("/").length), ""]){
  const rows=children.get(path).slice().sort((a,b)=>cmp(utf8(a.name)+(a.type==="tree"?"/":""),utf8(b.name)+(b.type==="tree"?"/":"")));
  let bytes="";
  for(const row of rows){if(row.type==="tree")need(hashes[row.path]===row.sha,"child_tree_digest");bytes+=(row.type==="tree"?"40000":row.mode)+" "+utf8(row.name)+"\0"+hashBytes(row.sha);}
  const actual=sha1("tree "+bytes.length+"\0"+bytes),expected=path===""?api.sha:entries.get(path).sha;
  need(actual===expected,"tree_merkle:"+path);hashes[path]=actual;
 }
 const walk=[];
 function visit(path){
  const rows=children.get(path).slice().sort((a,b)=>cmp(utf8(a.name)+(a.type==="tree"?"/":""),utf8(b.name)+(b.type==="tree"?"/":"")));
  for(const row of rows)if(row.type==="tree")visit(row.path);else walk.push(row);
 }
 visit("");
 const index=[...entries.values()].filter(x=>x.type==="blob").sort((a,b)=>cmp(utf8(a.path),utf8(b.path)));
 need(walk.length===3914&&index.length===3914,"3914_leaves");
 need(walk.every((row,i)=>row.path===index[i].path&&row.mode===index[i].mode&&row.sha===index[i].sha),"recursive_tree_order_equals_index_order_for_this_tree");
 const treeText=walk.map(row=>row.mode+" blob "+row.sha+"\t"+utf8(row.path)+"\0").join("");
 const indexText=index.map(row=>row.mode+" "+row.sha+" 0\t"+utf8(row.path)+"\0").join("");
 const pin=bytes=>({bytes:bytes.length,sha256:sha256(bytes),blob:sha1("blob "+bytes.length+"\0"+bytes),nul_records:bytes.split("\0").length-1,final_nul:bytes.endsWith("\0")});
 return {treeText,indexText,treePin:pin(treeText),indexPin:pin(indexText),tree_sha:api.sha,verified_tree_objects:Object.keys(hashes).length,leaf_count:walk.length,raw_path_utf8:true,index_stage:0,path_order_equal_for_this_tree:true};
}
