
function gitLeafIndexText(rebuilt){
 const byPath=new Map(rebuilt.trees.map(x=>[x.path,x]));
 const cmp=(a,b)=>{const x=byteString(utf8Bytes(a.path+(a.type==="tree"?"/":""))),y=byteString(utf8Bytes(b.path+(b.type==="tree"?"/":"")));return x<y?-1:x>y?1:0};
 let out="";
 function walk(path){for(const e of byPath.get(path).tree.slice().sort(cmp)){const full=(path?path+"/":"")+e.path;if(e.type==="tree")walk(full);else out+=full+"\0"+e.mode+"\0"+e.sha+"\0"+e.size+"\n";}}
 walk("");return out;
}