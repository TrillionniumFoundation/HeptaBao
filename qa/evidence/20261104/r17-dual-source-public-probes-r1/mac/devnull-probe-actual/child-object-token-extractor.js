function splitRawObject(raw){
 const ws=(p)=>{while(/\s/.test(raw[p]||"")&&p<raw.length)p++;return p;};
 function end(p){p=ws(p);const first=raw[p];if(first==='"'){p++;for(;p<raw.length;p++){if(raw[p]==="\\"){p++;continue;}if(raw[p]==='"')return p+1;}throw Error("string");}
 if(first==="{"||first==="["){const close=first==="{"?"}":"]";p++;while(true){p=ws(p);if(raw[p]===close)return p+1;if(raw[p]===","||raw[p]===":"){p++;continue;}p=end(p);}}
 while(p<raw.length&&!/[\s,\]}]/.test(raw[p]))p++;return p;}
 let p=ws(0);if(raw[p++]!=="{")throw Error("object");const result={};while(true){p=ws(p);if(raw[p]==="}")break;let ke=end(p),key=JSON.parse(raw.slice(p,ke));p=ws(ke);if(raw[p++]!==":")throw Error("colon");p=ws(p);let ve=end(p);if(Object.prototype.hasOwnProperty.call(result,key))throw Error("duplicate");result[key]=raw.slice(p,ve);p=ws(ve);if(raw[p]===","){p++;continue;}if(raw[p]!=="}")throw Error("delimiter");}
 return result;
}
