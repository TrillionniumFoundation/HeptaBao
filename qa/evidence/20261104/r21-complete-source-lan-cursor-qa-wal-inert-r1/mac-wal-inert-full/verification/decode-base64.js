function decodeBase64Exact(value){
 const abc="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 if(typeof value!=="string"||value.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))throw Error("noncanonical base64");
 let out="";
 for(let i=0;i<value.length;i+=4){
  const a=abc.indexOf(value[i]),b=abc.indexOf(value[i+1]),cp=value[i+2]==="=",dp=value[i+3]==="=",c=cp?0:abc.indexOf(value[i+2]),d=dp?0:abc.indexOf(value[i+3]);
  if((cp&&(b&15)!==0)||(dp&&!cp&&(c&3)!==0))throw Error("base64 pad bits");
  const n=(a<<18)|(b<<12)|(c<<6)|d;
  out+=String.fromCharCode((n>>16)&255);
  if(!cp)out+=String.fromCharCode((n>>8)&255);
  if(!dp)out+=String.fromCharCode(n&255);
 }
 return out;
}
