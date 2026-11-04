export function decodeBase64Utf8(s) {
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 if(typeof s!=="string"||s.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw Error("invalid base64");
 const bytes=[];
 for(let i=0;i<s.length;i+=4){const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==="="?0:alphabet.indexOf(s[i+2]),d=s[i+3]==="="?0:alphabet.indexOf(s[i+3]);if(s[i+2]==="="&&(b&15))throw Error("noncanonical padding");if(s[i+3]==="="&&s[i+2]!=="="&&(c&3))throw Error("noncanonical padding");const n=(a<<18)|(b<<12)|(c<<6)|d;bytes.push((n>>>16)&255);if(s[i+2]!=="=")bytes.push((n>>>8)&255);if(s[i+3]!=="=")bytes.push(n&255);}
 let binary="";for(let i=0;i<bytes.length;i+=4096)binary+=String.fromCharCode(...bytes.slice(i,i+4096));
 return decodeURIComponent(escape(binary));
}
