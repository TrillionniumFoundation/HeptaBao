const utf8 = function utf8binary(text) {
  let out="";
  for (const ch of text) {
    const n=ch.codePointAt(0);
    if(n>=0xd800&&n<=0xdfff) throw new Error("unpaired UTF-16 surrogate");
    if(n<0x80)out+=String.fromCharCode(n);
    else if(n<0x800)out+=String.fromCharCode(0xc0|(n>>6),0x80|(n&63));
    else if(n<0x10000)out+=String.fromCharCode(0xe0|(n>>12),0x80|((n>>6)&63),0x80|(n&63));
    else out+=String.fromCharCode(0xf0|(n>>18),0x80|((n>>12)&63),0x80|((n>>6)&63),0x80|(n&63));
  }
  return out;
};
const sha1 = function sha1binary(s) {
  const len=s.length,n=Math.ceil((len+9)/64)*64,buf=new Uint8Array(n),dv=new DataView(buf.buffer);
  for(let i=0;i<len;i++){const b=s.charCodeAt(i);if(b>255)throw new Error("binary input only");buf[i]=b;}
  buf[len]=0x80;dv.setUint32(n-8,Math.floor(len/0x20000000));dv.setUint32(n-4,(len*8)>>>0);
  const H=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0],w=new Uint32Array(80);const L=(x,n)=>(x<<n)|(x>>>(32-n));
  for(let off=0;off<n;off+=64){
    for(let j=0;j<16;j++)w[j]=dv.getUint32(off+j*4);
    for(let j=16;j<80;j++)w[j]=L(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);
    let[a,b,c,d,e]=H;
    for(let j=0;j<80;j++){let f,k;if(j<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(j<40){f=b^c^d;k=0x6ed9eba1;}else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(L(a,5)+f+e+k+w[j])>>>0;e=d;d=c;c=L(b,30);b=a;a=t;}
    const v=[a,b,c,d,e];for(let j=0;j<5;j++)H[j]=(H[j]+v[j])>>>0;
  }
  return H.map(x=>x.toString(16).padStart(8,"0")).join("");
};
const sha256 = function sha256binary(s) {
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const len=s.length, n=Math.ceil((len+9)/64)*64,buf=new Uint8Array(n),dv=new DataView(buf.buffer);
  for(let i=0;i<len;i++){let b=s.charCodeAt(i);if(b>255)throw new Error("binary input only");buf[i]=b;}
  buf[len]=0x80;dv.setUint32(n-8,Math.floor(len/0x20000000));dv.setUint32(n-4,(len*8)>>>0);
  const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Uint32Array(64);
  const R=(x,n)=>(x>>>n)|(x<<(32-n));
  for(let off=0;off<n;off+=64){
    for(let j=0;j<16;j++)w[j]=dv.getUint32(off+j*4);
    for(let j=16;j<64;j++){const x=w[j-15],y=w[j-2];w[j]=(w[j-16]+(R(x,7)^R(x,18)^(x>>>3))+w[j-7]+(R(y,17)^R(y,19)^(y>>>10)))>>>0;}
    let [a,b,c,d,e,f,g,h]=H;
    for(let j=0;j<64;j++){const t1=(h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+K[j]+w[j])>>>0;const t2=((R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c)))>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
    const v=[a,b,c,d,e,f,g,h];for(let j=0;j<8;j++)H[j]=(H[j]+v[j])>>>0;
  }
  return H.map(x=>x.toString(16).padStart(8,"0")).join("");
};
const decode64 = function decodeBase64Binary(s){if(typeof s!=="string"||s.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw new Error("base64 syntax");const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let acc=0,bits=0,out="";for(const c of s){if(c==="=")break;acc=(acc<<6)|chars.indexOf(c);bits+=6;if(bits>=8){bits-=8;out+=String.fromCharCode((acc>>>bits)&255);}}if(bits>0&&(acc&((1<<bits)-1))!==0)throw new Error("base64 nonzero pad bits");return out;};
