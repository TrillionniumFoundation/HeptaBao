function sha256Bytes(input){
 const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const n=input.length,b=new Uint8Array(((n+9+63)>>6)<<6);for(let i=0;i<n;i++){const c=input.charCodeAt(i);if(c>255)throw Error("byte string required");b[i]=c;}b[n]=128;
 const bits=n*8,hi=Math.floor(bits/4294967296),lo=bits>>>0;
 for(let i=0;i<4;i++){b[b.length-8+i]=(hi>>>(24-8*i))&255;b[b.length-4+i]=(lo>>>(24-8*i))&255;}
 let H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];const W=new Uint32Array(64),rr=(x,n)=>(x>>>n)|(x<<(32-n));
 for(let off=0;off<b.length;off+=64){
  for(let t=0;t<16;t++){let p=off+4*t;W[t]=((b[p]<<24)|(b[p+1]<<16)|(b[p+2]<<8)|b[p+3])>>>0;}
  for(let t=16;t<64;t++){let x=W[t-15],y=W[t-2];W[t]=(W[t-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[t-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0;}
  let[a,c,d,e,f,g,h,i]=H;
  for(let t=0;t<64;t++){const T1=(i+(rr(f,6)^rr(f,11)^rr(f,25))+((f&g)^(~f&h))+K[t]+W[t])>>>0,T2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&c)^(a&d)^(c&d)))>>>0;i=h;h=g;g=f;f=(e+T1)>>>0;e=d;d=c;c=a;a=(T1+T2)>>>0;}
  const v=[a,c,d,e,f,g,h,i];H=H.map((x,j)=>(x+v[j])>>>0);
 }return H.map(x=>x.toString(16).padStart(8,"0")).join("");
}
