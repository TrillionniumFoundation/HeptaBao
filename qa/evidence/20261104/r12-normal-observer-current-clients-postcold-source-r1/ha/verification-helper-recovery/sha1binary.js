function sha1binary(s) {
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
}
