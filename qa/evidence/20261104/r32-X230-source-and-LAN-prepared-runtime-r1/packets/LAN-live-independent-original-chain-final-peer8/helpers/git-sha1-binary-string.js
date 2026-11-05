function sha1(bytes){
 const n=bytes.length, words=[];for(let i=0;i<n;i++)words[i>>>2]=(words[i>>>2]||0)|(bytes.charCodeAt(i)&255)<<(24-(i%4)*8);
 words[n>>>2]=(words[n>>>2]||0)|0x80<<(24-(n%4)*8);
 const total=(((n+8)>>>6)+1)*16; words[total-2]=Math.floor(n/0x20000000);words[total-1]=(n*8)>>>0;
 let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476,e0=0xc3d2e1f0;
 const rol=(x,n)=>(x<<n)|(x>>>(32-n));
 for(let o=0;o<total;o+=16){const w=new Array(80);for(let i=0;i<16;i++)w[i]=words[o+i]||0;for(let i=16;i<80;i++)w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
  let a=a0,b=b0,c=c0,d=d0,e=e0;
  for(let i=0;i<80;i++){let f,k;if(i<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(i<40){f=b^c^d;k=0x6ed9eba1;}else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(rol(a,5)+f+e+k+w[i])|0;e=d;d=c;c=rol(b,30);b=a;a=t;}
  a0=(a0+a)|0;b0=(b0+b)|0;c0=(c0+c)|0;d0=(d0+d)|0;e0=(e0+e)|0;
 }return [a0,b0,c0,d0,e0].map(v=>(v>>>0).toString(16).padStart(8,"0")).join("");
}
