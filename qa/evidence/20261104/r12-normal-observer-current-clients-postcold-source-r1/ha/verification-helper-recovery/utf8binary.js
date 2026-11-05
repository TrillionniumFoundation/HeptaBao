function utf8binary(text) {
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
}
