function actualStdinProcessStartBinding(r) {
 if (Object.prototype.hasOwnProperty.call(r, "stdin_text")) throw new Error("wire_stdin_text_not_allowed");
 function sorted(x) { if (Array.isArray(x)) return x.map(sorted); if(x && typeof x === "object") return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sorted(x[k])])); return x; }
 const obj={args:r.args||[],cpu_quota_percent:r.cpu_quota_percent??null,cwd:r.cwd??null,env:r.env||{},executable:r.executable,host:r.host,memory_max_bytes:r.memory_max_bytes??null,nice:r.nice??null,stdin:r.stdin??null,timeout_seconds:r.timeout_seconds??null};
 const canonical=JSON.stringify(sorted(obj));
 const digest=sha256Latin1(byteString(utf8Bytes(canonical)));
 return {canonical,sha256:digest,native_fingerprint:BigInt("0x"+digest.slice(0,16)).toString()};
}
