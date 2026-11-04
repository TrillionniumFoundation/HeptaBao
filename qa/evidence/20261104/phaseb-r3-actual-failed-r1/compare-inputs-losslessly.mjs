// Derived evidence utility; no file, process, network or product calls.
// Numeric lexemes are tagged before JSON.parse to avoid JavaScript precision loss.
const parseLossless = (raw)=>{let out="",i=0,inString=false,escaped=false;for(;i<raw.length;i++){const c=raw[i];if(inString){out+=c;if(escaped)escaped=false;else if(c==="\\")escaped=true;else if(c==='"')inString=false;continue;}if(c==='"'){inString=true;out+=c;continue;}if(c==="-"||(c>="0"&&c<="9")){const m=raw.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);if(!m)throw Error("number");out+=JSON.stringify("\u0001json-number:"+m[0]);i+=m[0].length-1;}else out+=c;}return JSON.parse(out);};
const canonical = (v)=>{if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";if(v&&typeof v==="object")return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";return JSON.stringify(v);};
export function compareOriginalResult(raw) {
  const result = parseLossless(raw);
  return canonical(result.verified_inputs_before) === canonical(result.verified_inputs_after);
}
