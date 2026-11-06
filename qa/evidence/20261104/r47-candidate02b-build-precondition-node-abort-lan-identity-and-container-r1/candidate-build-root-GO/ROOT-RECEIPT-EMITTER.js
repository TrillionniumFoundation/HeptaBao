function pythonSortedAsciiJson(value, depth=0){
 const indent=n=>"  ".repeat(n);
 if(value===null)return "null";
 if(typeof value==="boolean")return value?"true":"false";
 if(typeof value==="number"){if(!Number.isSafeInteger(value))throw Error("only safe integer numbers");return String(value);}
 if(typeof value==="string"){if(!/^[\x00-\x7f]*$/.test(value))throw Error("ASCII-only receipt strings");return JSON.stringify(value);}
 if(Array.isArray(value)){if(!value.length)return "[]";return "[\n"+value.map(x=>indent(depth+1)+pythonSortedAsciiJson(x,depth+1)).join(",\n")+"\n"+indent(depth)+"]";}
 if(value&&typeof value==="object"){
   if(Object.keys(value).length===1&&typeof value.$exactInteger==="string"){if(!/^-?[0-9]+$/.test(value.$exactInteger))throw Error("bad exact integer");return value.$exactInteger;}
   const keys=Object.keys(value).sort();if(!keys.length)return "{}";
   return "{\n"+keys.map(k=>indent(depth+1)+JSON.stringify(k)+": "+pythonSortedAsciiJson(value[k],depth+1)).join(",\n")+"\n"+indent(depth)+"}";
 }
 throw Error("unsupported receipt value");
}
