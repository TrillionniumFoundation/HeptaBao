function dumpPublisherJSON(value, indent=null, depth=0) {
 const sp=n=>" ".repeat(n);
 if(value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).join(",")==="$exactInteger"){
  if(!/^-?[0-9]+$/.test(value.$exactInteger))throw Error("exact_integer");return value.$exactInteger;
 }
 if(value===null)return "null";
 if(typeof value==="boolean")return value?"true":"false";
 if(typeof value==="number"){if(!Number.isSafeInteger(value))throw Error("only_publisher_safe_integers");return String(value);}
 if(typeof value==="string"){if(!/^[\x20-\x7e]*$/.test(value))throw Error("only_existing_ascii_publisher_strings");return JSON.stringify(value);}
 const arr=Array.isArray(value),keys=arr?null:Object.keys(value).sort();
 const parts=arr?value.map(v=>dumpPublisherJSON(v,indent,depth+1)):keys.map(k=>JSON.stringify(k)+": "+dumpPublisherJSON(value[k],indent,depth+1));
 if(!parts.length)return arr?"[]":"{}";
 if(indent===null)return (arr?"[":"{")+parts.join(", ")+(arr?"]":"}");
 return (arr?"[":"{")+"\n"+parts.map(x=>sp((depth+1)*indent)+x).join(",\n")+"\n"+sp(depth*indent)+(arr?"]":"}");
}
