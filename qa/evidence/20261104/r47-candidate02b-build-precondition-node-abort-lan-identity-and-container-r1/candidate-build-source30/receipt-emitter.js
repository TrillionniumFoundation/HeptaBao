function exactPythonJSON(value, pretty, level=0) {
  const pad=n=>"  ".repeat(n);
  if(value===null)return "null";
  if(typeof value==="boolean")return value?"true":"false";
  if(typeof value==="number"){if(!Number.isSafeInteger(value))throw Error("only exact integers");return String(value);}
  if(typeof value==="string"){if([...value].some(c=>c.charCodeAt(0)>127))throw Error("finite ASCII input required");return JSON.stringify(value);}
  if(typeof value!=="object")throw Error("closed JSON types");
  if(!Array.isArray(value)&&Object.keys(value).length===1&&typeof value.$exactInteger==="string"){
    if(!/^-?[0-9]+$/.test(value.$exactInteger))throw Error("exact integer token");
    return value.$exactInteger;
  }
  if(Array.isArray(value)){
    if(value.length===0)return "[]";
    const rows=value.map(v=>exactPythonJSON(v,pretty,level+1));
    return pretty?"[\n"+rows.map(x=>pad(level+1)+x).join(",\n")+"\n"+pad(level)+"]":"["+rows.join(", ")+"]";
  }
  const keys=Object.keys(value).sort();
  if(keys.length===0)return "{}";
  const rows=keys.map(k=>exactPythonJSON(k,false)+": "+exactPythonJSON(value[k],pretty,level+1));
  return pretty?"{\n"+rows.map(x=>pad(level+1)+x).join(",\n")+"\n"+pad(level)+"}":"{"+rows.join(", ")+"}";
}
