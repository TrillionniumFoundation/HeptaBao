function topLevelRawFields(raw){
 let i=0;const fields={};const ws=()=>{while(/\s/.test(raw[i]||"")&&i<raw.length)i++;};
 ws();if(raw[i++]!=="{")throw Error("object expected");
 while(true){
  ws();if(raw[i]==="}"){i++;break;}
  if(raw[i]!=='"')throw Error("key expected");const start=i++;let escapeNext=false;
  while(i<raw.length){const c=raw[i++];if(escapeNext){escapeNext=false;continue;}if(c==="\\"){escapeNext=true;continue;}if(c==='"')break;}
  const key=JSON.parse(raw.slice(start,i));if(Object.prototype.hasOwnProperty.call(fields,key))throw Error("duplicate key");
  ws();if(raw[i++]!==":")throw Error("colon expected");ws();const valueStart=i;let depth=0,inString=false,escaped=false;
  for(;i<raw.length;i++){
   const c=raw[i];if(inString){if(escaped)escaped=false;else if(c==="\\")escaped=true;else if(c==='"')inString=false;continue;}
   if(c==='"')inString=true;else if(c==="{"||c==="[")depth++;else if(c==="}"||c==="]"){if(depth===0)break;depth--;}else if(c===","&&depth===0)break;
  }
  if(inString||depth!==0)throw Error("unclosed value");
  fields[key]=raw.slice(valueStart,i).trim();
  if(raw[i]===","){i++;continue;}if(raw[i]==="}"){i++;break;}throw Error("delimiter expected");
 }
 ws();if(i!==raw.length)throw Error("trailing data");return fields;
}
