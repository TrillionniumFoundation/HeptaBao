function topTokens(raw){
    JSON.parse(raw);
    let i=0;
    const white=()=>{while(/\s/.test(raw[i]??"")&&i<raw.length)i++;};
    function stringEnd(at){let j=at+1;for(;j<raw.length;j++){if(raw[j]==="\\"){j++;continue;}if(raw[j]==='"')return j+1;}throw new Error("token_string");}
    white();if(raw[i++]!=="{")throw new Error("token_object");
    const result={};
    while(true){
      white();if(raw[i]==="}"){i++;break;}
      if(raw[i]!=='"')throw new Error("token_key");
      const end=stringEnd(i),key=JSON.parse(raw.slice(i,end));i=end;white();
      if(raw[i++]!==":")throw new Error("token_colon");white();
      const start=i;
      if(raw[i]==='"')i=stringEnd(i);
      else if(raw[i]==="{"||raw[i]==="["){
        const stack=[raw[i++]];
        while(stack.length){
          if(i>=raw.length)throw new Error("token_nesting");
          const ch=raw[i];
          if(ch==='"'){i=stringEnd(i);continue;}
          if(ch==="{"||ch==="[")stack.push(ch);
          else if(ch==="}"||ch==="]"){
            const open=stack.pop();if((open==="{"&&ch!=="}")||(open==="["&&ch!=="]"))throw new Error("token_pair");
          }
          i++;
        }
      } else while(i<raw.length&&raw[i]!==","&&raw[i]!=="}")i++;
      if(Object.prototype.hasOwnProperty.call(result,key))throw new Error("duplicate_key");
      result[key]=raw.slice(start,i).trimEnd();white();
      if(raw[i]===","){i++;continue;}if(raw[i]==="}"){i++;break;}throw new Error("token_separator");
    }
    white();if(i!==raw.length)throw new Error("token_trailing");return result;
  }
