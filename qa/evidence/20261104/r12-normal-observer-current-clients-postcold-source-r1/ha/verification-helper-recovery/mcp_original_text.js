function originalText(r){if(r.isError)throw new Error("MCP error");const a=r.content?.filter(x=>x.type==="text");if(a?.length!==1)throw new Error("expected single original text");return a[0].text;}
