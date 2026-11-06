function makeFormatterReceiptBody(before,oldRows,requestPin,expected){
 let s=before;const replacements=[];
 const names=[
 ["GF_STAGE_BODY_REQUEST","GF_FORMATTER_RECEIPT_BODY_REQUEST"],
 ["GF_STAGE_BODY_EXPECTED","GF_FORMATTER_RECEIPT_BODY_EXPECTED"],
 ["GF_STAGE_RESULT_MAX_BYTES","GF_FORMATTER_RECEIPT_MAX_BYTES"],
 ["GF_STAGE_INFO_REQUEST","GF_FORMATTER_RECEIPT_INFO_REQUEST"],
 ["GF_STAGE_RESULT_PATH","GF_FORMATTER_RECEIPT_PATH"],
 ["stageResultBody","formatterReceiptBody"],["stageResultInfo","formatterReceiptInfo"],
 ["gfAuthorizeStageResultBodyOnly","gfAuthorizeFormatterReceiptBodyOnly"],
 ["gfAuthorizeStageResultInfoOnly","gfAuthorizeFormatterReceiptInfoOnly"],
 ["authorize_stage_result_body","authorize_formatter_receipt_body"],
 ["authorize_stage_result_info","authorize_formatter_receipt_info"],
 ["stage_result_binary_read_only","formatter_receipt_binary_read_only"],
 [":stage_result_body_original",":formatter_receipt_body_original"],
 ["1a1aed43ac9-fc05-62ec","1a1af017fae-fc05-64f1"]
 ];
 function mapped(t){for(const[a,b]of names)t=t.split(a).join(b);return t;}
 function one(label,a,b){const count=s.split(a).length-1;if(count!==1)throw Error(label+": "+count);s=s.replace(a,b);replacements.push({label,before:a,after:b});}
 for(const r of oldRows){
  const a=mapped(r.before);let b=mapped(r.after);
  if(r.label==="one exact body capability after actual metadata"){
   b=b.replace("Only this 27581-byte range is admitted","Only this 22202-byte range is admitted");
   b=b.replace(/^const GF_FORMATTER_RECEIPT_BODY_REQUEST = .*;$/m,"const GF_FORMATTER_RECEIPT_BODY_REQUEST = "+JSON.stringify(requestPin)+";\nconst GF_FORMATTER_RECEIPT_BODY_PAGE_BYTES = 16384;");
   b=b.replace(/^const GF_FORMATTER_RECEIPT_BODY_EXPECTED = .*;$/m,"const GF_FORMATTER_RECEIPT_BODY_EXPECTED = "+JSON.stringify(expected)+";");
   b=b.replace('   && g.maximum_binary_read_starts===1','   && g.maximum_binary_read_starts===1\n   && g.immutable_page_bytes===GF_FORMATTER_RECEIPT_BODY_PAGE_BYTES');
  }
  one(r.label,a,b);
 }
 one("new binary observer pages only; prior observer cap remains8192",
  "q.operation_id===s.activeObserver.id && q.limit===8192",
  'q.operation_id===s.activeObserver.id\n   && q.limit===(s.activeObserver.tool==="binary_read" ? GF_FORMATTER_RECEIPT_BODY_PAGE_BYTES : 8192)');
 one("same new page cap checked on returned bytes",
  "gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length",
  'gfNeed(b.length<=(a.tool==="binary_read" ? GF_FORMATTER_RECEIPT_BODY_PAGE_BYTES : 8192)\n     && v.next_offset===q.offset+b.length');
 return{source:s,replacements};
}