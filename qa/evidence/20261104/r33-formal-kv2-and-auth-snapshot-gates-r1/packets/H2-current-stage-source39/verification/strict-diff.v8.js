function strictStage(before,after,diff,applyDiff,utf8,sha1,sha256){
 const f=applyDiff(before,diff),r=applyDiff(after,diff,true);
 if(f.text!==after||r.text!==before||f.hunks!==14||r.hunks!==14)throw Error("strict whole diff");
 const pin=s=>{const b=utf8(s);return{blob:sha1("blob "+b.length+"\0"+b),bytes:b.length,sha256:sha256(b)};};
 return {status:"PASS_STRICT_WHOLE_SOURCE",before:pin(before),after:pin(after),diff:pin(diff),forward_hunks:f.hunks,reverse_hunks:r.hunks,Runtime_calls:0,modules_executed:0};
}
