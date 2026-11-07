/* The only public entry. No exception-derived text or stack is returned. */
async function b4pRun(action,input){
 try{
  if(action==="prepare")return {ok:true,value:await b4pPrepare(input)};
  if(action==="invoke")return {ok:true,value:await b4pInvokeAndArchivePrivate()};
  if(action==="accept")return {ok:true,value:b4pAcceptSafeProjection()};
  throw new Error("closed_private_action_set");
 }catch(error){
  store(B4P_SLOT+":private-entry-exception",{
   name:String(error?.name),message:String(error?.message),stack:String(error?.stack)});
  return {ok:false,stopped:true,code:"private_adapter_stopped"};
 }
}
