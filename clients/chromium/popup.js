const port=chrome.runtime.connect({name:"vault-popup"});
const status=document.getElementById("status"), master=document.getElementById("master"), matches=document.getElementById("matches"), items=document.getElementById("items"), form=document.getElementById("unlock-form");
let disconnected=false;
function connectionClosed(){disconnected=true;status.textContent="已锁定，本地连接已关闭。请重新打开扩展。";master.value="";matches.hidden=true;items.replaceChildren();for(const control of document.querySelectorAll("button,input,select"))control.disabled=true;}
function send(message){if(disconnected)return false;try{port.postMessage(message);return true;}catch{connectionClosed();return false;}}
form.addEventListener("submit",(event)=>{event.preventDefault();const password=master.value;master.value="";if(disconnected)return;status.textContent="正在本地解锁…";send({op:"unlock",password});});
document.getElementById("lock").addEventListener("click",()=>{master.value="";matches.hidden=true;items.replaceChildren();send({op:"lock"});});
document.getElementById("fill").addEventListener("click",()=>{if(items.value)send({op:"fill",item_id:items.value});});
port.onMessage.addListener((message)=>{
  if(message.op==="check_focus" && Number.isInteger(message.request_id)){
    chrome.windows.getCurrent().then((window)=>send({op:"focus_response",request_id:message.request_id,window_id:window.id,focused:document.hasFocus()&&document.visibilityState==="visible"})).catch(()=>send({op:"focus_response",request_id:message.request_id,focused:false}));
    return;
  }
  if(!message.ok){status.textContent="请求被拒绝或密码库已锁定。请检查页面和本地配置。";matches.hidden=true;return;}
  if(message.op==="list"){
    document.getElementById("origin").textContent=message.origin;items.replaceChildren();
    for(const item of message.items){const option=document.createElement("option");option.value=item.id;option.textContent=item.title;items.append(option);}
    matches.hidden=false;document.getElementById("fill").disabled=message.items.length===0;status.textContent=message.items.length?"已找到当前域名的登录条目。":"当前域名没有精确匹配条目。";
  }else{status.textContent=message.op==="filled"?"已填充并锁定，请在页面提交登录。":"已锁定。";matches.hidden=true;items.replaceChildren();}
});
port.onDisconnect.addListener(connectionClosed);
