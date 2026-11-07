function restore4aInfoLocalCloseAction({goRaw,goPin,goWholeReadback,beforeRaw,afterRaw}) {
 const slot="combined_4a49405b_rog_source_gitfirst_r1";
 const beforePin={"blob":"bd06c489e911bf65d630ae8665e9ca5e00d96de2","bytes":157674,"sha256":"99343cb695f2bfda2c47111dd8b226d02479ad15f051179bc13b9bb60e605efe"},afterPin={"blob":"22cb576c41caea26beb8f931dfa8a8a9e48a0262","bytes":157675,"sha256":"3808482edffd2a0fb68de8bf15ae42af22a52b5eff80c36ae521ef47ed7b1c0d"};
 function need(v,c){if(!v)throw Error(c);}
 function eq(raw,p){return JSON.stringify(gitBlobMeta(raw))===JSON.stringify(p);}
 need(goWholeReadback===true&&eq(goRaw,goPin),"whole explicit recovery GO");
 const g=JSON.parse(goRaw);
 need(g.authorization==="GO"&&g.scope==="4a_info_local_close_action_recovery_only"&&g.before_state?.blob===beforePin.blob&&g.after_state?.blob===afterPin.blob&&g.native_calls_authorized===0,"exact recovery scope");
 need(eq(beforeRaw,beforePin)&&eq(afterRaw,afterPin),"immutable before after");
 const current=load(slot);need(eq(JSON.stringify(current,null,2)+"\n",beforePin),"same current state");
 need(current.paused===true&&current.pending===null&&!current.nativeCallInFlight&&current.activeObserver?.id==="578da6337fdfe69127df760cd01b59b0916e181914666ba5f1be3c97fa82bd00"&&current.activeObserver.futureClosed===true&&current.activeObserver.eof===true&&current.activeObserver.total===579&&current.activeObserver.nextPageOffset===579,"same closed original observer");
 need(current.outerFailure?.action==="close"&&current.outerFailure?.message==="closed_gfRun_action"&&current.calls["c4a-source-r1-reportinfo-p0"]?.phase==="accepted","exact local action failure");
 need(load(slot+":local_close_action_recovery")===undefined,"once source recovery");
 const next=JSON.parse(afterRaw),only={...current,paused:false};
 need(JSON.stringify(next)===JSON.stringify(only),"only paused false; all old errors kept");
 store(slot+":local_close_action_recovery",{goPin,beforePin,afterPin,oldOuterFailure:current.outerFailure,NativeCalls:0,reason:"wrong local action close; correct close_observer not yet reached"});
 store(slot,next);
 return {restored:true,NativeCalls:0,nextAction:"close_observer",originalObserver:next.activeObserver.id};
}
