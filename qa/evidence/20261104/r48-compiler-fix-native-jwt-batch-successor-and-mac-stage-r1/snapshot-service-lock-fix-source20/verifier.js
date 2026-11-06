function verifySnapshotServiceLockFix(I,F) {
 const checks=[];
 const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw new Error(name);};
 check("exact base candidate",I.baseCommit==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 check("two modified Rust files only",I.files.length===2);
 let replaced=0;
 for(const [i,f] of I.files.entries()) {
  const before=F[f.beforeFile],after=F[f.afterFile],d=F[f.diffFile],r=F[f.reverseFile];
  for(const [label,raw,pin] of [["before",before,f.beforePin],["after",after,f.afterPin]]) {
   const got=gitBlobMeta(raw);check(i+" "+label+" blob",got.blob===pin.blob);
   check(i+" "+label+" bytes/SHA",got.bytes===pin.bytes&&got.sha256===pin.sha256);
  }
  const matches=[...before.matchAll(/service\s*\.lock_for_request\(\)/g)];
  check(i+" exact old Service count",matches.length===f.expectedCount);
  check(i+" fixed original deadline",f.deadline===(i===0?"self.owner.deadline":"deadline"));
  const replacement="crate::request_deadline::lock_until(service.as_ref(), "+f.deadline+")";
  check(i+" only exact Service expressions changed",before.replace(/service\s*\.lock_for_request\(\)/g,replacement)===after);
  check(i+" no Service implicit HA lock remains",!(/service\s*\.lock_for_request\(\)/.test(after)));
  check(i+" original HA lock remains",(after.match(/\.lock_for_request\(\)/g)||[]).length===1);
  check(i+" forward exact",snapshotApply(before,d)===after);
  check(i+" reverse exact",snapshotApply(after,d,true)===before);
  check(i+" standalone reverse exact",snapshotApply(after,r)===before);
  replaced+=matches.length;
 }
 check("nine exact Service expressions",replaced===9);
 const client=F[I.files[0].afterFile],source=F[I.files[1].afterFile],helper=F[I.helper],stderr=F[I.stderr];
 check("client original scope",client.includes("RequestDeadlineScope::enter(self.owner.deadline)"));
 check("source accepted-at business bound retained",source.includes(".accepted_at()\n            .checked_add(request_timeout)"));
 check("source restrict then same peer deadline",source.includes("peer.restrict_deadline(business_bound)?;\n        let deadline = peer.deadline();\n        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);"));
 check("source typed completion remains Vec",source.includes(") -> Result<(u16, Zeroizing<Vec<u8>>), Response> {"));
 check("helper exact whole",JSON.stringify(gitBlobMeta(helper))===JSON.stringify(I.helperPin));
 check("generic deadline helper exists",helper.includes("pub(crate) fn lock_until<T>(\n    mutex: &Mutex<T>,\n    deadline: Instant,"));
 check("helper min scope retained",helper.includes("let deadline = current().map_or(deadline, |outer| outer.min(deadline));"));
 check("HA trait still only concrete process",helper.includes("impl HaLock for Mutex<crate::ha::HaProcess>"));
 check("helper pre/post try_lock deadline checks",helper.includes("if Instant::now() >= deadline {\n            return Err(LockWaitError::Busy);")&&helper.includes("Ok(guard) => {\n                if Instant::now() >= deadline {"));
 check("stderr exact whole",JSON.stringify(gitBlobMeta(stderr))===JSON.stringify(I.stderrPin));
 const codes=[...stderr.matchAll(/^error\[(E\d+)\]:/gm)].map(m=>m[1]);
 check("actual nine E0599",codes.filter(x=>x==="E0599").length===9);
 check("actual two E0277 retained",codes.filter(x=>x==="E0277").length===2);
 return {schema:"snapshot-service-lock-fix-source-verifier-r1",ok:true,checks,total:checks.length,replacedServiceExpressions:replaced,files:2,sourceOnly:true,rustCompileExecuted:false,runtimeTestsExecuted:0,e0277Resolution:"unverified until actual Rust compilation"};
}
