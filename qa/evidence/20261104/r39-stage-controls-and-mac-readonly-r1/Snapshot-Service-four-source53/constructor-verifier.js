function verifySnapshotFixtureOrigins({pipeline:p,test}) {
 const checks=[];function check(name,condition){checks.push({name,pass:!!condition});if(!condition)throw Error(name);}
 check("old constructor wrapper explicit original false",p.afterText.includes("Self::start_with_snapshot_routes(configured_native_storage, false)"));
 check("new constructor only enables origins",p.afterText.includes("fn start_for_snapshot_forwarding() -> TestResult<Self> {\n        Self::start_with_snapshot_routes(false, true)\n"));
 check("old start unchanged calls configured false",p.afterText.includes("pub(super) fn start() -> TestResult<Self> {\n        Self::start_with_configured_storage(false)\n"));
 check("only fixed original peer socket origin",p.afterText.includes('peer.api_address = Some(format!("https://{}", peer.address))'));
 check("all postconstructor methods/tests whole",p.afterText.slice(p.afterText.indexOf("    fn directory("))===p.beforeText.slice(0+p.beforeText.indexOf("    fn directory(")));
 check("all preconstructor source whole",p.afterText.slice(0,p.afterText.indexOf("    fn start_with_configured_storage("))===p.beforeText.slice(0,p.beforeText.indexOf("    fn start_with_configured_storage(")));
 check("only2 constructor calls in new tests",(test.beforeText.match(/Pipeline::start\(\)\?/g)||[]).length===2&&test.afterText===test.beforeText.replaceAll("Pipeline::start()?","Pipeline::start_for_snapshot_forwarding()?"));
 check("new tests explicitly reject legacy redirect",test.afterText.includes('NativeSnapshotAdmission::Redirect(_) => Err("standby snapshot used legacy redirect".into())'));
 check("same real mTLS/limits/ownership old constructor body",!p.afterText.includes("let configs =")&&p.afterText.includes("peer_timeout_ms: 1500")&&p.afterText.includes("forward_timeout_ms: 8000")&&p.afterText.includes("max_inflight: 32")&&p.afterText.includes("allow_legacy_peer_v1: false"));
 check("no new HTTP client or listener",p.afterText.split("TcpListener::bind").length===p.beforeText.split("TcpListener::bind").length&&p.afterText.split("register_forward_handler").length===p.beforeText.split("register_forward_handler").length);
 return {checks,allPassed:checks.every(x=>x.pass),sourceOnly:true};
}
