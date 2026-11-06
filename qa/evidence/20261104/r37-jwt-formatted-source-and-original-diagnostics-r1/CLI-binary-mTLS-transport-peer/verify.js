function verifyTransportPeer(texts, expected, pin, strictApply) {
 const checks=[];
 function check(name,value){ checks.push({name,passed:!!value}); if(!value)throw Error(name); }
 for(const e of expected) {
  const p=pin(texts[e.path]);
  check("whole:"+e.path,p.blob===e.blob&&p.bytes===e.bytes&&p.sha256===e.sha256);
 }
 for(const [before,after,diff] of [
  ["before-authenticated_peer_frame.rs","after-authenticated_peer_frame.rs","authenticated_peer_frame.diff"],
  ["before-lib.rs","after-lib.rs","lib.diff"]]) {
  const applied=strictApply(texts[before],texts[diff]);
  check("strict-one-hunk:"+diff,applied.hunks===1&&applied.raw===texts[after]);
 }
 const p=texts["candidate-native_snapshot_peer.rs"],b=texts["dependency-native_snapshot_body.rs"],test=texts["candidate-native_snapshot_peer_tests.rs"];
 const parts=texts["COMPLETE-PATCH.diff"].split(/(?=^--- )/m).filter(x=>x);
 check("complete-patch-four-files",parts.length===4);
 check("complete-patch-integration-deltas",parts[0]===texts["authenticated_peer_frame.diff"]&&parts[1]===texts["lib.diff"]);
 for(const [i,name] of [[2,"candidate-native_snapshot_peer.rs"],[3,"candidate-native_snapshot_peer_tests.rs"]]) {
  const lines=parts[i].split("\n"),header=/^@@ -0,0 \+1,([0-9]+) @@$/.exec(lines[2]);
  const body=lines.slice(3,-1);
  check("new-file-strict:"+name,header&&body.length===Number(header[1])&&body.every(x=>x.startsWith("+"))&&body.map(x=>x.slice(1)).join("\n")+"\n"===texts[name]);
 }
 check("original-authenticated-prefix-whole",texts["after-authenticated_peer_frame.rs"].startsWith(texts["before-authenticated_peer_frame.rs"]));
 check("native-feature-gates",texts["authenticated_peer_frame.diff"].includes('+#[cfg(feature = "native-v6-peer-ingress")]')&&texts["lib.diff"].includes('+#[cfg(feature = "native-v6-peer-ingress")]'));
 const client=p.slice(p.indexOf("pub fn exchange_snapshot_before("),p.indexOf("#[derive(Clone, Copy"));
 check("one-client-connect",client.split("TcpStream::connect_timeout(").length===2);
 check("client-leaf-before-token-metadata",client.indexOf("request.server_leaves.contains(&leaf)")<client.indexOf("metadata_write(&mut tls, request.metadata"));
 check("client-close-before-reverse-read",client.indexOf("tls.conn.send_close_notify();")<client.indexOf("exact_read(&mut tls, &mut decision, deadline)?;",client.indexOf("tls.conn.send_close_notify();")));
 check("client-body-finish-before-response",client.indexOf("body.finish()")<client.lastIndexOf("Ok(SnapshotPeerResponse"));
 check("client-final-deadline-and-sink-flush",client.includes("flush_before(response_sink, deadline)?;\n        time_left(deadline)?;"));
 const accept=p.slice(p.indexOf("pub fn accept_body<T>"),p.indexOf("pub fn reject("));
 check("receiver-ready-failedio-before-wire",accept.indexOf("self.phase = SnapshotPeerPhase::FailedIo;")<accept.indexOf("exact_write(self.tls, &[READY]"));
 check("receiver-witness-after-finish",accept.indexOf("body.finish()")<accept.indexOf("Ok((parsed, verified))"));
 check("receiver-data-not-result-authority",accept.includes("consumer: impl FnOnce(&mut dyn Read) -> T")&&accept.includes("let parsed = consumer(&mut body);"));
 const complete=p.slice(p.indexOf("pub fn complete("),p.indexOf("pub fn serve_one_mtls_peer_frame_or_snapshot"));
 check("complete-body-state-check",complete.includes("self.phase != SnapshotPeerPhase::BodyComplete"));
 check("complete-terminal-after-flush",complete.indexOf("flush_before(self.tls, self.deadline)?;")<complete.indexOf("*self.terminal_written = true;"));
 check("receiver-original-budget-clamp",p.includes(".checked_add(remaining)")&&p.includes(".min(deadline);")&&p.includes("tls.sock.deadline = deadline;"));
 check("snapshot-strict-alpn",p.includes("if &prefix == STREAM_PREFIX {\n        if !strict {\n            return Err(HaError::PeerAuthenticationFailed);"));
 check("body-END-before-positive-tail-read",b.indexOf("frames != self.frames")<b.indexOf("read_some(&mut self.input, &mut tail, self.deadline)?"));
 check("body-EOF-before-witness",b.indexOf("read_some(&mut self.input, &mut tail, self.deadline)?")<b.indexOf("self.verified = Some(VerifiedSnapshotBody"));
 check("body-finish-no-drain",b.includes("if self.read(&mut tail)? != 0 {\n            return Err(invalid(\"snapshot archive consumer left unread body bytes\"));"));
 check("body-existing-caps",b.includes("SNAPSHOT_BODY_CHUNK_BYTES: usize = 65_536")&&b.includes("MAX_SNAPSHOT_BODY_BYTES: u64 = 2_488_803_400"));
 const conn=texts["reference-rustls-conn.rs"],state=texts["reference-rustls-common_state.rs"],stream=texts["reference-rustls-stream.rs"];
 check("rustls-close-or-unexpected-eof",conn.includes("(true, _) => Ok(())")&&conn.includes("(false, true) => Err(io::Error::new(")&&conn.includes("io::ErrorKind::UnexpectedEof"));
 check("rustls-send-receive-independent",state.includes("self.has_received_close_notify = true;")&&state.includes("self.has_sent_close_notify = true;")&&state.includes("&& !self.has_received_close_notify"));
 check("rustls-explicit-flush-propagates",stream.includes("fn flush(&mut self) -> Result<()> {\n        self.complete_prior_io()?;"));
 const tag=JSON.parse(texts["reference-rustls-tag.json"]);
 check("exact-rustls-tag-commit",tag.tag==="v/0.23.44"&&tag.object.sha==="64ad386785c718c74262b79e6893813db381adfe");
 check("exact-rustls-lock",texts["reference-Cargo.lock"].includes('name = "rustls"\nversion = "0.23.44"'));
 const tests=[...test.matchAll(/#\[test\]\nfn ([a-z0-9_]+)/g)].map(x=>x[1]);
 check("six-test-sources",tests.length===6);
 check("actual-TCP-half-close-negative-source",test.includes("shutdown(std::net::Shutdown::Write)")&&test.includes("assert_eq!(finalized.load(Ordering::SeqCst), 0)"));
 check("wrong-pin-does-not-read-upload-source",test.includes("assert_eq!(source.position(), 0)")&&test.includes("assert_eq!(calls.load(Ordering::SeqCst), 0)"));
 return {schema:"heptabao.snapshot-peer.independent-limited-source-checks.r1",passed:true,checkCount:checks.length,checks,testsPresentNotExecuted:tests,executedRust:false,executedComponents:false,RuntimeCalls:0,ServiceIntegrationQualified:false};
}