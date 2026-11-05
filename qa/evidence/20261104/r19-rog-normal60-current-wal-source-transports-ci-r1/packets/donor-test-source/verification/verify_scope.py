import difflib,hashlib,json,pathlib
root=pathlib.Path("/tmp/heptabao-donor-window-source-dbf4egmr")
ledger=json.loads("[{\"label\":\"cfg_test_observation_field\",\"before\":\"        pub(crate) per_donor_peak_frames: BTreeMap<u64, usize>,\\n        per_donor_active_frames: BTreeMap<u64, usize>,\",\"after\":\"        pub(crate) per_donor_peak_frames: BTreeMap<u64, usize>,\\n        pub(crate) object_submissions: Vec<(u64, [u8; 32])>,\\n        per_donor_active_frames: BTreeMap<u64, usize>,\"},{\"label\":\"cfg_test_observation_method\",\"before\":\"        pub(super) fn spawned(&self) {\\n            if let Ok(mut counts) = self.0.lock() {\\n                counts.spawned += 1;\\n            }\\n        }\",\"after\":\"        pub(super) fn spawned(&self, target: u64, object: Option<[u8; 32]>) {\\n            if let Ok(mut counts) = self.0.lock() {\\n                counts.spawned += 1;\\n                if let Some(id) = object {\\n                    counts.object_submissions.push((target, id));\\n                }\\n            }\\n        }\"},{\"label\":\"cfg_test_actual_submission_hook\",\"before\":\"    #[cfg(test)]\\n    if let Some(observation) = &context.observation {\\n        observation.spawned();\\n    }\",\"after\":\"    #[cfg(test)]\\n    if let Some(observation) = &context.observation {\\n        // The sole controller records actual task submission before returning to\\n        // its next assignment. Concurrent TLS handlers may observe another order.\\n        let object = match step {\\n            PullStep::Manifest(_) => None,\\n            PullStep::Object(index) => references.get(index).map(|reference| reference.id),\\n        };\\n        observation.spawned(target, object);\\n    }\"},{\"label\":\"actual_dispatch_tail_assertion\",\"before\":\"            assert_eq!(healthy.iter().copied().collect::<BTreeSet<_>>(), expected);\\n            assert!(\\n                healthy[healthy.len() - WORKERS_PER_DONOR..]\",\"after\":\"            assert_eq!(healthy.iter().copied().collect::<BTreeSet<_>>(), expected);\\n            // Tail priority belongs to the dispatcher's assignment order. The\\n            // four authenticated TLS handlers may receive those tasks out of order.\\n            // Keep the real wire population checks above and bind both observations\\n            // to the same exact set of object IDs, without delaying any handler.\\n            let submitted: Vec<_> = tasks\\n                .object_submissions\\n                .iter()\\n                .filter(|(donor, _)| *donor == 2)\\n                .map(|(_, id)| *id)\\n                .collect();\\n            assert_eq!(submitted.len(), OBJECTS);\\n            assert_eq!(submitted.iter().copied().collect::<BTreeSet<_>>(), expected);\\n            assert!(\\n                submitted[submitted.len() - WORKERS_PER_DONOR..]\"}]")
pairs={}
for name in ("v6_committed_root_pull.rs","v6_committed_root_pull_donor_window_tests.rs"):
 before=(root/"before"/name).read_text();after=(root/"after"/name).read_text()
 pairs[name]=(before,after)
 changes=ledger[:3] if name=="v6_committed_root_pull.rs" else ledger[3:]
 work=before
 for change in changes:
  assert work.count(change["before"])==1
  work=work.replace(change["before"],change["after"],1)
 assert work==after
 for change in reversed(changes):
  assert work.count(change["after"])==1
  work=work.replace(change["after"],change["before"],1)
 assert work==before
 diff="".join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),fromfile="before/"+name,tofile="candidate/"+name))
 (root/(name+".diff")).write_text(diff)

def production_projection(text):
 start=text.index("#[cfg(test)]\nmod observation {")
 end=text.index("#[cfg(test)]\npub(crate) use observation::observe_pull_tasks;",start)
 text=text[:start]+text[end:]
 start=text.index("    #[cfg(test)]\n    if let Some(observation) = &context.observation {\n",text.index("fn pending_pull("))
 end=text.index("    Ok(PendingPull {",start)
 block=text[start:end]
 assert block.startswith("    #[cfg(test)]\n")
 assert block.endswith("    }\n")
 return text[:start]+text[end:]
old,new=pairs["v6_committed_root_pull.rs"]
assert production_projection(old)==production_projection(new)
assert old.count("observation.spawned(")==new.count("observation.spawned(")==1
obstart=new.index("#[cfg(test)]\nmod observation {");obend=new.index("#[cfg(test)]\npub(crate) use",obstart)
for change in ledger[:2]:
 at=new.index(change["after"]);assert obstart<at<obend
oldtest,newtest=pairs["v6_committed_root_pull_donor_window_tests.rs"]
oldstart=oldtest.index("fn run_two_donor_recovery(");newstart=newtest.index("fn run_two_donor_recovery(")
assert oldtest[:oldstart]==newtest[:newstart]
assert oldtest[oldtest.index("\n#[test]"):]==newtest[newtest.index("\n#[test]"):]
for snippet in ['let until = started + Duration::from_secs(14);','assert_eq!(tasks.spawned, tasks.joined);','assert_eq!(tasks.active_frames, 0);','assert!(tasks.peak_frames <= 8);','assert!(tasks.per_donor_peak_frames.values().all(|peak| *peak <= 4));','assert_eq!(healthy.iter().copied().collect::<BTreeSet<_>>(), expected);','sources.stop_and_join()?;','"the healthy source fetches every leaf exactly once"','"a silent source retains only its original four requests"','"source joins retain the original operation bound"']:
 assert oldtest.count(snippet)==newtest.count(snippet)==1
assert 'assert_eq!(submitted.len(), OBJECTS);' in newtest
assert 'assert_eq!(submitted.iter().copied().collect::<BTreeSet<_>>(), expected);' in newtest
assert 'submitted[submitted.len() - WORKERS_PER_DONOR..]' in newtest
result={'schema':'heptabao.donor-window-dispatch-observation-source-proof.v1','status':'passed_source_mechanics','parent_commit':'c133d7e7b8a1df5f0be8f4337893f234c6ccede2','unique_changes':len(ledger),'forward_and_reverse_whole_exact':True,'non_test_projection_bytes_equal':True,'actual_source_handler_and_server_workers_bytes_equal':True,'original_two_test_entries_bytes_equal':True,'all_original_wire_population_capacity_deadline_byte_cleanup_assertions_preserved':True,'submission_count_and_set_checks_added':True,'changed_order_assertion_sensor':'actual sequential controller submission, rather than concurrent TLS server arrival','rust_format_or_compile':False,'rust_test_execution':False,'host_io':False,'product_runtime':False}
print(json.dumps({'proof':result,'diffs':{n:(root/(n+'.diff')).read_text() for n in pairs}},sort_keys=True))
