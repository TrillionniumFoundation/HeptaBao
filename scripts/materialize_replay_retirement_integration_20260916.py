from pathlib import Path

CAP = Path('crates/heptabao-durable-service/src/capacity.rs')
SERVICE = Path('crates/heptabao-server/src/service.rs')
CAP_TESTS = Path('crates/heptabao-server/src/service_capacity_tests.rs')


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one match, found {count}')
    return text.replace(old, new, 1)


c = CAP.read_text()
insert = c.rfind('\n}')
if insert < 0:
    raise SystemExit('capacity module close not found')
extra = r'''

    #[test]
    fn replay_retirement_crash_window_recovers_authenticated_frontier() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("replay-retirement-crash-window")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        service.put_in_replay_epoch(0, put_request("old-a", b"a")?)?;
        service.put_in_replay_epoch(0, put_request("old-b", b"b")?)?;
        service.compact()?;
        let generation = service.generation();
        let empty = BTreeMap::new();
        let next_ledger = sealed_ledger(
            &service.barrier,
            generation,
            1,
            generation,
            &empty,
        )?;
        // Simulate process death after the authenticated HBC3 ledger/frontier
        // replacement and before the replacement empty-ledger checkpoint.
        atomic_write(&service.root, &ledger_path(&service.root), &next_ledger)?;
        drop(service);

        let mut recovered = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
        assert_eq!(recovered.replay_epoch(), 1);
        assert_eq!(recovered.retired_through_generation(), generation);
        assert_eq!(recovered.retained_request_count(), 0);
        assert!(matches!(
            recovered.put_in_replay_epoch(0, put_request("old-a", b"a")?),
            Err(ServiceError::ReplayEpochMismatch)
        ));
        assert!(matches!(
            recovered.put_in_replay_epoch(1, put_request("new-a", b"c")?)?,
            MutationOutcome::Committed { generation: 3, .. }
        ));
        drop(recovered);
        let recovered = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
        assert_eq!(recovered.replay_epoch(), 1);
        assert_eq!(recovered.retired_through_generation(), 2);
        assert_eq!(recovered.generation(), 3);
        Ok(())
    }

    #[test]
    fn replay_retirement_backup_restore_preserves_epoch_and_frontier() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("replay-retirement-backup")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        service.put_in_replay_epoch(0, put_request("old-a", b"a")?)?;
        service.retire_replay_epoch()?;
        let first = service.put_in_replay_epoch(1, put_request("epoch-one", b"b")?)?;
        let backup = service.export_backup()?;
        service.put_in_replay_epoch(1, put_request("later", b"c")?)?;
        let restore = service.restore_backup(&backup, true)?;
        assert_eq!(restore.restored_generation, 2);
        assert_eq!(service.replay_epoch(), 1);
        assert_eq!(service.retired_through_generation(), 1);
        assert_eq!(service.retained_request_count(), 1);
        assert!(matches!(
            service.put_in_replay_epoch(0, put_request("old-a", b"a")?),
            Err(ServiceError::ReplayEpochMismatch)
        ));
        match first {
            MutationOutcome::Committed {
                recovery_reference,
                ..
            } => assert!(matches!(
                service.reconcile(&recovery_reference),
                ReconciliationStatus::Committed { generation: 2 }
            )),
            _ => return Err(ServiceError::CorruptState),
        }
        assert!(matches!(
            service.put_in_replay_epoch(1, put_request("epoch-one", b"b")?)?,
            MutationOutcome::Duplicate { generation: 2, .. }
        ));
        Ok(())
    }
'''
c = c[:insert] + extra + c[insert:]
CAP.write_text(c)

s = SERVICE.read_text()
old = '''        if compact_before_entry {
            durable.apply_batch_with_compaction(
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        } else {
            durable.apply_batch(
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        }
'''
new = '''        let replay_epoch = durable.replay_epoch();
        if compact_before_entry {
            durable.apply_batch_with_compaction_in_replay_epoch(
                replay_epoch,
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        } else {
            durable.apply_batch_in_replay_epoch(
                replay_epoch,
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        }
'''
s = replace_once(s, old, new, 'server epoch-aware state batch')

old = '''                "sys/storage/raft/compact"
                    | "sys/storage/raft/snapshot"
                    | "sys/storage/raft/snapshot-force"
'''
new = '''                "sys/storage/raft/compact"
                    | "sys/storage/raft/replay-retire"
                    | "sys/storage/raft/snapshot"
                    | "sys/storage/raft/snapshot-force"
'''
# This authorization block appears once in source text despite search rendering duplicates.
s = replace_once(s, old, new, 'maintenance authorization path')

old = '''            "recovery_required": false,
            "automatic_journal_checkpoint": true,
            "replay_id_eviction": false
'''
new = '''            "recovery_required": false,
            "automatic_journal_checkpoint": true,
            "replay_id_eviction": false,
            "replay_epoch": durable.replay_epoch(),
            "retired_through_generation": durable.retired_through_generation(),
            "replay_retirement": "explicit-single-node"
'''
s = replace_once(s, old, new, 'capacity replay metadata')

needle = '''        if path == "sys/storage/raft/compact" {
'''
route = r'''        if path == "sys/storage/raft/replay-retire" {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "replay retirement requires POST or PUT");
            }
            if body.as_object().is_none_or(|object| !object.is_empty()) {
                return Response::error(400, "replay retirement accepts an empty JSON object");
            }
            // Multi-node epoch transition needs quorum ordering and is deliberately
            // deferred to the HA fault/upgrade closure. Never retire one node's
            // replay frontier behind its peers.
            if self.ha.is_some() {
                return Response::error(
                    409,
                    "replay retirement requires single-node mode until coordinated HA epoch transition is qualified",
                );
            }
            let (result, fenced) = {
                let Some(durable) = self.durable.as_mut() else {
                    return Response::error(503, "server is sealed");
                };
                let result = durable.retire_replay_epoch();
                (result, durable.recovery_required())
            };
            if fenced {
                self.recovery_required = true;
            }
            return match result {
                Ok(outcome) => Response::ok(json!({
                    "data": {
                        "previous_epoch": outcome.previous_epoch,
                        "replay_epoch": outcome.current_epoch,
                        "retired_through_generation": outcome.retired_through_generation,
                        "retired_requests": outcome.retired_requests,
                    }
                })),
                Err(_) => Response::error(503, "replay retirement failed; inspect durable state"),
            };
        }

'''
if s.count(needle) != 1:
    raise SystemExit(f'replay route insertion count={s.count(needle)}')
s = s.replace(needle, route + needle, 1)
SERVICE.write_text(s)

# Add service-level proof that retirement is root-only, frees replay slots, and
# subsequent authoritative state persistence uses the new current epoch.
t = CAP_TESTS.read_text()
t += r'''

#[test]
fn replay_retirement_is_root_only_and_state_commits_continue_in_new_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-retirement-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        assert_eq!(init.status, 200);
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        let token = init.body["root_token"].as_str().ok_or("missing token")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let retire = "sys/storage/raft/replay-retire";
        assert_eq!(
            service
                .handle_at("POST", retire, "", "invalid-token", json!({}), 100)
                .status,
            403
        );
        let before = service
            .durable
            .as_ref()
            .ok_or("missing durable")?
            .retained_request_count();
        assert!(before > 0);
        let retired = service.handle_at("POST", retire, "", token, json!({}), 100);
        assert_eq!(retired.status, 200);
        assert_eq!(retired.body["data"]["previous_epoch"], 0);
        assert_eq!(retired.body["data"]["replay_epoch"], 1);
        assert!(retired.body["data"]["retired_requests"].as_u64().is_some_and(|n| n > 0));
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 1);
        assert_eq!(durable.retained_request_count(), 0);

        // This mutation exercises Service::persist_state_batch. If it accidentally
        // rebinds to legacy epoch zero, the request fails before durable entry.
        let write = service.handle_at(
            "POST",
            "secret/data/post-retirement",
            "",
            token,
            json!({"data": {"value": "commits-in-epoch-one"}}),
            101,
        );
        assert_eq!(write.status, 200);
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 1);
        assert_eq!(durable.retained_request_count(), 1);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}
'''
CAP_TESTS.write_text(t)
