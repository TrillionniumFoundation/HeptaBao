// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed capability/parser and private metadata fault fixtures only.
//! No runtime initialization, SSH, services, jobs, or live effects.
use super::*;
const LEGACY_OWNER_KEYS: usize = 128;
const LEGACY_GLOBAL_KEYS: usize = 512;
use serde_json::json;

fn readonly_rows() -> Vec<serde_json::Value> {
	vec![
		json!({"tool":"read_multiple_files","arguments":{"host":"fixture","paths":["/fixture/data"]}}),
		json!({"tool":"file_info","arguments":{"host":"fixture","path":"/fixture/data"}}),
		json!({"tool":"binary_read","arguments":{"host":"fixture","path":"/fixture/data","offset":0,"limit":17}}),
		json!({"tool":"process_status","arguments":{"host":"fixture","job_id":"fixture-job"}}),
		json!({"tool":"process_read","arguments":{"host":"fixture","job_id":"fixture-job","limit":17}}),
		json!({"tool":"process_wait","arguments":{"host":"fixture","job_id":"fixture-job","timeout_seconds":1}}),
		json!({"tool":"process_list","arguments":{}}),
		json!({"tool":"hardware_snapshot","arguments":{"host":"fixture"}}),
		json!({"tool":"service_status","arguments":{"host":"fixture","services":["fixture.service"]}}),
		json!({"tool":"network_inspect","arguments":{"host":"fixture"}}),
	]
}

#[test]
fn exactly_ten_closed_typed_readonly_arms_roundtrip_without_generic_dispatch() {
	let mut actual = std::collections::BTreeSet::new();
	for row in readonly_rows() {
		let operation: ReadOperation = serde_json::from_value(row.clone()).unwrap();
		assert_eq!(operation.tool(), row["tool"].as_str().unwrap());
		assert_eq!(
			serde_json::from_value::<ReadOperation>(serde_json::to_value(operation).unwrap())
				.unwrap()
				.tool(),
			row["tool"].as_str().unwrap()
		);
		actual.insert(row["tool"].as_str().unwrap().to_owned());
	}
	assert_eq!(actual.len(), 10);
}

#[test]
fn effectful_recursive_maintenance_and_arbitrary_tool_names_never_parse() {
	for tool in [
		"process_start",
		"process_cancel",
		"pty_input",
		"host_signal",
		"binary_write",
		"binary_upload",
		"inode_patch",
		"privileged_action",
		"maintenance_apply",
		"operation_start",
		"operation_status",
		"operation_result",
		"operation_cancel",
		"request_start",
		"request_result",
		"read_file",
		"shell",
		"arbitrary_tool",
		"FILE_INFO",
	] {
		assert!(
			serde_json::from_value::<ReadOperation>(json!({"tool":tool,"arguments":{}})).is_err(),
			"unlisted capability must not acquire an operation dispatch arm"
		);
	}
}

#[test]
fn start_envelope_denies_caller_authority_and_unknown_root_fields() {
	for name in [
		"owner",
		"request_id",
		"operation_id",
		"ssh_target",
		"executable",
		"pid",
		"allow_write",
		"runtime_config",
		"policy",
	] {
		let mut input =
			json!({"operation":{"tool":"process_list","arguments":{}},"idempotency_key":"fixture"});
		input[name] = json!("untrusted");
		assert!(serde_json::from_value::<OperationStartParams>(input).is_err());
	}
}

#[test]
fn typed_operation_envelope_denies_hidden_generic_dispatch_arguments() {
	for name in [
		"owner",
		"ssh_target",
		"executable",
		"args",
		"pid",
		"tool_name",
		"timeout_seconds",
	] {
		for mut input in readonly_rows() {
			input[name] = json!("untrusted");
			assert!(serde_json::from_value::<ReadOperation>(input).is_err());
		}
	}
}

#[test]
fn each_readonly_argument_type_denies_extra_caller_authority() {
	for name in [
		"owner",
		"ssh_target",
		"executable",
		"command",
		"pid",
		"privileged_action",
	] {
		for mut input in readonly_rows() {
			input["arguments"][name] = json!("untrusted");
			assert!(serde_json::from_value::<ReadOperation>(input).is_err());
		}
	}
}

#[test]
fn cancellation_and_status_can_only_reference_server_operation_ids() {
	for key in ["pid", "host", "signal", "executable", "owner", "request_id"] {
		let mut input = json!({"operation_id":"0000000000000000000000000000000000000000000000000000000000000001"});
		input[key] = json!(12345);
		assert!(serde_json::from_value::<OperationCancelParams>(input.clone()).is_err());
		assert!(serde_json::from_value::<OperationStatusParams>(input).is_err());
	}
	for value in [
		json!(12345),
		json!({"pid":12345}),
		json!([12345]),
		json!(null),
	] {
		assert!(
			serde_json::from_value::<OperationCancelParams>(json!({"operation_id":value})).is_err()
		);
	}
}

#[test]
fn result_cursor_types_have_bounded_unsigned_wire_representation() {
	let id = "0000000000000000000000000000000000000000000000000000000000000001";
	for page in [
		json!({"operation_id":id,"offset":-1}),
		json!({"operation_id":id,"offset":4294967296_u64}),
		json!({"operation_id":id,"limit":-1}),
		json!({"operation_id":id,"limit":65536_u64}),
		json!({"operation_id":id,"limit":"16384"}),
		json!({"operation_id":id,"owner":"untrusted"}),
	] {
		assert!(serde_json::from_value::<OperationResultParams>(page).is_err());
	}
	let valid: OperationResultParams =
		serde_json::from_value(json!({"operation_id":id,"offset":0,"limit":16384})).unwrap();
	assert_eq!(valid.offset, Some(0));
	assert_eq!(valid.limit, Some(16384));
}

#[test]
fn server_identity_validator_refuses_os_pid_paths_case_and_other_widths() {
	assert!(valid_id(&format!("{:064x}", 1)));
	for id in [
		"",
		"12345",
		"../operation",
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"000000000000000000000000000000000000000000000000000000000000000z",
	] {
		assert!(!valid_id(id));
	}
}

#[test]
fn private_idempotency_keys_are_bounded_by_bytes_and_cannot_contain_controls() {
	assert!(valid_key("private fixture"));
	assert!(valid_key(&"x".repeat(128)));
	assert!(!valid_key(&"x".repeat(129)));
	assert!(!valid_key(&"界".repeat(43)));
	for key in ["", "x\0y", "x\ny", "x\ry", "x\ty", "x\u{7f}y"] {
		assert!(!valid_key(key));
	}
}

#[test]
fn private_key_binding_is_credential_bound_and_never_plaintext_authority() {
	let scope =
		ResultCryptoScope::from_verified_token(b"tttttttttttttttttttttttttttttttt").unwrap();
	let foreign =
		ResultCryptoScope::from_verified_token(b"uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu").unwrap();
	let key = b"private-key-marker-e3aa2e5c1c1440b8a9005a787f1fb017";
	let a = scope.idempotency_binding(key).unwrap();
	assert!(valid_id(&a));
	assert_ne!(a, foreign.idempotency_binding(key).unwrap());
	assert_ne!(
		a,
		scope
			.idempotency_binding(b"another private fixture key")
			.unwrap()
	);
	assert_eq!(a, scope.clone().idempotency_binding(key).unwrap());
	assert!(!a.contains(std::str::from_utf8(key).unwrap()));
}

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};

fn fixture_id(number: u64) -> String {
	format!("{number:064x}")
}

fn fixture_root() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
	store(root.path()).unwrap();
	root
}

fn fixture_ledger(root: &Path) -> String {
	let base = root_at(root).unwrap();
	let anchor: Anchor = read_json(&base, ANCHOR_NAME).unwrap();
	anchor.namespace_id
}

fn fixture_binding(root: &Path, number: u64) -> Binding {
	Binding {
		request_id: fixture_id(number),
		owner: fixture_id(0xeeee),
		tool_name: "file_info".into(),
		accepted_unix_ms: 1000 + u128::from(number),
		key_hash: fixture_id(10_000 + number),
		request_hash: fixture_id(0xfeed),
		policy_binding: fixture_id(0xbeef),
		ledger_identity: fixture_ledger(root),
	}
}

fn require_new(reservation: Reservation) -> Binding {
	match reservation {
		Reservation::New(binding) => binding,
		Reservation::Existing(_) => panic!("fixture expected one fresh admission permit"),
	}
}

fn require_existing(reservation: Reservation) -> Binding {
	match reservation {
		Reservation::Existing(binding) => binding,
		Reservation::New(_) => panic!("used operation key must never acquire another permit"),
	}
}

fn same_binding(left: &Binding, right: &Binding) {
	assert!(
		left == right,
		"complete immutable binding must remain identical"
	);
}

fn graph_paths(root: &Path, binding: &Binding) -> [PathBuf; 3] {
	let dir = root.join(STORE_NAME);
	[
		dir.join(format!("{}.json", binding.key_hash)),
		dir.join(".occupied")
			.join(format!("{}.json", binding.key_hash)),
		dir.join(".intents")
			.join(format!("{}.json", binding.request_id)),
	]
}

fn private_fixture_write(path: &Path, data: &[u8]) {
	let mut file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.unwrap();
	file.write_all(data).unwrap();
	file.sync_all().unwrap();
}

#[test]
fn reservation_publishes_a_private_complete_immutable_three_record_graph() {
	let root = fixture_root();
	let proposed = fixture_binding(root.path(), 1);
	let reserved = require_new(reserve_at(root.path(), proposed.clone()).unwrap());
	same_binding(&reserved, &proposed);
	for path in graph_paths(root.path(), &reserved) {
		let metadata = fs::metadata(&path).unwrap();
		assert_eq!(metadata.mode() & 0o7777, 0o600);
		assert_eq!(metadata.nlink(), 1);
		assert!(metadata.len() <= 4096);
		let stored: Binding = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
		same_binding(&stored, &reserved);
	}
	let by_key = lookup_key_at(
		root.path(),
		&reserved.owner,
		&reserved.key_hash,
		&reserved.request_hash,
		&reserved.policy_binding,
	)
	.unwrap()
	.unwrap();
	let by_id = lookup_id_at(
		root.path(),
		&reserved.owner,
		&reserved.request_id,
		&reserved.policy_binding,
	)
	.unwrap()
	.unwrap();
	same_binding(&by_key, &reserved);
	same_binding(&by_id, &reserved);
}

#[test]
fn repeating_pending_key_preserves_identity_even_without_audit_or_payload_receipts() {
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 2)).unwrap());
	let mut another = first.clone();
	another.request_id = fixture_id(900_002);
	another.accepted_unix_ms += 90_000;
	let repeated = require_existing(reserve_at(root.path(), another).unwrap());
	same_binding(&first, &repeated);
	assert!(!root.path().join("request-audit").exists());
	let payload = root
		.path()
		.join(STORE_NAME)
		.join(".payloads")
		.join(format!("{}.bin", first.request_id));
	assert!(!payload.exists());
}

#[test]
fn every_missing_graph_role_refuses_retry_and_never_repairs_or_reissues_a_permit() {
	for missing_role in 0..3 {
		let root = fixture_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 10)).unwrap());
		let paths = graph_paths(root.path(), &first);
		let surviving_before: Vec<_> = paths
			.iter()
			.enumerate()
			.filter(|(index, _)| *index != missing_role)
			.map(|(_, path)| fs::read(path).unwrap())
			.collect();
		fs::remove_file(&paths[missing_role]).unwrap();
		let mut another = first.clone();
		another.request_id = fixture_id(910_010);
		assert!(reserve_at(root.path(), another).is_err());
		assert!(lookup_key_at(
			root.path(),
			&first.owner,
			&first.key_hash,
			&first.request_hash,
			&first.policy_binding,
		)
		.is_err());
		assert!(!paths[missing_role].exists());
		let surviving_after: Vec<_> = paths
			.iter()
			.enumerate()
			.filter(|(index, _)| *index != missing_role)
			.map(|(_, path)| fs::read(path).unwrap())
			.collect();
		assert_eq!(surviving_before, surviving_after);
	}
}

#[test]
fn deletion_of_both_key_markers_leaves_historical_intent_as_a_no_replay_boundary() {
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 20)).unwrap());
	let paths = graph_paths(root.path(), &first);
	fs::remove_file(&paths[0]).unwrap();
	fs::remove_file(&paths[1]).unwrap();
	let intent = fs::read(&paths[2]).unwrap();
	let mut another = first.clone();
	another.request_id = fixture_id(920_020);
	assert!(reserve_at(root.path(), another).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(&paths[2]).unwrap(), intent);
	assert!(!paths[0].exists() && !paths[1].exists());
}

#[test]
fn conflicts_in_owner_tool_arguments_policy_or_ledger_never_mutate_used_binding() {
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 30)).unwrap());
	let before: Vec<_> = graph_paths(root.path(), &first)
		.iter()
		.map(|path| fs::read(path).unwrap())
		.collect();
	for field in 0..5 {
		let mut conflict = first.clone();
		conflict.request_id = fixture_id(930_000 + field);
		match field {
			0 => conflict.owner = fixture_id(0xdddd),
			1 => conflict.tool_name = "binary_read".into(),
			2 => conflict.request_hash = fixture_id(0xfeed + 1),
			3 => conflict.policy_binding = fixture_id(0xbeef + 1),
			_ => conflict.ledger_identity = fixture_id(0xdead),
		}
		assert!(reserve_at(root.path(), conflict).is_err());
		let after: Vec<_> = graph_paths(root.path(), &first)
			.iter()
			.map(|path| fs::read(path).unwrap())
			.collect();
		assert_eq!(after, before);
	}
}

#[test]
fn foreign_namespace_complete_graph_cannot_be_imported_as_local_authority() {
	let source = fixture_root();
	let destination = fixture_root();
	let source_binding =
		require_new(reserve_at(source.path(), fixture_binding(source.path(), 40)).unwrap());
	assert_ne!(
		fixture_ledger(source.path()),
		fixture_ledger(destination.path())
	);
	for (from, to) in graph_paths(source.path(), &source_binding)
		.iter()
		.zip(graph_paths(destination.path(), &source_binding))
	{
		private_fixture_write(&to, &fs::read(from).unwrap());
	}
	assert!(lookup_id_at(
		destination.path(),
		&source_binding.owner,
		&source_binding.request_id,
		&source_binding.policy_binding,
	)
	.is_err());
	let mut another = source_binding.clone();
	another.request_id = fixture_id(940_040);
	assert!(reserve_at(destination.path(), another).is_err());
}

#[test]
fn every_graph_record_rejects_symlinks_hardlinks_public_permissions_and_corruption() {
	for role in 0..3 {
		for fault in 0..4 {
			let root = fixture_root();
			let first =
				require_new(reserve_at(root.path(), fixture_binding(root.path(), 50)).unwrap());
			let paths = graph_paths(root.path(), &first);
			let victim = &paths[role];
			let bytes = fs::read(victim).unwrap();
			match fault {
				0 => {
					let outside = root.path().join("outside.json");
					private_fixture_write(&outside, &bytes);
					fs::remove_file(victim).unwrap();
					symlink(outside, victim).unwrap();
				}
				1 => {
					fs::hard_link(victim, root.path().join("hardlink.json")).unwrap();
				}
				2 => {
					fs::set_permissions(victim, fs::Permissions::from_mode(0o644)).unwrap();
				}
				_ => {
					fs::write(victim, b"{not valid metadata").unwrap();
				}
			}
			assert!(lookup_key_at(
				root.path(),
				&first.owner,
				&first.key_hash,
				&first.request_hash,
				&first.policy_binding,
			)
			.is_err());
			let mut another = first.clone();
			another.request_id = fixture_id(950_050);
			assert!(reserve_at(root.path(), another).is_err());
		}
	}
}

#[test]
fn graph_fifo_is_nonblocking_refusal_without_waiting_for_a_writer() {
	use std::os::unix::ffi::OsStrExt;
	for role in 0..3 {
		let root = fixture_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 60)).unwrap());
		let paths = graph_paths(root.path(), &first);
		fs::remove_file(&paths[role]).unwrap();
		let raw = std::ffi::CString::new(paths[role].as_os_str().as_bytes()).unwrap();
		assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
		let began = std::time::Instant::now();
		assert!(lookup_key_at(
			root.path(),
			&first.owner,
			&first.key_hash,
			&first.request_hash,
			&first.policy_binding,
		)
		.is_err());
		assert!(began.elapsed() < std::time::Duration::from_secs(2));
	}
}

#[test]
fn payload_directory_replacement_does_not_create_a_new_trusted_namespace() {
	let root = fixture_root();
	let original = root.path().join(STORE_NAME).join(".payloads");
	let moved = root.path().join("old-payloads");
	fs::rename(&original, &moved).unwrap();
	fs::create_dir(&original).unwrap();
	fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
	assert!(store(root.path()).is_err());
	assert!(moved.is_dir());
}

#[test]
fn completed_and_unknown_owner_keys_grow_beyond_128_without_rebinding_history() {
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 1000)).unwrap());
	let before = graph_snapshot(root.path(), &first);
	for number in 1001..1001 + LEGACY_OWNER_KEYS as u64 + 32 {
		let binding =
			require_new(reserve_at(root.path(), fixture_binding(root.path(), number)).unwrap());
		if number % 2 == 0 {
			outcome_at(root.path(), &binding, Some("completed")).unwrap();
		}
	}
	let mut repeat = first.clone();
	repeat.request_id = fixture_id(900_100);
	same_binding(
		&first,
		&require_existing(reserve_at(root.path(), repeat).unwrap()),
	);
	assert_eq!(outcome_at(root.path(), &first, None).unwrap(), None);
	assert_eq!(graph_snapshot(root.path(), &first), before);
	same_binding(
		&first,
		&lookup_id_at(
			root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.unwrap()
		.unwrap(),
	);
}

#[test]
fn global_key_history_grows_beyond_512_with_all_original_bindings_unchanged() {
	let root = fixture_root();
	let mut originals = Vec::new();
	for number in 2000..2000 + LEGACY_GLOBAL_KEYS as u64 + 29 {
		let mut binding = fixture_binding(root.path(), number);
		binding.owner = fixture_id(100_000 + number % 5);
		let binding = require_new(reserve_at(root.path(), binding).unwrap());
		originals.push((binding.clone(), graph_snapshot(root.path(), &binding)));
	}
	for (binding, before) in originals {
		assert_eq!(outcome_at(root.path(), &binding, None).unwrap(), None);
		same_binding(
			&binding,
			&require_existing(reserve_at(root.path(), binding.clone()).unwrap()),
		);
		assert_eq!(graph_snapshot(root.path(), &binding), before);
	}
	let mut fresh = fixture_binding(root.path(), 900_200);
	fresh.owner = fixture_id(200_000);
	require_new(reserve_at(root.path(), fresh).unwrap());
}

#[test]
fn mixed_v9_v10_slots_track_64_each_without_rejecting_new_work() {
	let owner = next_id().unwrap();
	let v9: Vec<_> = (0..64)
		.map(|_| super::super::request_async::Slot::take(&owner).unwrap())
		.collect();
	let v10: Vec<_> = (0..64).map(|_| Slot::take(&owner).unwrap()).collect();
	assert_eq!(registry().unwrap().reserved.get(&owner).copied(), Some(64));
	drop(v10);
	drop(v9);
	assert!(!registry().unwrap().reserved.contains_key(&owner));
}

#[test]
fn native_sdk_result_family_serializes_exactly_before_operation_metadata() {
	let mut original = CallToolResult::success(vec![rmcp::model::ContentBlock::text(
		"private-unit-result-marker-\n\t\"escaped\"",
	)]);
	for failed in [false, true] {
		original.is_error = Some(failed);
		let expected = serde_json::to_vec(&original).unwrap();
		let (kind, bytes) =
			original_payload(&Ok(CallToolResponse::Complete(original.clone()))).unwrap();
		assert_eq!(kind, NativePayloadKind::NativeResult);
		assert_eq!(bytes.as_slice(), expected.as_slice());
	}
}

#[test]
fn native_sdk_rpc_error_serializes_exact_original_error_data_without_wrapping() {
	let original = rmcp::ErrorData::invalid_params(
		"private-unit-rpc-error-marker",
		Some(json!({"private-detail":"error-data-marker","number":12345})),
	);
	let expected = serde_json::to_vec(&original).unwrap();
	let (kind, bytes) = original_payload(&Err(original)).unwrap();
	assert_eq!(kind, NativePayloadKind::NativeError);
	assert_eq!(bytes.as_slice(), expected.as_slice());
	let restored: rmcp::ErrorData = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(serde_json::to_vec(&restored).unwrap(), expected);
}

#[test]
fn exact_native_sdk_wire_bound_retains_one_mib_and_refuses_next_byte_without_truncation() {
	let empty = CallToolResult::success(vec![rmcp::model::ContentBlock::text("")]);
	let overhead = serde_json::to_vec(&empty).unwrap().len();
	let exact = CallToolResult::success(vec![rmcp::model::ContentBlock::text(
		"x".repeat(MAX_PAYLOAD_BYTES - overhead),
	)]);
	let (_, bytes) = original_payload(&Ok(CallToolResponse::Complete(exact))).unwrap();
	assert_eq!(bytes.len(), MAX_PAYLOAD_BYTES);
	let oversized = CallToolResult::success(vec![rmcp::model::ContentBlock::text(
		"x".repeat(MAX_PAYLOAD_BYTES - overhead + 1),
	)]);
	assert!(original_payload(&Ok(CallToolResponse::Complete(oversized))).is_err());
}

#[test]
fn immutable_outcome_requires_complete_identity_and_cannot_be_rewritten_by_late_cancel() {
	let root = fixture_root();
	let binding = require_new(reserve_at(root.path(), fixture_binding(root.path(), 70)).unwrap());
	assert_eq!(
		outcome_at(root.path(), &binding, Some("completed")).unwrap(),
		Some("completed".into())
	);
	assert_eq!(
		outcome_at(root.path(), &binding, Some("cancelled_future")).unwrap(),
		Some("completed".into())
	);
	assert_eq!(
		outcome_at(root.path(), &binding, None).unwrap(),
		Some("completed".into())
	);
	let path = root
		.path()
		.join(STORE_NAME)
		.join(".outcomes")
		.join(format!("{}.json", binding.request_id));
	let mut outcome: Outcome = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
	outcome.owner = fixture_id(0xdddd);
	fs::write(path, serde_json::to_vec(&outcome).unwrap()).unwrap();
	assert!(outcome_at(root.path(), &binding, None).is_err());
}

#[test]
fn private_policy_config_is_keyed_bounded_and_keeps_full_secret_context() {
	let first =
		ResultCryptoScope::from_verified_token(b"unit-policy-test-credential-24732948732948732")
			.unwrap();
	let second =
		ResultCryptoScope::from_verified_token(b"unit-other-policy-credential-739284739284732")
			.unwrap();
	let policy = json!({"ssh_target":"hidden-host","fixed_args":["low-entropy-secret"],
		"controller_workspace_roots":["/private/root"]});
	let binding = private_policy_binding_for(&first, &policy).unwrap();
	assert_ne!(
		binding,
		private_policy_binding_for(&second, &policy).unwrap()
	);
	let changed = json!({"ssh_target":"hidden-host","fixed_args":["other-secret"],
		"controller_workspace_roots":["/private/root"]});
	assert_ne!(
		binding,
		private_policy_binding_for(&first, &changed).unwrap()
	);
	let bytes = serde_json::to_vec(&policy).unwrap();
	assert_ne!(binding, digest(&bytes));
	let mut legacy = b"hepta-runtime/result-policy/v1\0".to_vec();
	legacy.extend_from_slice(&bytes);
	assert_ne!(binding, digest(&legacy));
	assert!(
		private_policy_binding_for(&first, &json!({"secret":"x".repeat(MAX_PAYLOAD_BYTES)}))
			.is_err()
	);
}

#[test]
fn metadata_snapshot_rejects_mutation_during_owned_fd_read() {
	for fault in 0..4 {
		let root = fixture_root();
		let dir = store(root.path()).unwrap();
		let path = root.path().join(STORE_NAME).join("fixture-snapshot.json");
		let original = br#"{"identity":"aaaaaaaa"}"#;
		let mut file = OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&path)
			.unwrap();
		file.write_all(original).unwrap();
		file.sync_all().unwrap();
		drop(file);
		let mut observed = false;
		let result: Result<serde_json::Value> =
			read_json_observed(&dir, "fixture-snapshot.json", |_| {
				observed = true;
				match fault {
					0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?,
					1 => {
						let mut writer = OpenOptions::new().write(true).open(&path)?;
						writer.write_all(br#"{"identity":"bbbbbbbb"}"#)?;
						writer.set_modified(UNIX_EPOCH + Duration::from_secs(100))?;
						writer.sync_all()?;
					}
					2 => {
						let mut writer = OpenOptions::new().append(true).open(&path)?;
						writer.write_all(b" ")?;
						writer.sync_all()?;
					}
					_ => fs::hard_link(&path, root.path().join("new-hardlink"))?,
				}
				Ok(())
			});
		assert!(observed);
		assert!(
			result.is_err(),
			"a changed private FD cannot authorize any lookup/reservation"
		);
	}
}

#[tokio::test]
async fn completed_original_payload_wins_simultaneous_late_cancellation() {
	let cancel = CancellationToken::new();
	cancel.cancel();
	let original = CallToolResult::success(vec![rmcp::model::ContentBlock::text(
		"unit-double-ready-original-payload",
	)]);
	let expected = serde_json::to_vec(&original).unwrap();
	let (result, state) = await_read_completion(
		std::future::ready(Ok::<_, ()>(Ok::<_, rmcp::ErrorData>(
			CallToolResponse::Complete(original),
		))),
		&cancel,
	)
	.await;
	assert_eq!(state, "completed");
	let (_, bytes) = original_payload(&result.unwrap()).unwrap();
	assert_eq!(bytes.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn pending_read_is_cancelled_and_timeout_is_unknown_without_fake_payload() {
	let cancel = CancellationToken::new();
	cancel.cancel();
	let (result, state) = await_read_completion(
		std::future::pending::<std::result::Result<(), ()>>(),
		&cancel,
	)
	.await;
	assert!(result.is_none());
	assert_eq!(state, "cancelled_future");
	let (result, state) = await_read_completion(
		std::future::ready(Err::<(), _>(())),
		&CancellationToken::new(),
	)
	.await;
	assert!(result.is_none());
	assert_eq!(state, "unknown");
}

#[test]
fn encrypted_maximum_payload_roundtrips_through_actual_private_immutable_disk_graph() {
	let root = fixture_root();
	let binding =
		require_new(reserve_at(root.path(), fixture_binding(root.path(), 987654)).unwrap());
	let crypto =
		ResultCryptoScope::from_verified_token(b"unit-native-payload-disk-token-48239482394823948")
			.unwrap();
	let trusted = crypto_binding(&binding, NativePayloadKind::NativeResult).unwrap();
	let original = vec![0xab; MAX_PAYLOAD_BYTES];
	let packet = crypto.seal(&trusted, &original).unwrap();
	assert_eq!(packet.len(), MAX_PACKET_BYTES);
	save_payload_at(root.path(), &binding, &packet).unwrap();
	let path = root
		.path()
		.join(STORE_NAME)
		.join(".payloads")
		.join(format!("{}.bin", binding.request_id));
	let metadata = fs::metadata(&path).unwrap();
	assert_eq!(metadata.len(), MAX_PACKET_BYTES as u64);
	assert_eq!(metadata.mode() & 0o7777, 0o600);
	assert_eq!(metadata.nlink(), 1);
	let stored = read_payload_at(root.path(), &binding).unwrap().unwrap();
	assert_eq!(stored, packet);
	let reconnect =
		ResultCryptoScope::from_verified_token(b"unit-native-payload-disk-token-48239482394823948")
			.unwrap();
	assert_eq!(
		reconnect.open(&trusted, &stored).unwrap().as_bytes(),
		original.as_slice()
	);
	assert!(save_payload_at(root.path(), &binding, &packet).is_err());
	assert_eq!(fs::read(&path).unwrap(), packet);
	let mut changed = packet;
	*changed.last_mut().unwrap() ^= 1;
	fs::write(&path, &changed).unwrap();
	let corrupted = read_payload_at(root.path(), &binding).unwrap().unwrap();
	assert!(crypto.open(&trusted, &corrupted).is_err());
}

#[test]
fn old_capacity_environment_never_refuses_or_hides_durable_key_history() {
	const OWNER_KEYS_ENV: &str = "HEPTA_ASYNC_RETENTION_OWNER_KEYS";
	const GLOBAL_KEYS_ENV: &str = "HEPTA_ASYNC_RETENTION_GLOBAL_KEYS";
	const CHILD: &str = "HEPTA_UNBOUNDED_JOURNAL_TEST_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let status = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", "mcp::runtime::operation_async::tests::old_capacity_environment_never_refuses_or_hides_durable_key_history", "--test-threads=1"])
			.env(CHILD, "1").env(OWNER_KEYS_ENV, "2").env(GLOBAL_KEYS_ENV, "3")
			.status().unwrap();
		assert!(status.success());
		return;
	}
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 3000)).unwrap());
	let before = graph_snapshot(root.path(), &first);
	for number in 3001..=3540 {
		require_new(reserve_at(root.path(), fixture_binding(root.path(), number)).unwrap());
	}
	same_binding(
		&first,
		&lookup_id_at(
			root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.unwrap()
		.unwrap(),
	);
	assert_eq!(graph_snapshot(root.path(), &first), before);
	let directory = store(root.path()).unwrap();
	assert_eq!(bindings(&directory).unwrap().len(), 541);
}

fn graph_snapshot(root: &Path, binding: &Binding) -> Vec<(u64, u64, u32, u64, Vec<u8>)> {
	use std::os::unix::fs::MetadataExt;
	let directory = root.join(STORE_NAME);
	[
		directory.join(format!("{}.json", binding.key_hash)),
		directory
			.join(".occupied")
			.join(format!("{}.json", binding.key_hash)),
		directory
			.join(".intents")
			.join(format!("{}.json", binding.request_id)),
	]
	.into_iter()
	.map(|path| {
		let metadata = path.symlink_metadata().unwrap();
		(
			metadata.dev(),
			metadata.ino(),
			metadata.mode(),
			metadata.nlink(),
			fs::read(path).unwrap(),
		)
	})
	.collect()
}

#[test]
fn concurrent_64_independent_keys_are_durable_and_old_unknown_is_never_reissued() {
	let root = fixture_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(root.path(), 5000)).unwrap());
	let before = graph_snapshot(root.path(), &first);
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(64));
	let inputs: Vec<_> = (5001..5065)
		.map(|number| fixture_binding(root.path(), number))
		.collect();
	let workers: Vec<_> = inputs
		.into_iter()
		.map(|binding| {
			let path = root.path().to_path_buf();
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				barrier.wait();
				require_new(reserve_at(&path, binding).unwrap())
			})
		})
		.collect();
	for worker in workers {
		let binding = worker.join().unwrap();
		same_binding(
			&binding,
			&lookup_id_at(
				root.path(),
				&binding.owner,
				&binding.request_id,
				&binding.policy_binding,
			)
			.unwrap()
			.unwrap(),
		);
		assert_eq!(outcome_at(root.path(), &binding, None).unwrap(), None);
	}
	assert_eq!(graph_snapshot(root.path(), &first), before);
	same_binding(
		&first,
		&require_existing(reserve_at(root.path(), first.clone()).unwrap()),
	);
	assert_eq!(outcome_at(root.path(), &first, None).unwrap(), None);
}

#[test]
fn validation_cache_eviction_preserves_old_unknown_identity_and_accepts_new_keys() {
	let first_root = fixture_root();
	let root = &first_root;
	let first =
		require_new(reserve_at(first_root.path(), fixture_binding(root.path(), 7000)).unwrap());
	let before = graph_snapshot(first_root.path(), &first);
	let mut roots = Vec::new();
	for _ in 0..20 {
		let root = fixture_root();
		require_new(reserve_at(root.path(), fixture_binding(root.path(), 7000)).unwrap());
		roots.push(root);
	}
	same_binding(
		&first,
		&lookup_id_at(
			first_root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.unwrap()
		.unwrap(),
	);
	same_binding(
		&first,
		&require_existing(reserve_at(first_root.path(), first.clone()).unwrap()),
	);
	require_new(reserve_at(first_root.path(), fixture_binding(first_root.path(), 7001)).unwrap());
	assert_eq!(graph_snapshot(first_root.path(), &first), before);
	assert_eq!(outcome_at(first_root.path(), &first, None).unwrap(), None);
}
