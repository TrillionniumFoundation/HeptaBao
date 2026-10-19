//! Real native Service imports, physical file/barrier publication, and cold
//! recovery. Test payloads and credentials are isolated and synthetic.
use super::*;
use crate::service::tests::{Root, bootstrap};
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const IMPORT: &str = "sys/migration/openbao/kv2";
const BULK: usize = 112;

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let response = service.handle(method, path, "", token, body);
    if response.status >= 500 {
        eprintln!("native KV2 graph import: path={path} status={}", response.status);
    }
    response
}

fn fixture_bundle(bulk: bool) -> TestResult<Value> {
    let data = crate::engines::decode_lossless_json(
        br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"},"payload":"kept"}"#
    )?;
    let mut bundle = json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{
            "item":{
                "created_time":"1970-01-01T00:01:30.000000113Z",
                "updated_time":"1970-01-01T00:01:35.000000113Z",
                "current_version":5,"current_metadata_version":7,"oldest_version":3,
                "max_versions":3,"cas_required":true,"metadata_cas_required":true,
                "delete_version_after":"0s","custom_metadata":{"owner":"exact-import"},
                "versions":{
                    "3":{"created_time":"1970-01-01T00:01:33.000000113Z","deletion_time":"","destroyed":true,"data":null},
                    "4":{"created_time":"1970-01-01T00:01:34.000000113Z","deletion_time":"1970-01-01T00:01:36.000000113Z","destroyed":false,"data":{"old":true}},
                    "5":{"created_time":"1970-01-01T00:01:35.000000113Z","deletion_time":"","destroyed":false,"data":data}
                }
            },
            "scheduled":{
                "created_time":"1970-01-01T00:01:35.000000113Z","updated_time":"1970-01-01T00:01:35.000000113Z",
                "current_version":1,"current_metadata_version":2,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":true,
                "delete_version_after":"7200.5s","custom_metadata":null,
                "versions":{"1":{"created_time":"1970-01-01T00:01:35.000000113Z",
                    "deletion_time":"1970-01-01T00:03:20.5Z","source_deletion_time":"1970-01-01T02:01:35.500000113Z",
                    "destroyed":false,"data":{"scheduled":true}}}
            },
            "metadata-only":{
                "created_time":"1970-01-01T00:01:35.000000113Z","updated_time":"1970-01-01T00:01:35.000000113Z",
                "current_version":0,"current_metadata_version":1,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":true,
                "delete_version_after":"0s","custom_metadata":{},"versions":{}
            }
        }
    });
    if bulk {
        let entries = bundle["entries"].as_object_mut().ok_or("entries")?;
        for index in 0..BULK {
            entries.insert(format!("bulk/{index:03}"),json!({
                "created_time":"1970-01-01T00:01:35.000000113Z","updated_time":"1970-01-01T00:01:35.000000113Z",
                "current_version":1,"current_metadata_version":0,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":false,
                "delete_version_after":"0s","custom_metadata":null,
                "versions":{"1":{"created_time":"1970-01-01T00:01:35.000000113Z","deletion_time":"",
                    "destroyed":false,"data":{"index":index,"padding":"p".repeat(4096)}}}
            }));
        }
    }
    Ok(bundle)
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, token) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(30),
        );
        bootstrap(&mut service)?
    };
    // Real unrelated persisted state forces a V5 source while secret/ remains
    // pristine. Its contents must survive every successful and failed import.
    assert_eq!(call(&mut service,"POST","sys/mounts/keep",&token,
        json!({"type":"kv","options":{"version":"2"}})).status,204);
    assert_eq!(call(&mut service,"POST","keep/data/sentinel",&token,
        json!({"data":{"kept":"unrelated-root"}})).status,200);
    Ok((files,service,Zeroizing::new(key),Zeroizing::new(token)))
}

fn activate(service: &mut Service, token: &str) {
    assert_eq!(call(service,"POST","sys/internal/native-v6/activate",token,json!({})).status,204);
    assert!(service.native_root.as_ref().is_some_and(|root| root.reader_floor.native_kv2_format==2));
    assert!(service.record_root.is_none());
}

fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    assert_eq!(call(&mut service,"POST","sys/unseal","",json!({"key":key})).status,200);
    assert!(!service.recovery_required);
    Ok(service)
}

fn imported(service: &mut Service, token: &str, bulk: bool) -> TestResult {
    assert_eq!(call(service,"POST",IMPORT,token,
        json!({"mount":"secret","bundle":fixture_bundle(bulk)?})).status,204);
    Ok(())
}

fn selected_graph(service: &Service) -> TestResult<crate::state_record_root_v6::Kv2GraphRef> {
    Ok(service.native_root.as_ref().ok_or("native root")?.kv2.iter()
        .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount=="secret/")
        .ok_or("secret graph")?.clone())
}

fn same_graph(
    left: &crate::state_record_root_v6::Kv2GraphRef,
    right: &crate::state_record_root_v6::Kv2GraphRef,
) -> bool {
    left.scope == right.scope && left.graph_format == right.graph_format
        && left.root == right.root && left.logical_payload_bytes == right.logical_payload_bytes
}

fn sentinel(service: &mut Service, token: &str) {
    let response=call(service,"GET","keep/data/sentinel",token,json!({}));
    assert_eq!(response.status,200);
    assert_eq!(response.body["data"]["data"],json!({"kept":"unrelated-root"}));
}

fn observed(service: &mut Service, token: &str) -> TestResult<Vec<(u16,Value)>> {
    let mut output=Vec::new();
    for (path,body) in [
        ("secret/config",json!({})),("secret/metadata/item",json!({})),
        ("secret/metadata/scheduled",json!({})),("secret/metadata/metadata-only",json!({})),
        ("secret/data/item",json!({"version":3})),("secret/data/item",json!({"version":4})),
        ("secret/data/item",json!({"version":5})),("secret/data/scheduled",json!({"version":1})),
        ("secret/subkeys/item",json!({"version":5})),
    ] {
        let mut response=call(service,"GET",path,token,body);
        assert!(matches!(response.status,200|404));
        output.push((response.status,response.body.take()));
    }
    Ok(output)
}

fn assert_imported(service: &mut Service, token: &str, bulk: bool) -> TestResult {
    sentinel(service,token);
    let metadata=call(service,"GET","secret/metadata/item",token,json!({}));
    assert_eq!(metadata.status,200);
    assert_eq!(metadata.body["data"]["current_version"],5);
    assert_eq!(metadata.body["data"]["oldest_version"],3);
    assert_eq!(metadata.body["data"]["current_metadata_version"],7);
    assert_eq!(metadata.body["data"]["created_time"],"1970-01-01T00:01:30.000000113Z");
    assert_eq!(metadata.body["data"]["updated_time"],"1970-01-01T00:01:35.000000113Z");
    assert_eq!(metadata.body["data"]["custom_metadata"],json!({"owner":"exact-import"}));
    assert_eq!(metadata.body["data"]["versions"]["3"]["destroyed"],true);
    for number in [3,4] {
        assert_eq!(call(service,"GET","secret/data/item",token,json!({"version":number})).status,404);
    }
    let current=call(service,"GET","secret/data/item",token,json!({"version":5}));
    assert_eq!(current.status,200);
    assert_eq!(current.body["data"]["data"],fixture_bundle(false)?["entries"]["item"]["versions"]["5"]["data"]);
    let scope=selected_graph(service)?.scope;
    assert_eq!(service.state.as_ref().ok_or("state")?.engines.native_paged_view(&scope)
        .ok_or("native view")?.counts(),(if bulk {BULK+3} else {3},if bulk {BULK+4} else {4},if bulk {BULK+3} else {3}));
    assert!(crate::secret_serde::to_vec(&*service.state.as_ref().ok_or("state")?.engines,
        crate::MAX_APPLICATION_STATE_BYTES).is_err());
    if bulk {
        for index in [0,BULK/2,BULK-1] {
            let response=call(service,"GET",&format!("secret/data/bulk/{index:03}"),token,json!({}));
            assert_eq!(response.status,200);
            assert_eq!(response.body["data"]["data"]["index"],index);
            assert_eq!(response.body["data"]["metadata"]["version"],1);
        }
    }
    Ok(())
}

#[test]
fn native_kv2_graph_import_service_matches_legacy_history_and_cold_cas() -> TestResult {
    let (_reference_files,mut reference,_reference_key,reference_token)=initialized()?;
    imported(&mut reference,&reference_token,false)?;
    let expected=observed(&mut reference,&reference_token)?;
    let (files,mut native,key,token)=initialized()?;
    activate(&mut native,&token);
    {
        let _scope=crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now()+Duration::from_secs(30));
        let mut detached=native.state.as_ref().ok_or("state")?.clone();
        let parent=native.native_root.as_ref().ok_or("root")?.kv2_parent_key().map_err(|_| "root key")?;
        let bytes=crate::secret_serde::to_vec(&fixture_bundle(false)?,
            crate::MAX_APPLICATION_STATE_BYTES).map_err(|_| "encoding")?;
        let objects=detached.engines.stage_openbao_kv2_native_import(
            "", "secret", &bytes, &parent, &|| Ok(()),
        )?;
        detached.schema=detached.writer_schema();
        drop(objects);
        // The metadata-only candidate cannot fabricate its absent imported
        // payload closure by falling back to the old pristine mount.
        assert!(native.prepare_native_live_root_checked(&detached,&mut |_| Ok(())).is_err());
    }
    imported(&mut native,&token,false)?;
    assert_eq!(observed(&mut native,&token)?,expected);
    assert_imported(&mut native,&token,false)?;
    let graph=selected_graph(&native)?;
    drop(native);
    let mut native=reopen(&files,&key)?;
    assert!(same_graph(&selected_graph(&native)?, &graph));
    assert_eq!(observed(&mut native,&token)?,expected);
    assert_eq!(call(&mut native,"POST","secret/data/item",&token,
        json!({"options":{"cas":4},"data":{"rejected":true}})).status,400);
    assert_eq!(call(&mut native,"POST","secret/metadata/item",&token,
        json!({"metadata_cas":6,"custom_metadata":{"rejected":"true"}})).status,400);
    assert!(same_graph(&selected_graph(&native)?, &graph));
    assert_eq!(call(&mut native,"POST","secret/data/item",&token,
        json!({"options":{"cas":5},"data":{"after":"native-import"}})).status,200);
    assert_eq!(call(&mut native,"GET","secret/metadata/item",&token,json!({}))
        .body["data"]["current_version"],6);
    Ok(())
}

#[test]
fn native_kv2_graph_import_service_rejects_unauthorized_malformed_and_replayed_import() -> TestResult {
    let (_files,mut native,_key,token)=initialized()?;
    assert_eq!(call(&mut native,"PUT","sys/policies/acl/import-no-sudo",&token,
        json!({"policy":r#"path "sys/migration/openbao/kv2" { capabilities=["update"] }"#})).status,204);
    let issued=call(&mut native,"POST","auth/token/create",&token,
        json!({"policies":["import-no-sudo"],"no_default_policy":true,"ttl":"1h"}));
    assert_eq!(issued.status,200);
    let actor=Zeroizing::new(issued.body["auth"]["client_token"].as_str()
        .ok_or("fresh actual-clock limited actor")?.to_owned());
    activate(&mut native,&token);
    let graph=selected_graph(&native)?;
    let body=json!({"mount":"secret","bundle":fixture_bundle(false)?});
    assert_eq!(call(&mut native,"POST",IMPORT,&actor,body.clone()).status,403);
    assert_eq!(call(&mut native,"POST",IMPORT,"",body.clone()).status,403);
    let mut bad=body.clone();
    bad["bundle"]["entries"]["scheduled"]["versions"]["1"]["destroyed"]=json!(true);
    assert_eq!(call(&mut native,"POST",IMPORT,&token,bad).status,400);
    let mut bad=body.clone();
    bad["mount"]=json!("secret//");
    assert_eq!(call(&mut native,"POST",IMPORT,&token,bad).status,400);
    assert_eq!(call(&mut native,"GET",IMPORT,&token,body.clone()).status,405);
    assert!(same_graph(&selected_graph(&native)?, &graph));
    sentinel(&mut native,&token);
    imported(&mut native,&token,false)?;
    let committed=selected_graph(&native)?;
    assert_eq!(call(&mut native,"POST",IMPORT,&token,body).status,409);
    assert!(same_graph(&selected_graph(&native)?, &committed));
    let mut empty=fixture_bundle(false)?;
    empty["entries"]=json!({});
    empty["config"]=json!({"max_versions":0,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"});
    assert_eq!(call(&mut native,"POST",IMPORT,&token,json!({"mount":"keep","bundle":empty})).status,409);
    sentinel(&mut native,&token);
    Ok(())
}

// Inject only the named real import Apply acknowledgement after the backend
// has appended and fsynced its authenticated frame. Physical ciphertext,
// actual journals, root selection and normal cold Service recovery are real.
struct LoseImportApplyAck {
    inner: heptabao_durable_service::FileBackend,
    barrier: AeadBarrier,
    fired: Arc<AtomicBool>,
    suffix: &'static str,
}
impl LoseImportApplyAck {
    fn selected(&self, frame: &[u8]) -> Result<bool, heptabao_durable_service::BackendError> {
        use heptabao_durable_service::BackendError;
        let invalid = || BackendError::OutcomeUnknown;
        let word = |offset: usize| -> Result<usize, BackendError> {
            let bytes = frame.get(offset..offset + 4).ok_or_else(invalid)?;
            Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?) as usize)
        };
        if frame.len().checked_sub(4) != Some(word(0)?) {
            return Err(invalid());
        }
        let end = 16usize.checked_add(word(12)?).ok_or_else(invalid)?;
        if end.checked_add(32) != Some(frame.len()) {
            return Err(invalid());
        }
        let mut context = b"heptabao.durable-service.journal.v2".to_vec();
        context.extend_from_slice(frame.get(4..12).ok_or_else(invalid)?);
        let plain = Zeroizing::new(
            heptabao_durable_service::Barrier::open(
                &self.barrier,
                &context,
                frame.get(16..end).ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?,
        );
        if plain.first() != Some(&5) {
            return Ok(false);
        }
        let mut offset = 1usize;
        for field_index in 0..3 {
            let length_end = offset.checked_add(4).ok_or_else(invalid)?;
            let length = u32::from_le_bytes(
                plain
                    .get(offset..length_end)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize;
            let end = length_end.checked_add(length).ok_or_else(invalid)?;
            let value = std::str::from_utf8(plain.get(length_end..end).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if field_index == 2 {
                return Ok(
                    value.starts_with("native6-kv2-import-") && value.ends_with(self.suffix)
                );
            }
            offset = end;
        }
        Ok(false)
    }
}
impl heptabao_durable_service::DurableBackend for LoseImportApplyAck {
    fn verify(&self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.verify()
    }
    fn verify_live_ownership(&mut self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.verify_live_ownership()
    }
    fn immutable_blob_profile(
        &self,
    ) -> Result<
        heptabao_durable_service::ImmutableBlobProfile,
        heptabao_durable_service::BackendError,
    > {
        self.inner.immutable_blob_profile()
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: heptabao_durable_service::BlobLocator,
        ciphertext: &[u8],
        gate: &mut dyn FnMut() -> Result<(), heptabao_durable_service::BackendError>,
    ) -> Result<heptabao_durable_service::ImmutableBlobStage, heptabao_durable_service::BackendError>
    {
        self.inner
            .stage_immutable_ciphertext_checked(locator, ciphertext, gate)
    }
    fn pin_immutable_ciphertext(
        &self,
        locator: heptabao_durable_service::BlobLocator,
        exact_len: usize,
    ) -> Result<
        heptabao_durable_service::ImmutableBlobReadPin,
        heptabao_durable_service::BackendError,
    > {
        self.inner.pin_immutable_ciphertext(locator, exact_len)
    }
    fn load(
        &mut self,
    ) -> Result<heptabao_durable_service::BackendBundle, heptabao_durable_service::BackendError>
    {
        self.inner.load()
    }
    fn initialize_empty(
        &mut self,
        initial: &heptabao_durable_service::BackendBundle,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.initialize_empty(initial)
    }
    fn append_journal(
        &mut self,
        expected_len: usize,
        frame: &[u8],
    ) -> Result<usize, heptabao_durable_service::BackendError> {
        let length = self.inner.append_journal(expected_len, frame)?;
        if self.selected(frame)? && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(heptabao_durable_service::BackendError::OutcomeUnknown);
        }
        Ok(length)
    }
    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.truncate_journal(expected_len, new_len)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &heptabao_durable_service::BackendBundle,
        replacement: &heptabao_durable_service::BackendBundle,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.publish_checkpoint(expected, replacement)
    }
    fn close(self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.close()
    }
}


fn lose_ack(service: &mut Service, suffix: &'static str) -> TestResult<Arc<AtomicBool>> {
    let barrier=Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier")?);
    drop(service.durable.take().ok_or("durable")?);
    let fired=Arc::new(AtomicBool::new(false));
    let backend=LoseImportApplyAck {
        inner:heptabao_durable_service::FileBackend::open(&service.data_dir)?,
        barrier:AeadBarrier::new(*barrier)?,
        fired:Arc::clone(&fired),suffix,
    };
    service.durable=Some(DurableService::reopen_with_backend(
        Box::new(backend) as Box<dyn heptabao_durable_service::DurableBackend>,
        AeadBarrier::new(*barrier)?,MAX_OPERATIONS,
    )?);
    Ok(fired)
}

#[test]
fn native_kv2_graph_import_service_locator_ack_loss_keeps_old_root_then_retries() -> TestResult {
    let (files,mut native,key,token)=initialized()?;
    activate(&mut native,&token);
    let old=selected_graph(&native)?;
    let fired=lose_ack(&mut native,"-locators-0")?;
    let response=call(&mut native,"POST",IMPORT,&token,
        json!({"mount":"secret","bundle":fixture_bundle(true)?}));
    assert_eq!(response.status,503);
    assert!(fired.load(Ordering::SeqCst),"fixture must exceed one real 96-object atomic Apply");
    assert!(native.recovery_required);
    assert_eq!(call(&mut native,"GET","secret/data/item",&token,json!({})).status,503);
    drop(native);
    let mut native=reopen(&files,&key)?;
    assert!(same_graph(&selected_graph(&native)?, &old));
    assert_eq!(call(&mut native,"GET","secret/metadata/item",&token,json!({})).status,404);
    sentinel(&mut native,&token);
    imported(&mut native,&token,true)?;
    assert_imported(&mut native,&token,true)?;
    drop(native);
    let mut native=reopen(&files,&key)?;
    assert_imported(&mut native,&token,true)?;
    Ok(())
}

#[test]
fn native_kv2_graph_import_service_root_ack_loss_cold_selects_complete_import_once() -> TestResult {
    let (files,mut native,key,token)=initialized()?;
    activate(&mut native,&token);
    let old=selected_graph(&native)?;
    let fired=lose_ack(&mut native,"-root")?;
    let response=call(&mut native,"POST",IMPORT,&token,
        json!({"mount":"secret","bundle":fixture_bundle(true)?}));
    assert_eq!(response.status,503);
    assert!(fired.load(Ordering::SeqCst));
    assert!(native.recovery_required);
    drop(native);
    let mut native=reopen(&files,&key)?;
    assert!(!same_graph(&selected_graph(&native)?, &old));
    assert_imported(&mut native,&token,true)?;
    let graph=selected_graph(&native)?;
    assert_eq!(call(&mut native,"POST",IMPORT,&token,
        json!({"mount":"secret","bundle":fixture_bundle(true)?})).status,409);
    assert!(same_graph(&selected_graph(&native)?, &graph));
    assert_imported(&mut native,&token,true)?;
    Ok(())
}

fn snapshot_request(service:&mut Service,token:&str,method:&str)
    -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method,"sys/storage/raft/snapshot","",token,json!({})),
        Instant::now()+Duration::from_secs(30),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan))=>Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response))=>
            Err(format!("snapshot admission status={}",response.status).into()),
        NativeSnapshotAdmission::Redirect(_)=>Err("unexpected isolated redirect".into()),
    }
}

#[test]
fn native_kv2_graph_import_service_snapshot_restore_and_cold_recovery_preserve_history() -> TestResult {
    let (files,mut native,key,token)=initialized()?;
    activate(&mut native,&token);
    imported(&mut native,&token,true)?;
    let expected=observed(&mut native,&token)?;
    let mut request=snapshot_request(&mut native,&token,"GET")?;
    let (result,file)=request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(native.finish_external_request(*request,result).status,200);
    let mut archive=Zeroizing::new(Vec::new());
    file.ok_or("snapshot file")?.read_to_end(&mut archive)?;
    assert_eq!(call(&mut native,"POST","secret/data/item",&token,
        json!({"options":{"cas":5},"data":{"discarded":"after-export"}})).status,200);
    let mut request=snapshot_request(&mut native,&token,"POST")?;
    let (result,file)=request.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    assert_eq!(native.finish_external_request(*request,result).status,200);
    assert_eq!(observed(&mut native,&token)?,expected);
    assert_imported(&mut native,&token,true)?;
    drop(native);
    let mut native=reopen(&files,&key)?;
    assert_eq!(observed(&mut native,&token)?,expected);
    assert_imported(&mut native,&token,true)?;
    Ok(())
}
