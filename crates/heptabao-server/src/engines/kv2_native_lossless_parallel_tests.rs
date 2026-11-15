use super::*;
use crate::request_deadline::{self, RequestDeadlineScope};
use crate::v6_native_custody::OriginalDeadline;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "",
        mount: "secret/",
        incarnation: 17,
    }
}
fn fixture() -> CodecResult<(
    Arc<AddressKey>,
    NativeCellGraph,
    GraphObjects,
    NativeReadView,
)> {
    let data = lossless::decode_lossless_json(
        br#"{"integer":9007199254740993,"decimal":0.123456789012345678901234567890}"#,
    )
    .map_err(|_| RecordError::Invalid)?;
    let mut owner = Kv2::default();
    owner
        .handle("POST", "config", &json!({"max_versions":10}), 100)
        .map_err(|_| RecordError::Invalid)?;
    for version in 1..=4 {
        owner
            .handle(
                "POST",
                "data/history",
                &json!({"data":{
                    "exact":data,"version":version,"large":"p".repeat(2 * 1024 * 1024)
                }}),
                100 + version,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    owner
        .handle("POST", "destroy/history", &json!({"versions":[2]}), 110)
        .map_err(|_| RecordError::Invalid)?;
    owner
        .handle("POST", "delete/history", &json!({"versions":[1]}), 111)
        .map_err(|_| RecordError::Invalid)?;
    owner.lossless_format = Some(1);
    let key = AddressKey::from_bytes([191; 32]);
    let graph = NativeCellGraph::encode_paged(&owner, &key, scope(), &|| Ok(()))?;
    let mut source = GraphObjects::default();
    graph.visit_objects(
        |object| {
            source.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        },
        &|| Ok(()),
    )?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    Ok((key, graph, source, view))
}
fn request() -> CodecResult<(RequestDeadlineScope, OriginalDeadline)> {
    let scope = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(15));
    let deadline = OriginalDeadline::capture().map_err(|_| RecordError::Invalid)?;
    Ok((scope, deadline))
}

#[test]
fn lossless_parallel_export_keeps_original_decoder_exact_numbers_history_and_root()
-> CodecResult<()> {
    let (key, graph, source, view) = fixture()?;
    let mut serial = Zeroizing::new(Vec::new());
    view.write_lossless_export(&mut *serial, &source, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let expected_reads = graph
        .0
        .paged
        .as_ref()
        .ok_or(RecordError::Missing)?
        .descriptors
        .values()
        .flat_map(BTreeMap::values)
        .map(|descriptor| descriptor.blocks.len())
        .sum::<usize>();
    let (_scope, deadline) = request()?;
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let deliveries = AtomicUsize::new(0);
    let mut parallel = Zeroizing::new(Vec::new());
    view.write_lossless_export_parallel(
        &mut *parallel,
        &|reference| {
            if request_deadline::current() != Some(deadline.instant()) {
                return Err(RecordError::Invalid);
            }
            calls.fetch_add(1, Ordering::AcqRel);
            source.read_object(reference)
        },
        &|| {
            deliveries.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
        &|| deadline.check().map_err(|_| RecordError::Invalid),
        deadline,
        &stop,
    )
    .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(parallel.as_slice(), serial.as_slice());
    assert_eq!(calls.load(Ordering::Acquire), expected_reads);
    assert_eq!(deliveries.load(Ordering::Acquire), expected_reads);
    assert!(!stop.load(Ordering::Acquire));
    check_export_syntax(&mut parallel.as_slice(), parallel.len() as u64, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let checked = lossless::native_large::NativeLargeBundle::checked(parallel, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let restored =
        Kv2::from_native_large_import(&checked, &|| Ok(())).map_err(|_| RecordError::Corrupt)?;
    let restored = NativeCellGraph::encode_paged(&restored, &key, scope(), &|| Ok(()))?;
    assert_eq!(graph.root(), restored.root());
    Ok(())
}

#[test]
fn lossless_parallel_export_rejects_corruption_and_revocation_before_delivery() -> CodecResult<()> {
    let (_, _, source, view) = fixture()?;
    let (_scope, deadline) = request()?;
    for revoke in [false, true] {
        let stop = AtomicBool::new(false);
        let revoked = AtomicBool::new(false);
        let mut private_output = Zeroizing::new(Vec::new());
        let result = view.write_lossless_export_parallel(
            &mut *private_output,
            &|reference| {
                let mut bytes = source.read_object(reference)?;
                if revoke {
                    revoked.store(true, Ordering::Release);
                } else {
                    *bytes.first_mut().ok_or(RecordError::Corrupt)? ^= 1;
                }
                Ok(bytes)
            },
            &|| {
                if revoked.load(Ordering::Acquire) {
                    Err(RecordError::Invalid)
                } else {
                    Ok(())
                }
            },
            &|| deadline.check().map_err(|_| RecordError::Invalid),
            deadline,
            &stop,
        );
        assert!(result.is_err());
        assert!(stop.load(Ordering::Acquire));
    }
    Ok(())
}

#[test]
fn lossless_parallel_export_writer_failure_stops_and_preserves_sparse_rejection() -> CodecResult<()>
{
    let (_, _, source, mut view) = fixture()?;
    let (_scope, deadline) = request()?;
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic private output failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let stop = AtomicBool::new(false);
    assert!(
        view.write_lossless_export_parallel(
            &mut FailingWriter,
            &|reference| source.read_object(reference),
            &|| Ok(()),
            &|| Ok(()),
            deadline,
            &stop,
        )
        .is_err()
    );
    assert!(stop.load(Ordering::Acquire));
    view.owner
        .entries
        .get_mut("history")
        .ok_or(RecordError::Missing)?
        .versions
        .remove(&3);
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let mut output = Zeroizing::new(Vec::new());
    let result = view.write_lossless_export_parallel(
        &mut *output,
        &|reference| {
            calls.fetch_add(1, Ordering::AcqRel);
            source.read_object(reference)
        },
        &|| Ok(()),
        &|| Ok(()),
        deadline,
        &stop,
    );
    assert!(result.is_err());
    assert!(output.is_empty());
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(stop.load(Ordering::Acquire));
    Ok(())
}
