//! Explicit native-only migration profile. The ordinary 16-MiB JSON decoder
//! and legacy import remain unchanged. This proof conveys syntax, not custody.
use super::*;
use crate::state_records::RecordError;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::Zeroizing;

pub(crate) const PATH: &str = "sys/migration/openbao/kv2/native-large";
pub(crate) const MEDIA_TYPE: &str = "application/vnd.heptabao.kv2-lossless+json";
pub(crate) const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
// The aggregate native bundle can contain tens of thousands of small paths.
// This syntax-only budget is shared by import and export; each secret value
// still goes through the unchanged ordinary lossless decoder afterward.
const MAX_NODES: usize = 4_194_304;
const MAX_DEPTH: usize = 128;

type CheckResult = std::result::Result<(), RecordError>;

/// Only this strict profile can construct the large input. No raw bytes may
/// select a decoder budget or bypass the Service's pre-body admission.
pub(crate) struct NativeLargeBundle(Zeroizing<Vec<u8>>);
impl NativeLargeBundle {
    pub(crate) fn checked(
        bytes: Zeroizing<Vec<u8>>,
        check: &impl Fn() -> CheckResult,
    ) -> Result<Self> {
        let rejected = || bad("native-large KV2 profile rejected");
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(rejected());
        }
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let diagnostic_strict =
            crate::engines::kv2_native_large::diagnostic::Span::new("strict_syntax");
        let mut budget = Budget { nodes: 0, check };
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        let validated = Strict {
            budget: &mut budget,
            depth: 0,
        }
        .deserialize(&mut decoder);
        #[cfg(feature = "private-ha-forward-diagnostic")]
        diagnostic::metric("strict_nodes", budget.nodes);
        validated.map_err(|_| rejected())?;
        decoder.end().map_err(|_| rejected())?;
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        drop(diagnostic_strict);
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let _diagnostic_shape =
            crate::engines::kv2_native_large::diagnostic::Span::new("closed_schema_preflight");
        // The outer closed schema is small metadata with borrowed raw payloads.
        // A single value still uses the ordinary lossless JSON decoder below.
        let input: Import<'_> = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        if input.schema != IMPORT_SCHEMA
            || !ImportProfile::NativeLarge.counts_fit(input.entries.len(), 0)
        {
            return Err(rejected());
        }
        let mut versions = 0_usize;
        for entry in input.entries.values() {
            check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
            versions = versions
                .checked_add(entry.versions.len())
                .ok_or_else(rejected)?;
            if !ImportProfile::NativeLarge.counts_fit(input.entries.len(), versions)
                || entry.versions.len() > MAX_RETAINED_VERSIONS as usize
                || entry
                    .versions
                    .values()
                    .any(|version| version.data.get().len() > MAX_RECORD_BYTES)
            {
                return Err(rejected());
            }
        }
        #[cfg(feature = "private-ha-forward-diagnostic")]
        {
            diagnostic::metric("schema_paths", input.entries.len());
            diagnostic::metric("schema_versions", versions);
        }
        drop(input);
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        Ok(Self(bytes))
    }
}

// Validate an already bounded private export spool with this exact import
// profile, without materializing another complete plaintext bundle. The caller
// still owns its source, deadline, file bound and eventual delivery authority.
pub(crate) fn check_export_syntax(
    reader: &mut impl std::io::Read,
    length: u64,
    check: &impl Fn() -> CheckResult,
) -> Result<()> {
    check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
    if length == 0 || length > MAX_BUNDLE_BYTES as u64 {
        return Err(error(413, "native-large KV2 export byte bound exceeded"));
    }
    let mut budget = Budget { nodes: 0, check };
    let buffered = ExportSyntaxReader {
        reader,
        buffer: Zeroizing::new([0; 64 * 1024]),
        offset: 0,
        filled: 0,
    };
    let mut bounded = std::io::Read::take(buffered, length.saturating_add(1));
    let mut decoder = serde_json::Deserializer::from_reader(&mut bounded);
    Strict {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| error(413, "native-large KV2 export token profile rejected"))?;
    decoder
        .end()
        .map_err(|_| bad("native-large KV2 export syntax rejected"))?;
    if bounded.limit() != 1 {
        return Err(bad("native-large KV2 export length changed"));
    }
    check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))
}

// serde_json's stream decoder asks for individual bytes. Read real storage in
// bounded blocks while ensuring its plaintext buffer is erased on every exit.
struct ExportSyntaxReader<'a, R> {
    reader: &'a mut R,
    buffer: Zeroizing<[u8; 64 * 1024]>,
    offset: usize,
    filled: usize,
}
impl<R: std::io::Read> std::io::Read for ExportSyntaxReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.filled {
            self.filled = self.reader.read(&mut *self.buffer)?;
            self.offset = 0;
        }
        let count = output.len().min(self.filled - self.offset);
        output[..count].copy_from_slice(&self.buffer[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

impl Kv2 {
    pub(in crate::engines) fn from_native_large_import(
        input: &NativeLargeBundle,
        check: &impl Fn() -> CheckResult,
    ) -> Result<Self> {
        Self::from_validated_lossless_import_json(&input.0, ImportProfile::NativeLarge, &|| {
            check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))
        })
    }
}

// A validation-only token walk catches duplicate keys throughout the raw
// bundle without materializing a 64-MiB generic Value or relaxing domain JSON.
// Arbitrary precision numbers are only validated here; each actual payload is
// decoded by the original token-preserving domain decoder during projection.
struct Budget<'a> {
    nodes: usize,
    check: &'a dyn Fn() -> CheckResult,
}
struct Strict<'a, 'b> {
    budget: &'a mut Budget<'b>,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Strict<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        (self.budget.check)().map_err(serde::de::Error::custom)?;
        if self.depth > MAX_DEPTH || self.budget.nodes >= MAX_NODES {
            return Err(serde::de::Error::custom(
                "native-large JSON structural bound",
            ));
        }
        self.budget.nodes += 1;
        decoder.deserialize_any(self)
    }
}
struct Keys(BTreeSet<String>);
impl Drop for Keys {
    fn drop(&mut self) {
        for mut key in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}
impl<'de> Visitor<'de> for Strict<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded native-large JSON token")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, mut text: String) -> std::result::Result<(), E> {
        text.zeroize();
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<(), A::Error> {
        while sequence
            .next_element_seed(Strict {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut keys = Keys(BTreeSet::new());
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if !keys.0.insert(key.to_string()) {
                return Err(serde::de::Error::custom("duplicate native-large JSON key"));
            }
            map.next_value_seed(Strict {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "kv_lossless_native_large_tests.rs"]
mod tests;

// This observation exists only in the existing private diagnostic feature.
// It never supplies a clock, auth result, graph, durable receipt or outcome.
#[cfg(feature = "private-ha-forward-diagnostic")]
pub(crate) mod diagnostic {
    use std::cell::Cell;
    use std::io::Write as _;
    use std::marker::PhantomData;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    #[derive(Clone, Copy)]
    struct Context {
        id: u64,
        started: Instant,
        paths: u64,
        edits: u64,
        edit_nanos: u128,
    }
    thread_local! {
        static ACTIVE: Cell<Option<Context>> = const { Cell::new(None) };
    }

    pub(crate) struct RequestScope {
        previous: Option<Context>,
        _thread: PhantomData<Rc<()>>,
    }
    impl RequestScope {
        pub(crate) fn enter() -> Self {
            let current = Context {
                id: NEXT.fetch_add(1, Ordering::Relaxed),
                started: Instant::now(),
                paths: 0,
                edits: 0,
                edit_nanos: 0,
            };
            let _ = writeln!(
                std::io::stderr().lock(),
                "HBKV2_IMPORT_PERF pid={} id={} event=request_begin",
                std::process::id(),
                current.id
            );
            Self {
                previous: ACTIVE.with(|slot| slot.replace(Some(current))),
                _thread: PhantomData,
            }
        }
    }
    impl Drop for RequestScope {
        fn drop(&mut self) {
            let current = ACTIVE.with(|slot| slot.replace(self.previous));
            if let Some(current) = current {
                emit_progress(current, "request_end");
            }
        }
    }

    pub(crate) struct Span {
        id: Option<u64>,
        label: &'static str,
        started: Instant,
    }
    impl Span {
        pub(crate) fn new(label: &'static str) -> Self {
            let current = ACTIVE.with(Cell::get);
            if let Some(current) = current {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "HBKV2_IMPORT_PERF pid={} id={} event=stage_begin phase={} since_request_ns={}",
                    std::process::id(),
                    current.id,
                    label,
                    current.started.elapsed().as_nanos()
                );
            }
            Self {
                id: current.map(|current| current.id),
                label,
                started: Instant::now(),
            }
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            if let Some(id) = self.id {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "HBKV2_IMPORT_PERF pid={} id={} event=stage_end phase={} elapsed_ns={}",
                    std::process::id(),
                    id,
                    self.label,
                    self.started.elapsed().as_nanos()
                );
            }
        }
    }

    pub(crate) fn metric(name: &'static str, value: usize) {
        if let Some(current) = ACTIVE.with(Cell::get) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "HBKV2_IMPORT_PERF pid={} id={} event=metric name={} value={}",
                std::process::id(),
                current.id,
                name,
                value
            );
        }
    }
    pub(crate) fn index_edit_elapsed(elapsed: Duration) {
        ACTIVE.with(|slot| {
            if let Some(mut current) = slot.get() {
                current.edits = current.edits.saturating_add(1);
                current.edit_nanos = current.edit_nanos.saturating_add(elapsed.as_nanos());
                slot.set(Some(current));
            }
        });
    }
    fn emit_progress(current: Context, event: &'static str) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBKV2_IMPORT_PERF pid={} id={} event={} completed_graph_path_iterations={} completed_index_edits={} index_edit_ns={} since_request_ns={}",
            std::process::id(),
            current.id,
            event,
            current.paths,
            current.edits,
            current.edit_nanos,
            current.started.elapsed().as_nanos()
        );
    }
    pub(crate) fn graph_path_completed() {
        ACTIVE.with(|slot| {
            if let Some(mut current) = slot.get() {
                current.paths = current.paths.saturating_add(1);
                slot.set(Some(current));
                if current.paths == 1 || current.paths % 1024 == 0 {
                    emit_progress(current, "graph_progress");
                }
            }
        });
    }
}
