//! Stream one exact paged KV2 owner into the existing lossless import schema.
//!
//! Serialization grants no Actor, source, publication or restore authority.
//! The Service retains those owners and the original bounded file/deadline.
use super::*;
use crate::auth::Timestamp;
use std::io::{self, Write};

pub(crate) const PATH: &str = "sys/migration/openbao/kv2/export";
pub(crate) const MEDIA_TYPE: &str = lossless::native_large::MEDIA_TYPE;
pub(crate) const MAX_BYTES: u64 = lossless::native_large::MAX_BUNDLE_BYTES as u64;

fn rejected() -> EngineError {
    error(503, "native KV2 lossless export source is unavailable")
}
fn output_failed() -> EngineError {
    error(503, "native KV2 lossless export output is unavailable")
}

fn time_point(seconds: u64, precise: Option<Timestamp>) -> (u64, u32) {
    (
        seconds,
        precise.map_or(0, |at| at.duration_since_epoch().subsec_nanos()),
    )
}

// Native records can preserve sparse legacy histories. The existing lossless
// transfer schema cannot: refuse explicitly, never invent missing versions or
// export a successful bundle which the same schema cannot restore.
fn check_export_entry(entry: &Entry) -> Result<()> {
    let first = entry.oldest_version.max(1);
    let expected = if entry.current_version == 0 {
        0
    } else {
        entry
            .current_version
            .checked_sub(first)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(rejected)?
    };
    if (entry.current_version == 0 && entry.oldest_version != 0)
        || entry.versions.len() as u64 != expected
    {
        return Err(error(
            409,
            "lossless export schema cannot represent sparse retained history",
        ));
    }
    let created = time_point(entry.created_at, entry.precision.created_at);
    let updated = time_point(entry.updated_at, entry.precision.updated_at);
    if updated < created {
        return Err(rejected());
    }
    for (number, version) in &entry.versions {
        let precise = entry.version_precision(*number);
        let issued = time_point(version.created_at, precise.created_at);
        if issued < created
            || issued > updated
            || version
                .deletion_at
                .is_some_and(|at| time_point(at, precise.deletion_at) < issued)
            || precise
                .source_deletion_at
                .is_some_and(|at| time_point(at.seconds(), Some(at)) < issued)
        {
            return Err(rejected());
        }
    }
    Ok(())
}

pub(crate) fn check_export_syntax(
    reader: &mut impl io::Read,
    length: u64,
    check: &impl Fn() -> CodecResult<()>,
) -> Result<()> {
    lossless::native_large::check_export_syntax(reader, length, check)
}

struct BoundedOutput<'a, W> {
    writer: &'a mut W,
    written: u64,
    exhausted: bool,
}
impl<W: Write> Write for BoundedOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > MAX_BYTES)
        {
            self.exhausted = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lossless export bound exceeded",
            ));
        }
        let written = self.writer.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// Any partial file is discarded. The Service checks the original gate and
// mandatory audit again before allowing the completed file to reach a socket.
fn json<T: Serialize + ?Sized>(
    output: &mut impl Write,
    value: &T,
    check: &impl Fn() -> CodecResult<()>,
) -> Result<()> {
    check().map_err(|_| rejected())?;
    serde_json::to_writer(output, value).map_err(|_| output_failed())?;
    check().map_err(|_| rejected())
}
fn bytes(output: &mut impl Write, value: &[u8]) -> Result<()> {
    output.write_all(value).map_err(|_| output_failed())
}
fn field<T: Serialize + ?Sized>(
    output: &mut impl Write,
    name: &str,
    value: &T,
    first: &mut bool,
    check: &impl Fn() -> CodecResult<()>,
) -> Result<()> {
    if !*first {
        bytes(output, b",")?;
    }
    *first = false;
    json(output, name, check)?;
    bytes(output, b":")?;
    json(output, value, check)
}

#[derive(Serialize)]
struct ExportConfig {
    max_versions: u64,
    cas_required: bool,
    metadata_cas_required: bool,
    delete_version_after: String,
}
impl ExportConfig {
    fn from_owner(config: &Config) -> Self {
        Self {
            max_versions: config.max_versions,
            cas_required: config.cas_required,
            metadata_cas_required: config.metadata_cas_required,
            delete_version_after: lossless::display_duration(
                config.delete_version_after,
                config.delete_version_after_nanos,
            ),
        }
    }
}

impl NativeReadView {
    /// Keep the original ordered descriptor decoder/writer. The new reader
    /// only overlaps independently checked source reads in this one request.
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn write_lossless_export_parallel(
        &self,
        output: &mut impl Write,
        source: &(impl Fn(&ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> + Sync),
        before_delivery: &(impl Fn() -> CodecResult<()> + Sync),
        check: &(impl Fn() -> CodecResult<()> + Sync),
        deadline: crate::v6_native_custody::OriginalDeadline,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        let result = (|| {
            check().map_err(|_| rejected())?;
            if !self.is_paged() {
                return Err(error(501, "lossless export requires native paged KV2"));
            }
            // Preflight actual immutable owner metadata before any read-ahead.
            // The original decoder still repeats its full scoped descriptor,
            // ObjectRef, aggregate keyed digest and grammar validation.
            self.validate_paged_metadata().map_err(|_| rejected())?;
            let graph = self.graph.as_ref().ok_or_else(rejected)?;
            let paged = graph.paged.as_ref().ok_or_else(rejected)?;
            for entry in self.owner.entries.values() {
                check().map_err(|_| rejected())?;
                check_export_entry(entry)?;
            }
            let references = self.owner.entries.iter().flat_map(|(path, entry)| {
                entry
                    .versions
                    .iter()
                    .filter(|(_, version)| !version.destroyed)
                    .flat_map(move |(number, _)| {
                        match paged
                            .descriptors
                            .get(path)
                            .and_then(|values| values.get(number))
                        {
                            Some(descriptor) => ExportBlockRefs::Blocks(descriptor.blocks.iter()),
                            None => ExportBlockRefs::Missing(true),
                        }
                    })
            });
            prefetch::with_reader(
                references,
                source,
                before_delivery,
                check,
                deadline,
                stop,
                |reader| self.write_lossless_export(output, reader, check),
            )
        })();
        if result.is_err() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    /// Retain all source state, including empty custom metadata and a destroyed
    /// version's source-deletion timestamp. An external destination must reject
    /// states it cannot represent; export must not silently normalize them.
    pub(crate) fn write_lossless_export(
        &self,
        output: &mut impl Write,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<()> {
        let mut output = BoundedOutput {
            writer: output,
            written: 0,
            exhausted: false,
        };
        let result = self.write_lossless_export_inner(&mut output, reader, check);
        if output.exhausted {
            return Err(error(
                413,
                "native KV2 lossless export exceeds bundle bound",
            ));
        }
        result
    }

    fn write_lossless_export_inner(
        &self,
        output: &mut impl Write,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<()> {
        check().map_err(|_| rejected())?;
        if !self.is_paged() {
            return Err(error(501, "lossless export requires native paged KV2"));
        }
        self.validate_paged_metadata().map_err(|_| rejected())?;
        let graph = self.graph.as_ref().ok_or_else(rejected)?;
        let paged = graph.paged.as_ref().ok_or_else(rejected)?;
        for entry in self.owner.entries.values() {
            check().map_err(|_| rejected())?;
            check_export_entry(entry)?;
        }
        bytes(output, b"{\"schema\":")?;
        json(output, lossless::IMPORT_SCHEMA, check)?;
        bytes(output, b",\"config\":")?;
        json(output, &ExportConfig::from_owner(&self.owner.config), check)?;
        bytes(output, b",\"entries\":{")?;
        let mut first_entry = true;
        for (path, entry) in &self.owner.entries {
            check().map_err(|_| rejected())?;
            if !first_entry {
                bytes(output, b",")?;
            }
            first_entry = false;
            json(output, path, check)?;
            bytes(output, b":{")?;
            let mut first = true;
            field(
                output,
                "created_time",
                &lossless::display_time(entry.created_at, entry.precision.created_at),
                &mut first,
                check,
            )?;
            field(
                output,
                "updated_time",
                &lossless::display_time(entry.updated_at, entry.precision.updated_at),
                &mut first,
                check,
            )?;
            field(
                output,
                "current_version",
                &entry.current_version,
                &mut first,
                check,
            )?;
            field(
                output,
                "oldest_version",
                &entry.oldest_version,
                &mut first,
                check,
            )?;
            field(
                output,
                "current_metadata_version",
                &entry.current_metadata_version,
                &mut first,
                check,
            )?;
            field(
                output,
                "max_versions",
                &entry.config.max_versions,
                &mut first,
                check,
            )?;
            field(
                output,
                "cas_required",
                &entry.config.cas_required,
                &mut first,
                check,
            )?;
            field(
                output,
                "metadata_cas_required",
                &entry.config.metadata_cas_required,
                &mut first,
                check,
            )?;
            field(
                output,
                "delete_version_after",
                &lossless::display_duration(
                    entry.config.delete_version_after,
                    entry.config.delete_version_after_nanos,
                ),
                &mut first,
                check,
            )?;
            field(
                output,
                "custom_metadata",
                &entry.custom_metadata,
                &mut first,
                check,
            )?;
            bytes(output, b",\"versions\":{")?;
            let mut first_version = true;
            for (number, version) in &entry.versions {
                check().map_err(|_| rejected())?;
                if !first_version {
                    bytes(output, b",")?;
                }
                first_version = false;
                json(output, &number.to_string(), check)?;
                bytes(output, b":{")?;
                let precise = entry.version_precision(*number);
                let mut first = true;
                field(
                    output,
                    "created_time",
                    &lossless::display_time(version.created_at, precise.created_at),
                    &mut first,
                    check,
                )?;
                field(
                    output,
                    "deletion_time",
                    &version
                        .deletion_at
                        .map(|at| lossless::display_time(at, precise.deletion_at))
                        .unwrap_or_default(),
                    &mut first,
                    check,
                )?;
                field(output, "destroyed", &version.destroyed, &mut first, check)?;
                field(
                    output,
                    "source_deletion_time",
                    &precise
                        .source_deletion_at
                        .map(Timestamp::rfc3339)
                        .unwrap_or_default(),
                    &mut first,
                    check,
                )?;
                let descriptor = paged
                    .descriptors
                    .get(path)
                    .and_then(|versions| versions.get(number));
                if version.destroyed {
                    if descriptor.is_some() || version.data.is_some() {
                        return Err(rejected());
                    }
                    field(output, "data", &Value::Null, &mut first, check)?;
                } else {
                    // Fresh blocks, full scoped descriptor, every ObjectRef and
                    // aggregate keyed digest are checked on this invocation.
                    let descriptor = descriptor.ok_or_else(rejected)?;
                    if descriptor.logical_bytes > lossless::native_large::MAX_RECORD_BYTES as u64 {
                        return Err(error(
                            413,
                            "native KV2 lossless export exceeds record bound",
                        ));
                    }
                    let data = descriptor
                        .read(&graph.key, path, *number, reader, check)
                        .map_err(|_| rejected())?;
                    check().map_err(|_| rejected())?;
                    if !data.expose().is_object()
                        || (lossless::needs_lossless_number_format(data.expose())
                            && self.owner.lossless_format != Some(1))
                    {
                        return Err(rejected());
                    }
                    field(output, "data", data.expose(), &mut first, check)?;
                    drop(data);
                    check().map_err(|_| rejected())?;
                }
                bytes(output, b"}")?;
            }
            bytes(output, b"}}")?;
            check().map_err(|_| rejected())?;
        }
        bytes(output, b"}}\n")?;
        check().map_err(|_| rejected())
    }
}

#[cfg(test)]
#[path = "kv2_native_lossless_export_tests.rs"]
mod tests;

#[cfg(any(test, feature = "native-v6-storage"))]
#[path = "kv2_native_lossless_prefetch.rs"]
mod prefetch;

// Lazy ownership order, including repeated references. No graph-wide list,
// deduplication or successful bytes from an earlier position are retained.
#[cfg(any(test, feature = "native-v6-storage"))]
enum ExportBlockRefs<'a> {
    Blocks(std::slice::Iter<'a, ObjectRef>),
    Missing(bool),
}
#[cfg(any(test, feature = "native-v6-storage"))]
impl Iterator for ExportBlockRefs<'_> {
    type Item = CodecResult<ObjectRef>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Blocks(blocks) => blocks.next().cloned().map(Ok),
            Self::Missing(pending) => {
                if std::mem::take(pending) {
                    Some(Err(RecordError::Missing))
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "kv2_native_lossless_parallel_tests.rs"]
mod parallel_tests;
