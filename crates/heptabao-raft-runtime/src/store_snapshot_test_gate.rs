//! Test-only pause after a genuine snapshot has been persisted and its store
//! mutex released, before the builder returns metadata to OpenRaft. No log,
//! frontier, durable value or authority is supplied by this seam.
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    captured: AtomicU64,
    triggers: AtomicU64,
    released: AtomicBool,
    changed: Notify,
    release: Notify,
}
static GATES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Gate>>>> = OnceLock::new();
fn gates() -> &'static Mutex<BTreeMap<PathBuf, Arc<Gate>>> {
    GATES.get_or_init(Mutex::default)
}
fn selected(path: &Path) -> Option<Arc<Gate>> {
    gates().lock().ok()?.get(path).cloned()
}
pub(crate) struct SnapshotPause {
    path: PathBuf,
    gate: Arc<Gate>,
}
pub(crate) fn arm(path: &Path) -> io::Result<SnapshotPause> {
    let mut entries = gates()
        .lock()
        .map_err(|_| io::Error::other("snapshot test gate lock"))?;
    if entries.contains_key(path) {
        return Err(io::Error::other("snapshot test gate already armed"));
    }
    let gate = Arc::new(Gate::default());
    gate.armed.store(true, Ordering::SeqCst);
    entries.insert(path.to_path_buf(), Arc::clone(&gate));
    Ok(SnapshotPause {
        path: path.to_path_buf(),
        gate,
    })
}
impl SnapshotPause {
    pub(crate) async fn captured_index(&self) -> u64 {
        loop {
            let changed = self.gate.changed.notified();
            let value = self.gate.captured.load(Ordering::SeqCst);
            if value != 0 {
                return value;
            }
            changed.await;
        }
    }
    pub(crate) fn trigger_count(&self) -> u64 {
        self.gate.triggers.load(Ordering::SeqCst)
    }
    pub(crate) async fn wait_for_trigger_count(&self, count: u64) {
        loop {
            let changed = self.gate.changed.notified();
            if self.trigger_count() >= count {
                return;
            }
            changed.await;
        }
    }
    pub(crate) fn release(&self) {
        self.gate.released.store(true, Ordering::SeqCst);
        self.gate.release.notify_one();
    }
}
impl Drop for SnapshotPause {
    fn drop(&mut self) {
        self.release();
        if let Ok(mut entries) = gates().lock()
            && entries
                .get(&self.path)
                .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
        {
            entries.remove(&self.path);
        }
    }
}
pub(super) fn note_trigger(path: &Path) {
    if let Some(gate) = selected(path) {
        gate.triggers.fetch_add(1, Ordering::SeqCst);
        gate.changed.notify_one();
    }
}
pub(super) async fn after_persist(path: &Path, index: Option<u64>) {
    let Some(gate) = selected(path) else { return };
    if !gate.armed.swap(false, Ordering::SeqCst) {
        return;
    }
    if let Some(index) = index {
        gate.captured.store(index, Ordering::SeqCst);
        gate.changed.notify_one();
    }
    while !gate.released.load(Ordering::SeqCst) {
        gate.release.notified().await;
    }
}
