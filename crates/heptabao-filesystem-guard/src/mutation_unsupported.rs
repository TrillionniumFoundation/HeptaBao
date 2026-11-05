use super::{Observation, Removal, WatchId, refused};
use std::{fs::File, io};
pub(super) struct Queue;
pub(super) struct Registration;
impl Registration {
    pub(super) fn id(&self) -> WatchId {
        0
    }
}
impl Queue {
    pub(super) fn new() -> io::Result<Self> {
        Err(refused())
    }
    pub(super) fn register(&mut self, _file: &File) -> io::Result<Registration> {
        Err(refused())
    }
    pub(super) fn remove(&mut self, _registration: &Registration) -> io::Result<Removal> {
        Err(refused())
    }
    pub(super) fn drain(
        &mut self,
        _observe: &mut impl FnMut(Observation) -> io::Result<()>,
    ) -> io::Result<()> {
        Err(refused())
    }
}
