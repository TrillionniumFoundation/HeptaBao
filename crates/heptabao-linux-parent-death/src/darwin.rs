//! Two fixed Darwin ownership operations; no caller callback or signal.
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
unsafe extern "C" {
    fn fchdir(fd: i32) -> i32;
    fn fchflags(fd: i32, flags: u32) -> i32;
}
/// Apply only the Darwin user immutable flag to an already owned file.
pub fn set_owned_file_immutable(file: &File, enabled: bool) -> io::Result<()> {
    // SAFETY: Borrowed File retains this descriptor; fchflags neither retains
    // pointers nor accepts a path. Flags are fixed UF_IMMUTABLE or zero.
    if unsafe { fchflags(file.as_raw_fd(), if enabled { 2 } else { 0 }) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
/// Change only the new child cwd to the original admitted directory descriptor.
/// The owned cloned descriptor is retained by the command through its exec.
pub fn bind_private_directory(command: &mut Command, directory: &File) -> io::Result<()> {
    let held = directory.try_clone()?;
    // SAFETY: The closed post-fork hook calls only fchdir on its owned descriptor
    // and errno conversion; no allocation, lock, formatting or caller code.
    unsafe {
        command.pre_exec(move || {
            if fchdir(held.as_raw_fd()) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
