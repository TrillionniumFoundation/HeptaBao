#![deny(unsafe_code)]
//! A fixed Linux pre-exec parent-death binding for an owned provider.
//!
//! Linux binds this signal to the thread that actually spawns the child. The
//! caller must therefore spawn from its persistent ownership thread, which
//! retains the child through its terminal wait, rather than a request thread.
//! Only the immediate child is bound; this is not descendant containment.

/// Bind an owned command to its spawning thread with the fixed SIGKILL signal.
///
/// An already terminated parent is rejected before exec. No caller-selected
/// PID, signal, callback, or environment is accepted by this API. The executed
/// image must retain its credentials so exec does not clear the kernel binding.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn bind_owner_death(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    let parent = rustix::process::getpid();
    // SAFETY: This closed hook runs after fork and before exec. It captures only
    // the numeric parent identity and calls rustix prctl/getppid syscalls. Error
    // conversion uses only the allocation-free raw OS errno constructor. It
    // performs no allocation, logging, environment access, locks or formatting,
    // invokes no caller code, and has no panic path.
    unsafe {
        command.pre_exec(move || {
            if let Err(error) = rustix::process::set_parent_process_death_signal(Some(
                rustix::process::Signal::KILL,
            )) {
                return Err(std::io::Error::from_raw_os_error(error.raw_os_error()));
            }
            // If the parent died before prctl, no pending death signal exists.
            // If it dies after prctl, SIGKILL covers this check and the exec.
            if rustix::process::getppid() != Some(parent) {
                return Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::SRCH.raw_os_error(),
                ));
            }
            Ok(())
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::bind_owner_death;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn spawning_thread_exit_kills_and_reaps_actual_child() -> Result<(), Box<dyn std::error::Error>>
    {
        // spawn waits for the successful exec handshake before this owner exits.
        // The process containing the parent remains alive throughout the test.
        let owner = std::thread::spawn(|| {
            let mut command = Command::new("/bin/sleep");
            command
                .arg("30")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            bind_owner_death(&mut command);
            command.spawn()
        });
        let mut child = owner
            .join()
            .map_err(|_| std::io::Error::other("test owner thread failed"))??;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait()? {
                assert_eq!(
                    status.signal(),
                    Some(9),
                    "owner-thread death produces actual kernel SIGKILL and owned wait"
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                // Test failure cleanup targets only this still-owned child.
                // Administrative termination cannot satisfy the assertion.
                child.kill()?;
                child.wait()?;
                return Err("owner-thread death did not terminate the actual child".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
