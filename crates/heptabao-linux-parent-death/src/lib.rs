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
    use std::process::{Command, Stdio};

    #[test]
    fn fixed_signal_and_parent_survive_actual_exec() -> Result<(), Box<dyn std::error::Error>> {
        const PROBE: &str = "HEPTABAO_PARENT_DEATH_EXEC_TEST";
        if let Ok(expected_parent) = std::env::var(PROBE) {
            let expected_parent: i32 = expected_parent.parse()?;
            assert_eq!(
                rustix::process::parent_process_death_signal()?,
                Some(rustix::process::Signal::KILL),
                "the actual executed child retains the fixed kernel signal"
            );
            assert_eq!(
                rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get()),
                Some(expected_parent),
                "the actual executed child remains owned by its spawning parent"
            );
            return Ok(());
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "tests::fixed_signal_and_parent_survive_actual_exec",
            ])
            .env(
                PROBE,
                rustix::process::getpid().as_raw_nonzero().get().to_string(),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        bind_owner_death(&mut command);
        let mut child = command.spawn()?;
        assert!(
            child.wait()?.success(),
            "actual child executes and exits normally"
        );
        Ok(())
    }
}
