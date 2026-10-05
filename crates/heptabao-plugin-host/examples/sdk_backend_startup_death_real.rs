//! Owns a real companion before any setup message is sent. The external test
//! launcher owns this Rust child and verifies cleanup after killing only it.
#[cfg(target_os = "macos")]
use heptabao_plugin_host::SandboxFailure;
#[cfg(target_os = "macos")]
#[path = "../src/darwin_sdk_image.rs"]
pub mod darwin_sdk_image;
#[cfg(target_os = "macos")]
mod darwin_fixture {
    use super::darwin_sdk_image::OwnedExecutableImage;
    use ring::digest::{SHA256, digest};
    use serde_json::json;
    use std::error::Error;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    fn checksum(p: &Path) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(digest(&SHA256, &std::fs::read(p)?).as_ref().try_into()?)
    }
    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub(super) fn main() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 4 {
            return Err("companion plugin fresh-output arguments".into());
        }
        let source_companion = PathBuf::from(&args[1]);
        let source_plugin = PathBuf::from(&args[2]);
        let out = PathBuf::from(&args[3]);
        std::fs::create_dir(&out)?;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
        let socket = out.join("socket");
        std::fs::create_dir(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700))?;
        let directory = File::open(&socket)?;
        let companion_sha = checksum(&source_companion)?;
        let plugin_sha = checksum(&source_plugin)?;
        let companion = OwnedExecutableImage::open_in(&source_companion, companion_sha, &socket)
            .map_err(|e| std::io::Error::other(format!("companion image: {e:?}")))?;
        let plugin = OwnedExecutableImage::open_in(&source_plugin, plugin_sha, &socket)
            .map_err(|e| std::io::Error::other(format!("plugin image: {e:?}")))?;
        companion.verify()?;
        plugin.verify()?;
        let mut command = companion.command();
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(out.join("companion.private.log"))?;
        command
            .env_clear()
            .env("TMPDIR", ".")
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log));
        heptabao_linux_parent_death::bind_private_directory(&mut command, &directory)?;
        let cfd = heptabao_linux_parent_death::inherit_owned_file(
            &mut command,
            companion.original_file(),
        )?;
        let pfd =
            heptabao_linux_parent_death::inherit_owned_file(&mut command, plugin.original_file())?;
        let (cdev, cino, csize) = companion.cleanup_identity();
        let (pdev, pino, psize) = plugin.cleanup_identity();
        let images = json!([
            {"role":"companion","path":companion.descriptor_path(),"fd":cfd,"device":cdev,"inode":cino,"bytes":csize,"sha256":hex(&companion_sha)},
            {"role":"plugin","path":plugin.descriptor_path(),"fd":pfd,"device":pdev,"inode":pino,"bytes":psize,"sha256":hex(&plugin_sha)}
        ]);
        command.env("HBP_SDK_OWNED_IMAGES", images.to_string());
        let child = command.spawn()?;
        let mut child = OwnedChild(child);
        // No setup or any other frame is written; stdin remains held until owner death.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Err(format!("companion exited before setup: {status}").into());
            }
            let mut text = String::new();
            File::open(out.join("companion.private.log"))?.read_to_string(&mut text)?;
            if text
                .lines()
                .any(|s| s == "HBP_SDK_DARWIN_OWNERSHIP_BOUND_V1")
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("original launch bootstrap timeout".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut receipt = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(out.join("startup-receipt.original.json"))?;
        receipt.write_all(serde_json::to_string(&json!({"actual_Rust_pid":std::process::id(),"actual_companion_pid":child.0.id(),"setup_messages_sent":0,"plugin_was_not_started":true,"original_readonly_FDs_transferred":true,"bootstrap_observed":true,"startup_fixture":true,"owned_images":images})).map_err(std::io::Error::other)?.as_bytes())?;
        receipt.sync_all()?;
        while Instant::now() < deadline {
            if child.0.try_wait()?.is_some() {
                return Err("companion died while Rust owner still holds stdin".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("external owned host-death test did not trigger".into())
    }
}
#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    darwin_fixture::main()
}
#[cfg(not(target_os = "macos"))]
fn main() {
    println!("Darwin startup fixture requires macOS");
}
