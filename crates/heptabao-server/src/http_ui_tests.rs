use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    directory: PathBuf,
    manifest: PathBuf,
}
impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Result<Self, Box<dyn std::error::Error>> {
        // macOS /var aliases /private/var. The UI loader correctly rejects
        // noncanonical paths, including in its synthetic test fixture.
        let root = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-ui-assets-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let directory = root.join("dist");
        fs::create_dir(&directory)?;
        let mut pins = Vec::new();
        for (path, bytes) in files {
            let target = directory.join(path);
            fs::create_dir_all(target.parent().ok_or("parent")?)?;
            fs::write(&target, bytes)?;
            pins.push(json!({"path":path,"bytes":bytes.len(),"sha256":sha256(bytes)}));
        }
        let manifest = root.join("pins.json");
        fs::write(&manifest, serde_json::to_vec(&pins)?)?;
        Ok(Self {
            root,
            directory,
            manifest,
        })
    }
    fn assets(&self) -> Result<Assets, String> {
        Assets::load(
            &self.directory,
            &self.manifest,
            &sha256(&fs::read(&self.manifest).map_err(|_| "pins")?),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn manifest_pins_bytes_and_the_loaded_table_is_immutable() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(&[
        ("index.html", b"official index"),
        ("assets/app.js", b"official js"),
    ])?;
    let assets = fixture.assets()?;
    fs::write(
        fixture.directory.join("assets/app.js"),
        b"changed after startup",
    )?;
    assert!(fixture.assets().is_err());
    let reply = assets.reply(&request("GET", "/ui/assets/app.js").map_err(|error| error.message)?);
    let mut bytes = Vec::new();
    reply.write(&mut bytes, false)?;
    assert!(bytes.ends_with(b"official js"));
    assert!(Assets::load(&fixture.directory, &fixture.manifest, &"0".repeat(64)).is_err());
    Ok(())
}

#[test]
fn ui_head_mime_worker_scope_and_spa_fallback_are_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(&[
        ("index.html", b"official index"),
        ("assets/app.js", b"official js"),
        ("service-worker.js", b"worker"),
    ])?;
    let assets = fixture.assets()?;
    for path in [
        "/ui/",
        "/ui/vault/auth",
        "/ui/vault/secrets/secret/show/item",
        "/ui/vault/access/namespaces",
        "/ui/vault/mfa-setup",
        "/ui/vault/team/identity/oidc/provider/demo/authorize",
    ] {
        let reply = assets.reply(&request("GET", path).map_err(|error| error.message)?);
        assert_eq!(reply.status, 200);
        assert_eq!(&*reply.bytes, b"official index");
    }
    for path in [
        "/ui/assets/missing.js",
        "/ui/not-a-route",
        "/ui/v1/sys/seal",
        "/ui/images/missing.svg",
    ] {
        assert_eq!(
            assets
                .reply(&request("GET", path).map_err(|error| error.message)?)
                .status,
            404
        );
    }
    let mut head = Vec::new();
    assets
        .reply(&request("HEAD", "/ui/assets/app.js").map_err(|error| error.message)?)
        .write(&mut head, true)?;
    let head = std::str::from_utf8(&head)?;
    assert!(head.contains("Content-Type: text/javascript; charset=utf-8\r\n"));
    assert!(head.contains("Content-Length: 11\r\n"));
    assert!(head.contains("X-Content-Type-Options: nosniff\r\n"));
    assert!(head.contains("Cache-Control: no-store\r\n"));
    assert!(head.ends_with("\r\n\r\n"));
    let mut worker = Vec::new();
    assets
        .reply(&request("GET", "/ui/service-worker.js").map_err(|error| error.message)?)
        .write(&mut worker, false)?;
    assert!(
        std::str::from_utf8(&worker)?
            .contains("Service-Worker-Allowed: /v1/sys/storage/raft/snapshot\r\n")
    );
    let mut redirect = Vec::new();
    assets
        .reply(&request("GET", "/ui").map_err(|error| error.message)?)
        .write(&mut redirect, false)?;
    assert!(std::str::from_utf8(&redirect)?.contains("Location: /ui/\r\n"));
    Ok(())
}

#[test]
fn ui_targets_reject_traversal_encoded_separators_and_hidden_paths() {
    for target in [
        "/ui/../audit.jsonl",
        "/ui/%2e%2e/audit.jsonl",
        "/ui/assets/%2fetc/passwd",
        "/ui/assets/%5csecret",
        "/ui/assets/%252e%252e/secret",
        "/ui//assets/app.js",
        "/ui/.git/config",
        "/ui/assets/app.js#fragment",
        "/ui/assets/%00",
        "/ui/assets/%ZZ",
        "/ui/assets/\\secret",
    ] {
        assert!(request("GET", target).is_err(), "{target}");
    }
    assert!(request("POST", "/ui/").is_err());
    assert!(request("GET", "/ui/vault/auth?namespace=child").is_ok());
}

#[test]
fn enabled_ui_retains_header_framing_and_never_consumes_a_json_body() {
    fn parse(wire: &str, enabled: bool) -> Result<ParsedRequest, ParseError> {
        read_request_with_ui(
            &mut io::Cursor::new(wire.as_bytes()),
            Duration::from_secs(1),
            true,
            enabled,
        )
    }
    let good = "GET /ui/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert!(matches!(parse(good, true), Ok(ParsedRequest::Ui(_))));
    assert!(parse(good, false).is_err());
    for wire in [
        "GET /ui/ HTTP/1.1\r\n\r\n",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n{}",
        "GET /ui/ HTTP/1.1\r\nHost: a\r\n\r\nGET /v1/sys/seal HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        assert!(parse(wire, true).is_err(), "{wire:?}");
    }
    assert!(matches!(
        parse(
            "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
            true
        ),
        Ok(ParsedRequest::Api(_))
    ));
}

#[test]
fn asset_manifest_rejects_duplicate_traversal_and_missing_index()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(&[("index.html", b"index")])?;
    let row = json!({"path":"index.html","bytes":5,"sha256":sha256(b"index")});
    fs::write(
        &fixture.manifest,
        serde_json::to_vec(&vec![row.clone(), row])?,
    )?;
    assert!(fixture.assets().is_err());
    fs::write(
        &fixture.manifest,
        serde_json::to_vec(&vec![
            json!({"path":"../index.html","bytes":5,"sha256":sha256(b"index")}),
        ])?,
    )?;
    assert!(fixture.assets().is_err());
    let no_index = Fixture::new(&[("assets/app.js", b"js")])?;
    assert!(no_index.assets().is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn ui_loader_rejects_asset_symlinks_and_hardlinks() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(&[("index.html", b"index"), ("assets/app.js", b"js")])?;
    let path = fixture.directory.join("assets/app.js");
    fs::remove_file(&path)?;
    std::os::unix::fs::symlink(fixture.directory.join("index.html"), &path)?;
    assert!(fixture.assets().is_err());
    fs::remove_file(&path)?;
    fs::hard_link(fixture.directory.join("index.html"), &path)?;
    assert!(fixture.assets().is_err());
    Ok(())
}

#[test]
fn official_sw_filename_get_and_head_have_exact_snapshot_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(&[
        ("index.html", b"official index"),
        ("sw.js", b"registered worker"),
        ("sw-registration.js", b"registration script"),
        ("assets/app.js", b"ordinary script"),
    ])?;
    let assets = fixture.assets()?;
    for method in ["GET", "HEAD"] {
        let mut wire = Vec::new();
        assets
            .reply(&request(method, "/ui/sw.js").map_err(|error| error.message)?)
            .write(&mut wire, method == "HEAD")?;
        let wire = std::str::from_utf8(&wire)?;
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("Content-Type: text/javascript; charset=utf-8\r\n"));
        assert!(wire.contains("Content-Length: 17\r\n"));
        assert_eq!(
            wire.matches("Service-Worker-Allowed: /v1/sys/storage/raft/snapshot\r\n")
                .count(),
            1
        );
        if method == "HEAD" {
            assert!(wire.ends_with("\r\n\r\n"));
        } else {
            assert!(wire.ends_with("\r\n\r\nregistered worker"));
        }
    }
    for path in ["/ui/sw-registration.js", "/ui/assets/app.js"] {
        let mut wire = Vec::new();
        assets
            .reply(&request("GET", path).map_err(|error| error.message)?)
            .write(&mut wire, false)?;
        assert!(!std::str::from_utf8(&wire)?.contains("Service-Worker-Allowed:"));
    }
    Ok(())
}
