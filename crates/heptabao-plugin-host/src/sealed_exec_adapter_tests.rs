use super::*;
use std::error::Error;
use std::io::Write;

fn entries() -> Vec<(OsString, OsString)> {
    [
        ("HEPTABAO_SANDBOX_PROVIDER", PROVIDER),
        ("HEPTABAO_KMS_DEPLOYMENT", "/data/owned/deployment.json"),
        ("HEPTABAO_KMS_DEPLOYMENT_SHA256", &"a".repeat(64)),
        ("HEPTABAO_KMS_PROVIDER", "transit"),
        ("HEPTABAO_KMS_TEMP", "/data/owned/socket"),
        ("HEPTABAO_KMS_TIMEOUT_MS", "5000"),
        ("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS", "10000"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
    .collect()
}

fn args(path: &str) -> Vec<OsString> {
    [
        "--heptabao-profile",
        PROFILE,
        "--heptabao-plugin",
        path,
        "--heptabao-protocol",
        "1",
        "--heptabao-operation",
        "read",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn descriptor_capability_grammar_rejects_paths_and_ambiguous_numbers() {
    assert_eq!(parse_descriptor("/proc/23/fd/4"), Some(Descriptor { parent: 23, fd: 4 }));
    for path in [
        "/tmp/bridge",
        "/proc/self/fd/4",
        "/proc/023/fd/4",
        "/proc/0/fd/4",
        "/proc/23/fd/2",
        "/proc/23/fd/04",
        "/proc/23/fd/+4",
        "/proc/23/fd/4/",
        "/proc/23/fd/../4",
        "/proc/4294967296/fd/4",
        "/proc/23/fd/4294967296",
    ] {
        assert!(parse_descriptor(path).is_none(), "ambiguous image capability rejected");
    }
}

#[test]
fn only_fixed_read_profile_and_exact_arguments_are_accepted() {
    assert!(arguments(&args("/proc/23/fd/4")).is_ok());
    for (index, value) in [(1, "other"), (5, "2"), (7, "write"), (4, "--unknown")] {
        let mut values = args("/proc/23/fd/4");
        values[index] = OsString::from(value);
        assert_eq!(arguments(&values), Err(AdapterError::Arguments));
    }
    let mut values = args("/proc/23/fd/4");
    values.push(OsString::from("--deployment"));
    assert_eq!(arguments(&values), Err(AdapterError::Arguments));
}

#[test]
fn environment_is_closed_and_duplicate_values_do_not_override() {
    assert!(environment(entries(), 9999).is_ok());
    let mut values = entries();
    values.push((OsString::from("PATH"), OsString::from("/usr/bin")));
    assert_eq!(environment(values, 1), Err(AdapterError::Environment));
    let mut values = entries();
    values.push((OsString::from(ENVIRONMENT[0]), OsString::from(PROVIDER)));
    assert_eq!(environment(values, 1), Err(AdapterError::Environment));
    let mut values = entries();
    values.pop();
    assert_eq!(environment(values, 1), Err(AdapterError::Environment));
}

#[test]
fn deadline_remains_absolute_and_closed_numeric_fields_are_required() {
    assert_eq!(environment(entries(), 10000), Err(AdapterError::Deadline));
    assert_eq!(environment(entries(), 10001), Err(AdapterError::Deadline));
    for value in ["0", "+10000", "010000", "9223372036854775808"] {
        let mut values = entries();
        values[6].1 = OsString::from(value);
        assert_eq!(environment(values, 1), Err(AdapterError::Deadline));
    }
    for value in ["0", "60001", "05000", "-1", "5.0"] {
        let mut values = entries();
        values[5].1 = OsString::from(value);
        assert_eq!(environment(values, 1), Err(AdapterError::Environment));
    }
}

#[test]
fn environment_cannot_change_provider_or_relax_operator_paths_and_digest() {
    for (index, value) in [
        (0, "fixture"),
        (1, "/data/../deployment"),
        (1, "/data//deployment"),
        (2, "not-a-digest"),
        (2, "0000000000000000000000000000000000000000000000000000000000000000"),
        (3, "other-kms"),
        (4, "/data/owned/socket/"),
    ] {
        let mut values = entries();
        values[index].1 = OsString::from(value);
        assert_eq!(environment(values, 1), Err(AdapterError::Environment));
    }
}

#[test]
fn proc_identity_parses_kernel_comm_parentheses_and_keeps_start_ticks() {
    let mut fields = vec!["S".to_owned(), "5".to_owned()];
    fields.extend((0..17).map(|_| "0".to_owned()));
    fields.push("123".to_owned());
    let text = format!("42 (name with ) delimiters) {}\n", fields.join(" "));
    assert_eq!(
        process_identity(&text),
        Some(ProcessIdentity { pid: 42, parent: 5, start_ticks: 123 })
    );
    assert!(process_identity("42 (broken) S 5").is_none());
    assert!(process_identity(&text.replace("123", "0")).is_none());
}

#[test]
fn non_parent_descriptor_rejects_without_opening_requested_image() -> Result<(), Box<dyn Error>> {
    let own = self_identity()?;
    assert!(matches!(
        Parent::capture(Descriptor { parent: own.pid, fd: 3 }),
        Err(AdapterError::Parent)
    ));
    Ok(())
}

fn image(bytes: &[u8], seals: SealFlags, mode: Mode) -> Result<File, Box<dyn Error>> {
    let mut file = File::from(rustix::fs::memfd_create(
        "heptabao-adapter-admission-test",
        rustix::fs::MemfdFlags::CLOEXEC
            | rustix::fs::MemfdFlags::ALLOW_SEALING
            | rustix::fs::MemfdFlags::EXEC,
    )?);
    file.write_all(bytes)?;
    rustix::fs::fchmod(&file, mode)?;
    if !seals.is_empty() {
        rustix::fs::fcntl_add_seals(&file, seals)?;
    }
    // A new read-only open gives checked_image its own initial file offset.
    Ok(File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?)
}

fn elf_header() -> [u8; 64] {
    // Parser fixture only; not an executable, provider or cryptographic result.
    let mut bytes = [0_u8; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    let machine: u16 = if cfg!(target_arch = "aarch64") { 183 } else { 62 };
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes
}

fn all_seals() -> SealFlags {
    SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::EXEC | SealFlags::SEAL
}

#[test]
fn only_complete_executable_seals_with_exact_mode_pass_image_admission()
-> Result<(), Box<dyn Error>> {
    let bytes = elf_header();
    let mut valid = image(&bytes, all_seals(), Mode::RUSR | Mode::XUSR)?;
    assert!(checked_image(&mut valid).is_ok(), "complete immutable header admission");
    // F_SEAL_EXEC on an executable memfd may add write/grow/shrink seals
    // automatically. These are constructible incomplete kernel seal sets.
    for seals in [
        SealFlags::empty(),
        SealFlags::WRITE,
        SealFlags::SEAL,
        all_seals() & !SealFlags::EXEC,
        all_seals() & !SealFlags::SEAL,
    ] {
        let mut invalid = image(&bytes, seals, Mode::RUSR | Mode::XUSR)?;
        assert_eq!(checked_image(&mut invalid), Err(AdapterError::Image));
    }
    let mut invalid = image(&bytes, all_seals(), Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
    assert_eq!(checked_image(&mut invalid), Err(AdapterError::Image));
    Ok(())
}

#[test]
fn shebang_wrong_machine_and_truncated_images_never_pass_as_bridge()
-> Result<(), Box<dyn Error>> {
    let mut bytes = elf_header();
    bytes[..7].copy_from_slice(b"#!/bin/");
    let mut script = image(&bytes, all_seals(), Mode::RUSR | Mode::XUSR)?;
    assert_eq!(checked_image(&mut script), Err(AdapterError::Image));
    let mut bytes = elf_header();
    bytes[18..20].copy_from_slice(&0_u16.to_le_bytes());
    let mut other = image(&bytes, all_seals(), Mode::RUSR | Mode::XUSR)?;
    assert_eq!(checked_image(&mut other), Err(AdapterError::Image));
    let mut short = image(&[0; 63], all_seals(), Mode::RUSR | Mode::XUSR)?;
    assert_eq!(checked_image(&mut short), Err(AdapterError::Image));
    Ok(())
}
