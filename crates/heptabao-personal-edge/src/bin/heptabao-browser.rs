//! Chromium Native Messaging adapter. A local OS account and its installed
//! extension are trusted; the extension ID is routing, not caller attestation.
//! Only the encrypted personal vault is used; no service-root credential API.
use heptabao_personal_edge::validate_origin;
use heptabao_personal_vault::{ItemKind, VaultSession, read_private_file};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MESSAGE_LIMIT: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    vault_root: PathBuf,
    extension_id: String,
    unlock_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    id: u64,
    request: Request,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Unlock {
        password: String,
    },
    Lock,
    List {
        origin: String,
    },
    Fill {
        item_id: String,
        origin: String,
        top_frame: bool,
    },
}
impl Drop for Request {
    fn drop(&mut self) {
        if let Self::Unlock { password } = self {
            password.zeroize();
        }
    }
}

#[derive(Serialize)]
struct Success<'a, T: Serialize> {
    id: u64,
    ok: bool,
    result: &'a T,
}
#[derive(Serialize)]
struct Failure<'a> {
    id: u64,
    ok: bool,
    error: &'a str,
}
#[derive(Serialize)]
struct Status {
    locked: bool,
}
#[derive(Serialize)]
struct Fill<'a> {
    origin: &'a str,
    username: &'a str,
    password: &'a str,
    valid_for_ms: u64,
}

fn write_frame<T: Serialize>(writer: &mut impl Write, data: &T) -> Result<(), &'static str> {
    let bytes = Zeroizing::new(serde_json::to_vec(data).map_err(|_| "response_failed")?);
    if bytes.len() > MESSAGE_LIMIT {
        return Err("response_limit");
    }
    let end = Instant::now() + Duration::from_millis(30);
    for buffer in [&(bytes.len() as u32).to_ne_bytes()[..], &bytes[..]] {
        let mut offset = 0;
        while offset < buffer.len() {
            if Instant::now() >= end {
                return Err("output_unavailable");
            }
            match writer.write(&buffer[offset..]) {
                Ok(0) => return Err("output_unavailable"),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err("output_unavailable"),
            }
        }
    }
    writer.flush().map_err(|_| "output_unavailable")
}
fn success<T: Serialize>(writer: &mut impl Write, id: u64, value: &T) -> Result<(), &'static str> {
    write_frame(
        writer,
        &Success {
            id,
            ok: true,
            result: value,
        },
    )
}

fn handle(
    config: &Config,
    session: &mut Option<VaultSession>,
    lease_deadline: &mut Option<Instant>,
    message: &mut Message,
    writer: &mut impl Write,
) -> Result<(), &'static str> {
    match &mut message.request {
        Request::Status => success(
            writer,
            message.id,
            &Status {
                locked: session.as_ref().is_none_or(VaultSession::is_expired),
            },
        ),
        Request::Lock => {
            *session = None;
            *lease_deadline = None;
            success(writer, message.id, &Status { locked: true })
        }
        Request::Unlock { password } => {
            *session = None;
            *lease_deadline = None;
            let admitted = Instant::now();
            let opened = VaultSession::unlock(
                &config.vault_root,
                password.as_bytes(),
                Duration::from_secs(config.unlock_seconds),
            );
            password.zeroize();
            *session = Some(opened.map_err(|e| e.code())?);
            *lease_deadline = Some(admitted + Duration::from_secs(config.unlock_seconds));
            success(writer, message.id, &Status { locked: false })
        }
        Request::List { origin } => {
            if !validate_origin(origin) {
                return Err("origin_rejected");
            }
            let vault = session.as_ref().ok_or("locked_or_expired")?;
            let summaries = vault.summaries().map_err(|e| e.code())?;
            let matching: Vec<_> = summaries
                .into_iter()
                .filter(|i| {
                    i.kind == ItemKind::Login && i.origin.as_deref() == Some(origin.as_str())
                })
                .collect();
            success(writer, message.id, &matching)
        }
        Request::Fill {
            item_id,
            origin,
            top_frame,
        } => {
            if !*top_frame || !validate_origin(origin) {
                return Err("origin_rejected");
            }
            let item = session
                .as_ref()
                .ok_or("locked_or_expired")?
                .login_for_origin(item_id, origin)
                .map_err(|e| e.code())?;
            let username = item
                .username
                .as_deref()
                .filter(|u| !u.is_empty())
                .ok_or("username_required")?;
            let remaining = lease_deadline
                .ok_or("locked_or_expired")?
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(2000) as u64;
            if remaining == 0 {
                return Err("locked_or_expired");
            }
            success(
                writer,
                message.id,
                &Fill {
                    origin,
                    username,
                    password: &item.secret,
                    valid_for_ms: remaining,
                },
            )
        }
    }
}

fn read_loop(sender: mpsc::SyncSender<Result<Zeroizing<Vec<u8>>, &'static str>>) {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    loop {
        let mut header = [0u8; 4];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(_) => break,
        }
        let length = u32::from_ne_bytes(header) as usize;
        if length == 0 || length > MESSAGE_LIMIT {
            let _ = sender.send(Err("message_limit"));
            break;
        }
        let mut bytes = Zeroizing::new(vec![0u8; length]);
        if reader.read_exact(&mut bytes).is_err() {
            let _ = sender.send(Err("incomplete_message"));
            break;
        }
        if sender.send(Ok(bytes)).is_err() {
            break;
        }
    }
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || args[1] != "--config" {
        return Err("configuration_required");
    }
    let raw = read_private_file(Path::new(&args[2])).map_err(|_| "configuration_rejected")?;
    if raw.len() > 8192 {
        return Err("configuration_rejected");
    }
    let config: Config = serde_json::from_slice(&raw).map_err(|_| "configuration_rejected")?;
    if config.extension_id.len() != 32
        || !config
            .extension_id
            .bytes()
            .all(|b| (b'a'..=b'p').contains(&b))
        || args[3] != format!("chrome-extension://{}/", config.extension_id)
        || !config.vault_root.is_absolute()
        || !(1..=300).contains(&config.unlock_seconds)
    {
        return Err("caller_or_configuration_rejected");
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let _reader = std::thread::spawn(move || read_loop(sender));
    let mut session: Option<VaultSession> = None;
    let mut lease_deadline: Option<Instant> = None;
    let deadline = Instant::now() + Duration::from_secs(1800);
    // A stalled native reader must not keep the unlocked session alive while
    // write_all blocks. Use an unbuffered, nonblocking duplicate and a bounded
    // output deadline; an incomplete frame closes the host and drops the key.
    let fd = rustix::io::dup(std::io::stdout()).map_err(|_| "output_unavailable")?;
    let flags = rustix::fs::fcntl_getfl(&fd).map_err(|_| "output_unavailable")?;
    rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| "output_unavailable")?;
    let mut writer = std::fs::File::from(fd);
    while Instant::now() < deadline {
        if session.as_ref().is_some_and(VaultSession::is_expired) {
            session = None;
            lease_deadline = None;
        }
        let raw = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(raw)) => raw,
            Ok(Err(error)) => {
                write_frame(
                    &mut writer,
                    &Failure {
                        id: 0,
                        ok: false,
                        error,
                    },
                )?;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let mut message: Message = match serde_json::from_slice(&raw) {
            Ok(value) => value,
            Err(_) => {
                write_frame(
                    &mut writer,
                    &Failure {
                        id: 0,
                        ok: false,
                        error: "invalid_message",
                    },
                )?;
                continue;
            }
        };
        if let Err(error) = handle(
            &config,
            &mut session,
            &mut lease_deadline,
            &mut message,
            &mut writer,
        ) {
            if error == "output_unavailable" {
                return Err(error);
            }
            write_frame(
                &mut writer,
                &Failure {
                    id: message.id,
                    ok: false,
                    error,
                },
            )?;
        }
    }
    drop(session);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
