#![forbid(unsafe_code)]
use heptabao_credential_broker::{
    Bootstrap, Broker, Error, MAX_MESSAGE, Operation, Request, SignedGrant, authorize_revocation,
    call, initialize, issue, read_private, write_private,
};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
fn argument(args: &[String], index: usize) -> Result<&str, Error> {
    args.get(index)
        .map(String::as_str)
        .ok_or(Error("invalid_arguments"))
}
fn read<T: for<'de> serde::Deserialize<'de>>(path: &str) -> Result<T, Error> {
    serde_json::from_slice(&read_private(Path::new(path), MAX_MESSAGE)?)
        .map_err(|_| Error("invalid_input"))
}
fn emit(value: &impl serde::Serialize) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error("serialization_failure"))?;
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|_| Error("output_failure"))
}
fn response(value: serde_json::Value, execution: bool) -> Result<bool, Error> {
    let success = value["ok"].as_bool() == Some(true)
        && (!execution
            || (value["receipt"]["outcome"] == "completed"
                && value["receipt"]["http_success"].as_bool() != Some(false)));
    // Failure still includes the fixed broker error or durable receipt. A
    // nonzero exit is not permission to repeat an unknown external operation.
    emit(&value)?;
    Ok(success)
}
fn run() -> Result<bool, Error> {
    let args: Vec<String> = std::env::args().collect();
    let command = argument(&args, 1)?;
    let root = Path::new(argument(&args, 2)?);
    match command {
        "init" if args.len() == 3 => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(MAX_MESSAGE as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("input_failure"))?;
            if bytes.len() > MAX_MESSAGE {
                return Err(Error("input_too_large"));
            }
            let bootstrap: Bootstrap =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_input"))?;
            initialize(root, bootstrap)?;
            emit(&serde_json::json!({"ok":true,"synthetic_only":true}))?;
            Ok(true)
        }
        "issue" if args.len() == 6 => {
            let op: Operation = read(argument(&args, 3)?)?;
            let ttl: u64 = argument(&args, 5)?
                .parse()
                .map_err(|_| Error("invalid_ttl"))?;
            let grant = issue(root, &op, ttl)?;
            write_private(
                Path::new(argument(&args, 4)?),
                &serde_json::to_vec(&grant).map_err(|_| Error("serialization_failure"))?,
            )?;
            emit(
                &serde_json::json!({"ok":true,"grant_id":grant.grant.grant_id,"expires_at":grant.grant.expires_at}),
            )?;
            Ok(true)
        }
        "serve" if args.len() == 4 => {
            let count: usize = argument(&args, 3)?
                .parse()
                .map_err(|_| Error("invalid_request_limit"))?;
            Broker::open(root)?.serve(count)?;
            Ok(true)
        }
        "execute" | "status" if args.len() == 5 => {
            let operation: Operation = read(argument(&args, 3)?)?;
            let grant: SignedGrant = read(argument(&args, 4)?)?;
            let request = if command == "execute" {
                Request::Execute { grant, operation }
            } else {
                Request::Status { grant, operation }
            };
            response(call(root, &request)?, command == "execute")
        }
        "revoke" if args.len() == 4 => {
            let grant: SignedGrant = read(argument(&args, 3)?)?;
            let revocation = authorize_revocation(root, &grant)?;
            response(call(root, &Request::Revoke { revocation })?, false)
        }
        _ => Err(Error("invalid_arguments")),
    }
}
fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            let _result = writeln!(
                std::io::stderr(),
                "{{\"ok\":false,\"error\":\"{}\"}}",
                error.0
            );
            std::process::exit(1);
        }
    }
}
