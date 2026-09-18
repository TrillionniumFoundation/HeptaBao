"""Explicit HTTPS commands. Credentials never enter argv or ordinary stdout.

Every response is published into a new owner-only file. No shell execution,
redirect following, credential caching, environment-token fallback or blind
mutation retry is performed. This is not the full OpenBao CLI/Agent/Proxy.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
from .transport import (BaoError, Client, SafeArgumentParser, decode_json,
                        key_path, private_read, private_write)

INPUT_LIMIT = 256 * 1024


def token_file(path: str) -> str:
    try:
        value = private_read(path, 8192).decode("ascii").strip()
    except UnicodeError:
        raise BaoError("invalid_token_file") from None
    if not value or len(value) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise BaoError("invalid_token_file")
    return value


def output_preflight(path: str) -> None:
    """Reject a bad destination before any API request, then recheck on publish."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise BaoError("private_files_require_posix")
    target = Path(path).absolute()
    directory = None
    try:
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not stat.S_ISDIR(info.st_mode):
            raise BaoError("output_directory_requires_owner_only_mode")
        try:
            os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise BaoError("output_already_exists")
    except OSError:
        raise BaoError("output_preflight_failed") from None
    finally:
        if directory is not None:
            os.close(directory)


def input_object(filename: str):
    if filename == "-":
        if sys.stdin.isatty():
            raise BaoError("piped_json_input_required")
        data = sys.stdin.buffer.read(INPUT_LIMIT + 1)
        if len(data) > INPUT_LIMIT:
            raise BaoError("input_size_limit")
    else:
        data = private_read(filename, INPUT_LIMIT)
    result = decode_json(data)
    if not isinstance(result, dict):
        raise BaoError("input_object_required")
    return result


def parser() -> SafeArgumentParser:
    result = SafeArgumentParser(description=__doc__)
    result.add_argument("--address", required=True, help="Explicit HTTPS origin; no credentials in URL")
    result.add_argument("--ca-file", required=True)
    result.add_argument("--token-file", help="Owner-only bearer-token file; no direct token argument")
    result.add_argument("--namespace", default="")
    result.add_argument("--timeout", type=float, default=15.0)
    result.add_argument("--output", required=True, help="New response JSON file in an owner-only directory")
    result.add_argument("--allow-write", action="store_true", help="Explicitly admit a mutating command")
    commands = result.add_subparsers(dest="command", required=True, parser_class=SafeArgumentParser)
    for name in ("read", "list", "delete"):
        command = commands.add_parser(name)
        command.add_argument("path", help="Canonical API path without /v1/")
        if name == "read":
            command.add_argument("--wrap-ttl")
    command = commands.add_parser("write")
    command.add_argument("path")
    command.add_argument("--input", required=True, help="Private JSON file or - for piped JSON")
    command.add_argument("--wrap-ttl")
    command = commands.add_parser("capabilities")
    command.add_argument("paths", nargs="+")
    selectors = command.add_mutually_exclusive_group()
    selectors.add_argument("--target-token-file")
    selectors.add_argument("--accessor-file")
    command = commands.add_parser("wrap")
    command.add_argument("--input", required=True)
    command.add_argument("--ttl", required=True)
    for name in ("unwrap", "rewrap", "wrapping-lookup"):
        commands.add_parser(name).add_argument("--wrapping-token-file", required=True)
    return result


def prepare(args):
    if args.command in ("write", "delete", "wrap", "unwrap", "rewrap") or getattr(args, "wrap_ttl", None):
        if not args.allow_write:
            raise BaoError("explicit_write_admission_required")
    output_preflight(args.output)
    bearer = token_file(args.token_file) if args.token_file else None
    payload = None
    ttl = getattr(args, "wrap_ttl", None)
    if args.command in ("read", "list", "write", "delete"):
        path = key_path(args.path)
        method = {"read": "GET", "list": "LIST", "write": "POST", "delete": "DELETE"}[args.command]
        if args.command == "write":
            payload = input_object(args.input)
    elif args.command == "capabilities":
        if not 1 <= len(args.paths) <= 64 or len(set(args.paths)) != len(args.paths):
            raise BaoError("invalid_capability_paths")
        payload = {"paths": [key_path(path) for path in args.paths]}
        method, path = "POST", "sys/capabilities-self"
        if args.target_token_file:
            payload["token"] = token_file(args.target_token_file)
            path = "sys/capabilities"
        elif args.accessor_file:
            payload["accessor"] = token_file(args.accessor_file)
            path = "sys/capabilities-accessor"
    elif args.command == "wrap":
        method, path, payload, ttl = "POST", "sys/wrapping/wrap", input_object(args.input), args.ttl
    else:
        wrapped = token_file(args.wrapping_token_file)
        method, payload = "POST", {}
        if args.command == "rewrap":
            path, payload = "sys/wrapping/rewrap", {"token": wrapped}
        else:
            # Possession, not a root credential, authenticates self unwrap/lookup.
            if bearer is not None:
                raise BaoError("self_wrapping_command_does_not_take_a_second_token")
            bearer = wrapped
            path = "sys/wrapping/unwrap" if args.command == "unwrap" else "sys/wrapping/lookup"
    if bearer is None:
        raise BaoError("token_file_required")
    client = Client(args.address, args.ca_file, bearer, args.namespace, args.timeout)
    return client, method, "/v1/"+path, payload, ttl


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    dispatched, received = False, False
    try:
        client, method, path, payload, ttl = prepare(args)
        dispatched = True
        response = client.request(method, path, payload, wrap_ttl=ttl)
        received = True
        private_write(args.output, response.body, replace=False)
        # No response body, credential, private path or secret digest in diagnostics.
        print(json.dumps({"status": "received", "http_status": response.status, "stored_privately": True}))
        return 0 if 200 <= response.status < 300 else 1
    except BaoError as error:
        code = error.code
    except Exception:
        code = "client_operation_failed"
    print(json.dumps({"status": "failed", "code": code, "request_attempted": dispatched,
                      "response_received": received, "automatic_retry": False}), file=sys.stderr)
    return 2
