"""Executable OpenBao-style KV commands over the shared strict HTTPS Client.

Command output is the caller's requested secret data. Never log argv, environment,
response bodies or stdout as evidence. Error diagnostics contain only fixed codes.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
from urllib.parse import unquote

from .transport import (BaoError, Client, Response, SafeArgumentParser, canonical,
                        decode_json, endpoint, key_path, private_read)

INPUT_LIMIT = 256 * 1024


class Parser(SafeArgumentParser):
    def error(self, message):
        self.exit(1, "invalid command line; use --help\n")


def _env(name: str, default=None):
    return os.environ.get("BAO_" + name) or os.environ.get("VAULT_" + name) or default


def _boolean(value: str) -> bool:
    if value not in ("true", "false"):
        raise ValueError("boolean")
    return value == "true"


def _duration(value: str) -> float:
    # The shared Client retains its finite 60-second per-socket maximum.
    matched = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m)?", value)
    if not matched:
        raise BaoError("invalid_timeout")
    number = float(matched[1]) * {None: 1, "ms": .001, "s": 1, "m": 60}[matched[2]]
    if not math.isfinite(number) or not 0 < number <= 60:
        raise BaoError("invalid_timeout")
    return number


def _common(command: Parser, *, field: bool = True, formatted: bool = True, mounted: bool = True):
    command.add_argument("-address", "--address")
    command.add_argument("-ca-cert", "--ca-file", dest="ca_file")
    command.add_argument("-token-file", "--token-file")
    command.add_argument("-namespace", "--namespace")
    command.add_argument("-timeout", "--timeout")
    if formatted:
        command.add_argument("-format", "--format", choices=("table", "json", "yaml"))
    else:
        command.set_defaults(format="table")
    if field:
        command.add_argument("-field", "--field", default="")
    else:
        command.set_defaults(field="")
    if mounted:
        command.add_argument("-mount", "--mount", default="")
    else:
        command.set_defaults(mount="")


def parser() -> Parser:
    result = Parser(prog="heptabao kv", description=__doc__)
    commands = result.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("get", "put", "patch", "list", "delete", "undelete", "destroy", "rollback"):
        command = commands.add_parser(name)
        _common(command, field=name in ("get", "put", "patch", "delete"))
        if name in ("get", "rollback"):
            command.add_argument("-version", "--version", type=int, default=0)
        if name in ("put", "patch"):
            command.add_argument("-cas", "--cas", type=int, default=-1)
        if name == "patch":
            command.add_argument("-method", "--method", choices=("patch", "rw"))
            command.add_argument("-remove-data", "--remove-data", action="append", default=[])
        if name in ("delete", "undelete", "destroy"):
            command.add_argument("-versions", "--versions", action="append", default=[])
        command.add_argument("path")
        if name in ("put", "patch"):
            command.add_argument("data", nargs="+" if name == "put" else "*")
    enable = commands.add_parser("enable-versioning")
    _common(enable, field=False, mounted=False)
    enable.add_argument("path")
    metadata = commands.add_parser("metadata")
    actions = metadata.add_subparsers(dest="metadata_command", required=True, parser_class=Parser)
    for name in ("get", "put", "delete"):
        command = actions.add_parser(name)
        _common(command, field=False, formatted=name != "delete")
        command.add_argument("path")
        if name == "put":
            command.add_argument("-max-versions", "--max-versions", type=int)
            command.add_argument("-cas-required", "--cas-required", type=_boolean)
            command.add_argument("-delete-version-after", "--delete-version-after")
            command.add_argument("-custom-metadata", "--custom-metadata", action="append", default=[])
    return result


def _arguments(argv: list[str]) -> list[str]:
    # Go-style boolean flags don't consume the following positional path.
    result = []
    for value in argv:
        if value in ("-cas-required", "--cas-required"):
            result.append(value + "=true")
        else:
            result.append(value)
    return result


def _stdin() -> bytes:
    if sys.stdin.isatty():
        raise BaoError("piped_input_required")
    value = sys.stdin.buffer.read(INPUT_LIMIT + 1)
    if len(value) > INPUT_LIMIT:
        raise BaoError("input_size_limit")
    return value


def input_data(arguments: list[str]) -> dict:
    """Read all input before mount discovery; never echo invalid payloads."""
    result = {}
    stdin = None
    for argument in arguments:
        if argument == "-" or argument.startswith("@") and "=" not in argument:
            if argument == "-":
                if stdin is None:
                    stdin = _stdin()
                raw = stdin
            else:
                raw = private_read(argument[1:], INPUT_LIMIT)
            value = decode_json(raw)
            if not isinstance(value, dict):
                raise BaoError("input_object_required")
            result.update(value)
            continue
        key, separator, value = argument.partition("=")
        if not separator or not key:
            raise BaoError("key_value_input_required")
        if value == "-":
            if stdin is None:
                stdin = _stdin()
            raw = stdin
        elif value.startswith("@"):
            raw = private_read(value[1:], INPUT_LIMIT)
        else:
            result[key] = value
            continue
        try:
            result[key] = raw.decode("utf-8")
        except UnicodeError:
            raise BaoError("input_requires_utf8") from None
    if len(canonical(result)) > INPUT_LIMIT:
        raise BaoError("input_size_limit")
    return result


class ApiFailure(Exception):
    def __init__(self, status: int):
        self.status = status


def _request(client: Client, method: str, path: str, payload=None, *, allow_empty_version: bool = False, **kwargs) -> Response:
    response = client.request(method, "/v1/" + path, payload, **kwargs)
    if not 200 <= response.status < 300:
        data = response.body.get("data")
        metadata = data.get("metadata") if isinstance(data, dict) else None
        empty_version = (allow_empty_version and method == "GET" and response.status == 404
                         and isinstance(data, dict) and data.get("data") is None
                         and isinstance(metadata, dict) and type(metadata.get("version")) is int
                         and metadata["version"] > 0 and type(metadata.get("destroyed")) is bool)
        if not empty_version:
            raise ApiFailure(response.status)
    return response


def _versions(arguments: list[str]) -> list[int]:
    result = []
    for argument in arguments:
        for value in argument.split(","):
            if not re.fullmatch(r"[0-9]+", value) or not 0 < int(value) <= 2**64 - 1:
                raise BaoError("invalid_versions")
            result.append(int(value))
    if len(result) > 256:
        raise BaoError("invalid_versions")
    return result


def _local(args):
    # Reject malformed paths/options before even the read-only preflight request.
    path = args.path
    if args.command in ("list", "enable-versioning"):
        path = path.removesuffix("/")
    path = unquote(key_path(path, allow_empty=args.command == "list" and bool(args.mount)))
    mount = unquote(key_path(args.mount)) if args.mount else ""
    if hasattr(args, "cas") and not -1 <= args.cas <= 2**64 - 1:
        raise BaoError("invalid_cas")
    if hasattr(args, "version") and not 0 <= args.version <= 2**64 - 1:
        raise BaoError("invalid_version")
    if args.command == "rollback" and not args.version:
        raise BaoError("rollback_version_required")
    versions = _versions(getattr(args, "versions", []))
    if args.command in ("undelete", "destroy") and not versions:
        raise BaoError("versions_required")
    payload = input_data(args.data) if args.command in ("put", "patch") else None
    if args.command == "patch":
        if not args.data and not args.remove_data:
            raise BaoError("patch_data_required")
        if any(not key for key in args.remove_data):
            raise BaoError("invalid_remove_data")
    if args.command == "metadata" and args.metadata_command == "put":
        if args.max_versions is not None and not 0 <= args.max_versions <= 2**64 - 1:
            raise BaoError("invalid_max_versions")
        payload = {}
        for name in ("max_versions", "cas_required", "delete_version_after"):
            if getattr(args, name) is not None:
                payload[name] = getattr(args, name)
        custom = {}
        for item in args.custom_metadata:
            key, sep, value = item.partition("=")
            if not sep or not key:
                raise BaoError("invalid_custom_metadata")
            custom[key] = value
        if custom:
            payload["custom_metadata"] = custom
    fmt = args.format if args.format is not None else _env("FORMAT", "table")
    if fmt not in ("table", "json", "yaml"):
        raise BaoError("invalid_format")
    address = args.address if args.address is not None else _env("ADDR")
    ca = args.ca_file if args.ca_file is not None else _env("CACERT")
    if not address or not ca:
        raise BaoError("endpoint_and_ca_required")
    endpoint(address)
    timeout = _duration(args.timeout if args.timeout is not None else _env("CLIENT_TIMEOUT", "60s"))
    namespace = args.namespace if args.namespace is not None else _env("NAMESPACE", "")
    # Validate namespace with the same transport rules before constructing TLS.
    if namespace.startswith("/") or "//" in namespace:
        raise BaoError("invalid_namespace")
    if namespace:
        key_path(namespace.removesuffix("/"))
    if args.token_file == "":
        raise BaoError("token_file_required")
    token_filename = args.token_file if args.token_file is not None else _env("TOKEN_FILE")
    token = None
    if not token_filename:
        token = _env("TOKEN")
        if not token:
            token_filename = _env("TOKEN_PATH")
    if token_filename:
        try:
            token = private_read(token_filename, 8192).decode("ascii").strip()
        except UnicodeError:
            raise BaoError("invalid_token_file") from None
    if not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise BaoError("token_file_or_environment_required")
    return path, mount, versions, payload, fmt, (address, ca, token, namespace, timeout)


def discover(client: Client, path: str, explicit: str) -> tuple[str, str, int]:
    requested = explicit + ("/" + path if path else "") if explicit else path
    response = _request(client, "GET", "sys/internal/ui/mounts/" + key_path(requested))
    data = response.data()
    mounted = data.get("path")
    options = data.get("options")
    if data.get("type") != "kv" or not isinstance(mounted, str) or not mounted.endswith("/"):
        raise BaoError("kv_mount_required")
    mounted = mounted[:-1]
    key_path(mounted)
    if requested != mounted and not requested.startswith(mounted + "/"):
        raise BaoError("mount_response_path_mismatch")
    if explicit and explicit != mounted:
        raise BaoError("mount_response_path_mismatch")
    version = (options or {}).get("version", "1") if isinstance(options, (dict, type(None))) else None
    if version not in ("1", "2"):
        raise BaoError("unsupported_kv_version")
    relative = path if explicit else requested[len(mounted):].removeprefix("/")
    return mounted, relative, int(version)


def _read_data(client: Client, path: str, version: int = 0) -> tuple[dict, int]:
    response = _request(client, "GET", path + ("?version=" + str(version) if version else ""))
    data = response.data()
    metadata = data.get("metadata")
    value = data.get("data")
    current = metadata.get("version") if isinstance(metadata, dict) else None
    if not isinstance(value, dict) or type(current) is not int or current <= 0:
        raise BaoError("kv_response_data_required")
    return value, current


def execute(client: Client, args, path: str, mount: str, versions: list[int], payload) -> tuple[Response, str, int]:
    if args.command == "enable-versioning":
        response = _request(client, "POST", "sys/mounts/" + key_path(path) + "/tune", {"options": {"version": "2"}})
        return response, path + "/", 2
    mounted, relative, version = discover(client, path, mount)
    if not relative and args.command != "list":
        raise BaoError("secret_path_required")
    if version == 1 and (args.command in ("patch", "undelete", "destroy", "metadata", "rollback")
                         or versions or getattr(args, "version", 0) or getattr(args, "cas", -1) != -1):
        raise BaoError("kv_v2_required")
    prefix = key_path(mounted) + "/"
    suffix = key_path(relative, allow_empty=args.command == "list")
    data_path = prefix + ("data/" if version == 2 else "") + suffix
    if args.command == "get":
        response = _request(client, "GET", data_path + ("?version=" + str(args.version) if args.version else ""),
                            allow_empty_version=version == 2 and not args.field)
    elif args.command == "list":
        response = _request(client, "LIST", prefix + ("metadata/" if version == 2 else "") + suffix)
    elif args.command == "metadata":
        response = _request(client, {"get": "GET", "put": "POST", "delete": "DELETE"}[args.metadata_command],
                            prefix + "metadata/" + suffix, payload)
    elif args.command in ("delete", "undelete", "destroy"):
        if args.command == "delete" and not versions:
            response = _request(client, "DELETE", data_path)
        else:
            response = _request(client, "POST", prefix + args.command + "/" + suffix, {"versions": versions})
    elif args.command == "rollback":
        # Latest read anchors CAS. A selected historical version is never used as
        # the write CAS: concurrent changes must reject instead of being replaced.
        _, current = _read_data(client, data_path)
        old, _ = _read_data(client, data_path, args.version)
        response = _request(client, "POST", data_path, {"data": old, "options": {"cas": current}})
    else:
        content_type = "application/json"
        method = "POST"
        if version == 2:
            options = {"cas": args.cas} if args.cas >= 0 else {}
            if args.command == "patch":
                # The pinned 2.7 CLI treats PATCH CAS 0 as unset. PUT retains
                # CAS 0's create-only meaning; positive PATCH CAS stays exact.
                if args.cas == 0:
                    options = {}
                if args.method == "rw":
                    existing, current = _read_data(client, data_path)
                    existing.update(payload)
                    for key in args.remove_data:
                        existing.pop(key, None)
                    payload, options = existing, {"cas": current}
                else:
                    for key in args.remove_data:
                        payload[key] = None
                    method, content_type = "PATCH", "application/merge-patch+json"
            payload = {"data": payload}
            if options:
                payload["options"] = options
        try:
            response = _request(client, method, data_path, payload, content_type=content_type)
        except ApiFailure as error:
            if args.command != "patch" or args.method is not None or error.status != 403:
                raise
            # Documented default policy fallback is allowed only after a known
            # HTTP 403 refusal. A timeout, disconnect or 5xx is never replayed.
            existing, current = _read_data(client, data_path)
            existing.update(payload["data"])
            for key in args.remove_data:
                existing.pop(key, None)
            response = _request(client, "POST", data_path, {"data": existing, "options": {"cas": current}})
    return response, data_path, version


def _text(value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "<nil>"
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)


def _yaml(value, indent: int = 0) -> str:
    # JSON-quoted strings are YAML 1.2 scalars; quote all keys/strings so booleans,
    # tags and multiline values can't change the type or inject another document.
    pad = " " * indent
    if isinstance(value, dict) and value:
        result = []
        for key, item in value.items():
            nested = isinstance(item, (dict, list)) and bool(item)
            result.append(pad + json.dumps(key, ensure_ascii=False) + ":" +
                          ("\n" + _yaml(item, indent + 2) if nested else " " + json.dumps(item, ensure_ascii=False, allow_nan=False)))
        return "\n".join(result)
    if isinstance(value, list) and value:
        return "\n".join(pad + "-" + ("\n" + _yaml(item, indent + 2)
                                     if isinstance(item, (dict, list)) and item else
                                     " " + json.dumps(item, ensure_ascii=False, allow_nan=False)) for item in value)
    return pad + json.dumps(value, ensure_ascii=False, allow_nan=False)


def _table(title: str, value: dict) -> str:
    rows = [(key, _text(item)) for key, item in sorted(value.items())]
    width = max([3] + [len(key) for key, _ in rows])
    return title + "\n" + "Key".ljust(width) + "    Value\n" + "---".ljust(width) + "    -----\n" + \
        "\n".join(key.ljust(width) + "    " + item for key, item in rows)


def render(response: Response, args, fmt: str, data_path: str, version: int) -> str:
    if args.command == "enable-versioning":
        return "Success! Tuned the secrets engine at: " + data_path + "\n"
    data = response.body.get("data", {})
    selected = data.get("data") if args.command == "get" and version == 2 and isinstance(data, dict) else data
    if args.field:
        if not isinstance(selected, dict) or args.field not in selected:
            raise BaoError("field_not_found")
        value = selected[args.field]
        if fmt == "json":
            return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        if fmt == "yaml":
            return _yaml(value) + "\n"
        return _text(value)  # Table/raw field deliberately has no newline.
    if args.command == "list":
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
            raise BaoError("kv_listing_keys_required")
        if fmt == "table":
            return "Keys\n----\n" + "\n".join(keys) + "\n"
        value = keys
    else:
        value = response.body
    if fmt == "json":
        return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if fmt == "yaml":
        return _yaml(value) + "\n"
    if not data:
        return "Success!\n"
    if not isinstance(data, dict):
        raise BaoError("response_data_object_required")
    if args.command == "get" and version == 2:
        metadata = data.get("metadata")
        if not isinstance(metadata, dict) or selected is not None and not isinstance(selected, dict):
            raise BaoError("kv_response_data_required")
        text = "== Secret Path ==\n" + data_path + "\n\n" + _table("Metadata", metadata)
        if selected is not None:
            text += "\n\n" + _table("Data", selected)
        return text + "\n"
    if args.command == "metadata" and args.metadata_command == "get":
        metadata = dict(data)
        versions = metadata.pop("versions", {})
        if not isinstance(versions, dict):
            raise BaoError("kv_versions_object_required")
        text = _table("Metadata", metadata)
        for key, value in sorted(versions.items()):
            if not isinstance(value, dict):
                raise BaoError("kv_versions_object_required")
            text += "\n\n" + _table("Version " + key, value)
        return text + "\n"
    return _table("Data" if args.command == "get" else "Metadata", data) + "\n"


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(_arguments(list(sys.argv[1:] if argv is None else argv)))
    except SystemExit as error:
        return error.code
    attempted, received, remote = False, False, False
    try:
        path, mount, versions, payload, fmt, configuration = _local(args)
        remote = True
        client = Client(*configuration)
        attempted = True
        response, data_path, version = execute(client, args, path, mount, versions, payload)
        received = True
        text = render(response, args, fmt, data_path, version)
        sys.stdout.write(text)
        return 0
    except ApiFailure as error:
        received = True
        code, status = "api_error", error.status
    except BaoError as error:
        code, status = error.code, None
    except Exception:
        code, status = "client_operation_failed", None
    print(json.dumps({"status": "failed", "code": code, "http_status": status,
                      "request_attempted": attempted, "response_received": received,
                      "automatic_retry": False}), file=sys.stderr)
    # OpenBao's documented distinction: local misuse=1; remote/TLS/API failure=2.
    # A missing output field is local selection failure after a successful read.
    return 1 if not remote or code == "field_not_found" else 2
