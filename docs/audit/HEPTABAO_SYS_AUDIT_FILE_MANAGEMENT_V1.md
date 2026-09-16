# HeptaBao `sys/audit` file management profile

The current server exposes a bounded OpenBao-compatible management surface
for its mandatory authenticated file audit device:

* `GET /v1/sys/audit` lists the process-owned `file/` device;
* `GET /v1/sys/audit/file` returns its type, fixed path and rotation bounds;
* `PUT`/`POST /v1/sys/audit/file` accepts an idempotent `type=file` binding
  when `options.file_path` matches the path selected at process startup.

The route requires the root namespace and a root principal. The audit writer,
HMAC chain and rotation lock remain live for every request. Therefore `DELETE`
is rejected and a different path or device type is rejected; allowing either
would create an unaudited interval. HTTP, socket and syslog devices are still
unsupported and remain outside the compatibility claim.

The executable fixture `qa/openbao-acceptance/audit_file_live.py` covers list,
path binding, detail read, idempotent enable and fail-closed disable. This is a
bounded implementation fixture, not independent OpenBao compatibility or
production qualification evidence.
