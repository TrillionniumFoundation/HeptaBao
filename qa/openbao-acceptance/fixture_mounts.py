"""Explicit prerequisites for fresh synthetic acceptance instances.

Initialization creates the standard system mounts. A fixture that uses KV or
Transit provisions that engine itself before business or fault operations.
These setup mutations are submitted once, with the caller's existing budget.
"""


def _provision(call, path, body, *, error_type, request_options):
    status, _ = call("POST", "sys/mounts/" + path, body, **request_options)
    if type(status) is not int or status != 204:
        raise error_type("fixture_" + path + "_mount_setup_failed")
    return {"mount": path, "http_status": status, "mutations_submitted": 1,
            "automatic_retry": False}


def provision_secret_kv2(call, *, error_type=RuntimeError, **request_options):
    return _provision(call, "secret", {"type": "kv", "options": {"version": "2"}},
                      error_type=error_type, request_options=request_options)


def provision_transit(call, *, error_type=RuntimeError, **request_options):
    return _provision(call, "transit", {"type": "transit"},
                      error_type=error_type, request_options=request_options)
