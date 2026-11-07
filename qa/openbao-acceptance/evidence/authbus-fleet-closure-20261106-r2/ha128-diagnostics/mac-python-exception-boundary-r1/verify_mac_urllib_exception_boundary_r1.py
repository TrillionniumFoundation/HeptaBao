"""Pure local exception-boundary checks against the complete actual Mac source.

No network, subprocess, product service, private file, or deadline change.
Injected failures only verify the public Python wrapper; they do not recreate
the original HA failure or establish its missing underlying reason.
"""
import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError
from urllib.request import Request

ROOT = Path(__file__).resolve().parent / "ha128-r3-log-review"
SOURCE = ROOT / "urllib_request.actual_mac_public.py"
PIN = "7465dbf037295f8f04774c453ab84c31879999c507fa16a82627ce9bd9615992"


def main():
    raw = SOURCE.read_bytes()
    assert len(raw) == 77037 and hashlib.sha256(raw).hexdigest() == PIN
    tree = ast.parse(raw.decode())
    cls, = [x for x in tree.body if isinstance(x, ast.ClassDef)
            and x.name == "AbstractHTTPHandler"]
    method, = [x for x in cls.body if isinstance(x, ast.FunctionDef)
               and x.name == "do_open"]
    scope = {"URLError": URLError}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(SOURCE), "exec"), scope)
    do_open = scope["do_open"]
    rows = []
    for phase, failure, expected in [
        ("request", TimeoutError, "URLError"),
        ("request", ConnectionResetError, "URLError"),
        ("response_headers", TimeoutError, "TimeoutError"),
        ("response_body", TimeoutError, "TimeoutError"),
        ("success", None, "success"),
    ]:
        calls = {"request": 0, "getresponse": 0, "read": 0, "close": 0}

        class Response:
            reason = "fixture"

            def read(self):
                calls["read"] += 1
                if phase == "response_body":
                    raise failure("synthetic")
                return b"{}"

        class Connection:
            sock = None

            def __init__(self, host, **kwargs):
                assert host == "127.0.0.1:31040" and kwargs == {"timeout": 15}

            def set_debuglevel(self, value):
                assert value == 0

            def request(self, *args, **kwargs):
                calls["request"] += 1
                if phase == "request":
                    raise failure("synthetic")

            def getresponse(self):
                calls["getresponse"] += 1
                if phase == "response_headers":
                    raise failure("synthetic")
                return Response()

            def close(self):
                calls["close"] += 1

        req = Request("https://127.0.0.1:31040/v1/secret/data/fixture?version=12")
        req.timeout = 15
        actual = "success"
        reason_type = None
        try:
            response = do_open(SimpleNamespace(_debuglevel=0), Connection, req)
            assert response.read() == b"{}"
        except Exception as exc:
            actual = type(exc).__name__
            if isinstance(exc, URLError):
                reason_type = type(exc.reason).__name__
        assert actual == expected
        assert calls["request"] == 1
        assert calls["getresponse"] == (0 if phase == "request" else 1)
        assert calls["close"] == (1 if phase in ("request", "response_headers") else 0)
        if phase == "request":
            assert reason_type == failure.__name__
        rows.append({"injectedPhase": phase, "observedExceptionType": actual,
                     "wrappedReasonType": reason_type, "calls": calls, "passed": True})
    print(json.dumps({
        "schema": "heptabao.actual-mac-urllib-boundary.synthetic.v1",
        "sourceBytes": len(raw), "sourceSha256": PIN,
        "sourceMethodLines": [method.lineno, method.end_lineno],
        "passed": len(rows), "required": 5, "cases": rows,
        "actualHAReproduction": False, "underlyingHAReasonRecovered": False,
        "networkCalls": 0, "children": 0, "productExecutions": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
