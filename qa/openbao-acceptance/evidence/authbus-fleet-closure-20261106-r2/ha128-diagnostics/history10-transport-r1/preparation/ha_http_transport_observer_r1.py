"""Observe the pinned original urllib API call without a second request.

Only the original HTTPSHandler constructor binding is replaced in a copy of
the source-bound API function AST. Original request creation, proxy/redirect
policy, timeout argument, response bound and parsing remain byte-code inputs.
The original exceptions propagate unchanged. No URL, header, body, identifier,
exception message, value or private digest enters the public trace.
"""
from __future__ import annotations

import ast
import contextvars
import copy
import functools
import hashlib
import http.client
import inspect
import re
import ssl
import time
import urllib.error
import urllib.request

CURRENT = contextvars.ContextVar("heptabao_one_original_http_observation", default=None)
METHODS = frozenset(("GET", "HEAD", "LIST", "POST", "PUT", "DELETE"))
ERROR_CLASSES = frozenset((
    "URLError", "TimeoutError", "ConnectionRefusedError", "ConnectionResetError",
    "ConnectionAbortedError", "BrokenPipeError", "OSError", "SSLError",
    "SSLCertVerificationError", "SSLZeroReturnError", "SSLEOFError",
    "RemoteDisconnected", "BadStatusLine", "IncompleteRead", "HTTPError",
    "FixtureError", "JSONDecodeError", "Refused", "KeyboardInterrupt", "SystemExit",
))


class ObserverRefusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise ObserverRefusal(code)


def safe_error(error):
    result = {"class": type(error).__name__ if type(error).__name__ in ERROR_CLASSES else "OtherException"}
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    result["reasonClass"] = type(reason).__name__ if type(reason).__name__ in ERROR_CLASSES else "OtherReason"
    code = getattr(reason, "errno", None)
    if type(code) is int and -(2**31) <= code < 2**31:
        result["errno"] = code
    verify = getattr(reason, "verify_code", None)
    if type(verify) is int and 0 <= verify < 2**31:
        result["verifyCode"] = verify
    ssl_reason = getattr(reason, "reason", None)
    if isinstance(reason, ssl.SSLError) and isinstance(ssl_reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", ssl_reason):
        result["sslReason"] = ssl_reason
    return result


class Observation:
    def __init__(self, ordinal, node, method, timeout):
        self.started = time.monotonic()
        self.row = {"ordinal": ordinal, "node": node, "method": method,
                    "originalTimeoutSeconds": timeout, "phase": "api_enter",
                    "tcpConnected": False, "tlsConnected": False,
                    "connectionObjects": 0, "tcpConnectCalls": 0,
                    "httpsConnectCalls": 0, "sendCalls": 0,
                    "getresponseCalls": 0, "responseReadCalls": 0,
                    "responseCloseCalls": 0, "connectionCloseCalls": 0,
                    "bodyReadReturned": False, "apiReturned": False,
                    "automaticRetry": False, "events": []}

    def phase(self, label):
        need(len(self.row["events"]) < 64, "bounded_original_trace_events")
        self.row["phase"] = label
        self.row["events"].append({"phase": label,
                                   "elapsedMs": round((time.monotonic() - self.started) * 1000, 6)})


class ObservedConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        self.observation = CURRENT.get()
        need(isinstance(self.observation, Observation), "original_api_observation_required")
        super().__init__(*args, **kwargs)
        row = self.observation.row
        row["connectionObjects"] += 1
        need(row["connectionObjects"] == 1, "one_original_connection_object")
        original_create = self._create_connection

        def observed_create(*args, **kwargs):
            row["tcpConnectCalls"] += 1
            need(row["tcpConnectCalls"] == 1, "one_original_tcp_connect_call")
            self.observation.phase("tcp_connect")
            endpoint = original_create(*args, **kwargs)
            row["tcpConnected"] = True
            self.observation.phase("after_tcp_before_tls_complete")
            return endpoint

        self._create_connection = observed_create

    def connect(self):
        self.observation.row["httpsConnectCalls"] += 1
        need(self.observation.row["httpsConnectCalls"] == 1, "one_original_https_connect_call")
        result = super().connect()
        self.observation.row["tlsConnected"] = True
        self.observation.phase("request_send")
        return result

    def send(self, *args, **kwargs):
        self.observation.row["sendCalls"] += 1
        if self.observation.row["tlsConnected"]:
            self.observation.phase("request_send")
        result = super().send(*args, **kwargs)
        self.observation.phase("request_send_returned")
        return result

    def getresponse(self, *args, **kwargs):
        row = self.observation.row
        row["getresponseCalls"] += 1
        need(row["getresponseCalls"] == 1, "one_original_getresponse_call")
        self.observation.phase("response_headers")
        response = super().getresponse(*args, **kwargs)
        self.observation.phase("response_headers_returned")
        need(type(response.status) is int and 100 <= response.status <= 599, "original_http_status")
        row["status"] = response.status
        original_read, original_close = response.read, response.close

        def observed_read(*args, **kwargs):
            row["responseReadCalls"] += 1
            self.observation.phase("response_body")
            value = original_read(*args, **kwargs)
            row["bodyReadReturned"] = True
            self.observation.phase("response_body_returned")
            return value

        def observed_close(*args, **kwargs):
            row["responseCloseCalls"] += 1
            response.read, response.close = original_read, original_close
            return original_close(*args, **kwargs)

        response.read, response.close = observed_read, observed_close
        return response

    def close(self):
        self.observation.row["connectionCloseCalls"] += 1
        return super().close()


class ObservedHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        # This is the same AbstractHTTPHandler.do_open and the identical context.
        # No caller, context flag, hostname, proxy, timeout or request is altered.
        return self.do_open(ObservedConnection, req, context=self._context)


def bind_original_api(original, rows):
    """Caller pins the complete original QA source before this local binding."""
    need(isinstance(rows, list) and not rows, "new_bounded_trace_list")
    source = inspect.getsource(original)
    parsed = ast.parse(source)
    need(len(parsed.body) == 1 and isinstance(parsed.body[0], ast.FunctionDef)
         and parsed.body[0].name == "api", "exact_original_api_function")
    changed = copy.deepcopy(parsed)
    replacements = 0
    for node in ast.walk(changed):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "HTTPSHandler"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "request"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "urllib"):
            need(not node.args and len(node.keywords) == 1
                 and node.keywords[0].arg == "context"
                 and isinstance(node.keywords[0].value, ast.Name)
                 and node.keywords[0].value.id == "context", "original_handler_context")
            node.func = ast.copy_location(ast.Name(id="_BOUND_OBSERVED_HANDLER", ctx=ast.Load()), node.func)
            replacements += 1
    need(replacements == 1, "exact_one_handler_binding")
    ast.fix_missing_locations(changed)
    namespace = dict(original.__globals__)
    namespace["_BOUND_OBSERVED_HANDLER"] = ObservedHandler
    exec(compile(changed, original.__code__.co_filename, "exec"), namespace)
    inner = namespace["api"]

    @functools.wraps(original)
    def observed(context, node, method, path, body=None, token="", timeout=8.0, *, wrap_ttl=None):
        need(len(rows) < 512 and CURRENT.get() is None, "bounded_non_nested_api_observation")
        need(type(node.node_id) is int and node.node_id in (1, 2, 3)
             and method in METHODS and type(timeout) in (int, float) and 0 < timeout <= 15,
             "original_fixed_api_scope")
        observation = Observation(len(rows) + 1, node.node_id, method, timeout)
        rows.append(observation.row)
        owner = CURRENT.set(observation)
        try:
            result = inner(context, node, method, path, body, token, timeout, wrap_ttl=wrap_ttl)
            observation.row["apiReturned"] = True
            observation.phase("api_returned")
            return result
        except BaseException as error:
            observation.row["error"] = safe_error(error)
            raise
        finally:
            observation.row["elapsedMs"] = round((time.monotonic() - observation.started) * 1000, 6)
            CURRENT.reset(owner)

    observed.original_source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    observed.binding_changes = {"httpsHandlerConstructorReplacements": replacements,
                                "originalRequestsDelegatedOnce": True,
                                "originalExceptionsReraised": True,
                                "tlsContextChanged": False, "timeoutsChanged": False}
    return observed
