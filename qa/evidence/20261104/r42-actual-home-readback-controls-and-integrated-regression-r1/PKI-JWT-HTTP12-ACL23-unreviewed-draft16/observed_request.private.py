def _observed_request(self, method: str, path: str, payload=None, *, token: str | None = None,
            wrap_ttl: str | None = None, content_type: str = "application/json",
            consistency_index: str | None = None, inconsistent=None,
            _record, _timeout) -> Response:
    try:
        metadata = Metadata(consistency_index, inconsistent)
    except InvalidConsistency as error:
        raise BaoError(str(error)) from None
    if method not in ("GET", "HEAD", "LIST", "POST", "PUT", "PATCH", "DELETE", "SCAN"):
        raise BaoError("invalid_request_method")
    if not path.startswith("/v1/") or len(path) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in path):
        raise BaoError("invalid_request_path")
    if token is not None and (not isinstance(token, str) or len(token) > 8192
                              or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise BaoError("invalid_token_input")
    if content_type not in ("application/json", "application/merge-patch+json"):
        raise BaoError("unsupported_content_type")
    headers = {"X-Vault-Token": self._token if token is None else token, "Accept": "application/json"}
    if wrap_ttl is not None:
        if (not isinstance(wrap_ttl, str) or not 1 <= len(wrap_ttl) <= 64
                or any(ord(c) < 33 or ord(c) > 126 for c in wrap_ttl)):
            raise BaoError("invalid_wrapping_ttl_header")
        headers["X-Vault-Wrap-TTL"] = wrap_ttl
    if self.namespace:
        headers["X-Vault-Namespace"] = self.namespace
    raw = None if payload is None else canonical(payload)
    if raw is not None:
        if len(raw) > MAX_BODY:
            raise BaoError("request_size_limit")
        headers["Content-Type"] = content_type
    request = urllib.request.Request(self.address + path, data=raw, headers=headers, method=method)
    if metadata.headers():
        request.heptabao_consistency = metadata
    phase = "open_response"
    _record["open_calls"] = 1
    try:
        try:
            response = self._opener.open(request, timeout=_timeout)
        except urllib.error.HTTPError as error:
            response = error
        phase = "response_context"
        with response:
            _record["context_entered"] = True
            phase = "response_metadata"
            status = response.code
            if type(status) is not int or not 100 <= status <= 599:
                raise BaoError("raw_status_shape")
            _record["status"] = status
            if 300 <= status < 400:
                raise BaoError("redirect_rejected")
            index, index_valid = response_index(response.headers)
            retry_seconds = retry_after(response.headers)
            phase = "read_response"
            _record["read_calls"] = 1
            body = response.read(MAX_BODY + 1)
            _record["body_bytes"] = len(body)
            _record["body_within_cap"] = len(body) <= MAX_BODY
            if _record["public_body"] and len(body) <= MAX_BODY:
                _record["body_sha256"] = hashlib.sha256(body).hexdigest()
            if len(body) > MAX_BODY:
                raise BaoError("response_size_limit")
            phase = "close_response"
        _record["context_closed"] = True
        phase = "process_response"
        decoded = decode_json(body) if body else {}
        if not isinstance(decoded, dict):
            raise BaoError("response_object_required")
        return Response(status, decoded, index, index_valid, retry_seconds)
    except BaoError:
        raise
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as error:
        # Never retry a write automatically. Even a timeout can follow a commit.
        raise BaoError("transport_outcome_unknown" if method not in ("GET", "LIST", "HEAD")
                       else "transport_read_failed",
                       _diagnostic=_transport_diagnostic(error, phase)) from None
