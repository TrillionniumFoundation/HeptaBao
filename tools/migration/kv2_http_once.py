"""One HTTP request only; private header/body arrive exclusively on anonymous stdin."""
import base64
import ipaddress
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_INPUT = 32 * 1024 * 1024
MAX_RESPONSE = 2 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect refused")

def main():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("input bound")
    packet = json.loads(raw)
    if not isinstance(packet, dict) or set(packet) != {"address", "headers", "ca_file", "method", "path", "body"}:
        raise ValueError("input framing")
    url = urllib.parse.urlsplit(packet["address"])
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("invalid origin")
    if url.scheme == "http" and not ipaddress.ip_address(url.hostname).is_loopback:
        raise ValueError("non-loopback cleartext")
    headers = packet["headers"]
    if not isinstance(headers, dict) or set(headers) not in (
            {"X-Vault-Token", "Content-Type"},
            {"X-Vault-Token", "Content-Type", "X-Vault-Namespace"}):
        raise ValueError("invalid headers")
    if any(not isinstance(v, str) or "\r" in v or "\n" in v for v in headers.values()):
        raise ValueError("invalid headers")
    body = None if packet["body"] is None else base64.b64decode(packet["body"], validate=True)
    if body is not None and len(body) > 16 * 1024 * 1024:
        raise ValueError("body bound")
    context = ssl.create_default_context(cafile=packet["ca_file"])
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect,
        urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(
        packet["address"].rstrip("/") + "/v1/" + packet["path"],
        data=body, headers=headers, method=packet["method"])
    try:
        with opener.open(request, timeout=5) as response:
            raw = response.read(MAX_RESPONSE + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        sys.stdout.buffer.write(json.dumps({"status": error.code}).encode("ascii") + b"\n")
        return
    if len(raw) > MAX_RESPONSE:
        raise ValueError("response bound")
    sys.stdout.buffer.write(json.dumps({"status": status}).encode("ascii") + b"\n" + raw)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Exception messages may include URLs or server data.
        sys.stderr.write("HTTP leaf failed\n")
        raise SystemExit(1)
