"""Real local transport and private filesystem controls; no Bao/Cargo or real credentials."""
import time
_STARTED = time.monotonic()
import hashlib
import http.server
import importlib.util
import json
import os
import pathlib
import signal
import sys
import threading
import types
import unittest.mock

BASE = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = pathlib.Path(sys.argv[1])
assert str(FIXTURE).startswith("/data/") and not FIXTURE.exists()
FIXTURE.mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location("owned_cli", BASE / "tools/migration/openbao270_kv2_migrate.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
checks = []
counts = {"slow": 0, "redirect": 0, "forbidden": 0}
def bounded():
    assert time.monotonic() - _STARTED < 30
def record(name):
    bounded()
    checks.append(name)
def private_write(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path == "/v1/slow":
            counts["slow"] += 1
            body = b'{"data":{"ok":true}}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.4)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif self.path == "/v1/redirect":
            counts["redirect"] += 1
            self.send_response(302)
            self.send_header("Location", "/v1/forbidden")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/v1/forbidden":
            counts["forbidden"] += 1
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        # A migration write must never be reached by these negative controls.
        counts["post"] = counts.get("post", 0) + 1
        self.send_response(500)
        self.end_headers()

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
origin = "http://127.0.0.1:" + str(server.server_port)
try:
    client = cli.Client(origin, "synthetic-never-real", end=time.monotonic() + 20)
    started = time.monotonic()
    try:
        client.request("GET", "slow")
        raise AssertionError("slow drip unexpectedly completed")
    except cli.DecodeError as error:
        assert str(error) == "migration HTTP absolute request deadline exceeded; no retry performed"
    elapsed = time.monotonic() - started
    assert 4.9 <= elapsed < 6
    life = client.last_request_lifecycle
    assert life["original_popen"] is True and life["planned_signal"] == signal.SIGTERM
    assert life["returncode"] == -signal.SIGTERM and life["original_wait_completed"] is True
    assert counts["slow"] == 1 and counts.get("post", 0) == 0
    record("real slow-drip response stopped by original HTTP Popen deadline under 6 seconds")

    try:
        client.request("GET", "redirect")
        raise AssertionError("redirect unexpectedly followed")
    except cli.DecodeError as error:
        assert str(error) == "migration HTTP failed; no retry performed"
    assert counts["redirect"] == 1 and counts["forbidden"] == 0
    assert client.last_request_lifecycle["returncode"] == 1
    assert client.last_request_lifecycle["original_wait_completed"] is True
    record("real HTTP redirect refused without target request")

    insecure = FIXTURE / "insecure-token"
    private_write(insecure, b"synthetic-never-real", 0o644)
    try:
        cli.private_read(insecure, 65536)
        raise AssertionError("public token file accepted")
    except cli.DecodeError:
        pass
    original = FIXTURE / "private-token"
    private_write(original, b"synthetic-never-real")
    link = FIXTURE / "token-link"
    os.symlink(original, link)
    try:
        cli.private_read(link, 65536)
        raise AssertionError("symlink token accepted")
    except OSError:
        pass
    record("private file modes and no-follow token custody enforced")

    fifo = FIXTURE / "blocked-token-fifo"
    os.mkfifo(fifo, 0o600)
    output = FIXTURE / "blocked-output"
    started = time.monotonic()
    try:
        cli.supervise(["export", "--address", origin, "--token-file", str(fifo),
                       "--mount", "kv", "--output", str(output)],
                      end=time.monotonic() + 0.3)
        raise AssertionError("blocked input escaped overall deadline")
    except cli.DecodeError as error:
        assert str(error) == "migration original absolute deadline exceeded"
    assert time.monotonic() - started < 2
    assert not output.exists()
    life = cli.supervise.last_lifecycle
    assert life["planned_signal"] == signal.SIGTERM and life["returncode"] == -signal.SIGTERM
    assert life["original_wait_completed"] is True
    try:
        os.killpg(life["pgid"], 0)
        raise AssertionError("original worker group remains")
    except ProcessLookupError:
        pass
    record("real blocked credential open terminated by original overall session deadline")

    expired = FIXTURE / "expired-output"
    try:
        cli.exclusive_output(expired, b"bounded", end=time.monotonic() - 1)
        raise AssertionError("expired output created")
    except cli.DecodeError:
        pass
    assert not expired.exists()
    sequence = iter([0, 0, 2])
    with unittest.mock.patch.object(cli, "time", types.SimpleNamespace(monotonic=lambda: next(sequence))):
        try:
            cli.exclusive_output(expired, b"bounded", end=1)
            raise AssertionError("post-write expired output published")
        except cli.DecodeError:
            pass
    assert not expired.exists() and not list(FIXTURE.glob(".kv2-migration-*"))
    record("output deadline checked before creation and after real staging/fsync before publication")

    destination = FIXTURE / "existing-output"
    private_write(destination, b"preserved")
    try:
        cli.exclusive_output(destination, b"replacement", end=time.monotonic() + 2)
        raise AssertionError("existing output overwritten")
    except FileExistsError:
        pass
    assert destination.read_bytes() == b"preserved"
    assert not list(FIXTURE.glob(".kv2-migration-*"))
    record("exclusive publication preserves existing destination and removes staging")

    destination = FIXTURE / "completed-output"
    cli.exclusive_output(destination, b"bounded", end=time.monotonic() + 2)
    assert destination.read_bytes() == b"bounded"
    st = destination.stat()
    assert st.st_mode & 0o777 == 0o600 and st.st_nlink == 1
    record("successful exclusive output has exact bytes, private mode and one link")
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)
    assert not thread.is_alive()
    bounded()
    closure = {"controls": checks, "checks_completed": len(checks), "qualified": False,
               "scope": "CLI-local transport/lifecycle tests only; no real migration or decoder requalification",
               "elapsed_seconds": time.monotonic() - _STARTED,
               "counts": counts, "http_original_lifecycle": client.last_request_lifecycle,
               "supervisor_original_lifecycle": getattr(cli.supervise, "last_lifecycle", None),
               "server_thread_joined": not thread.is_alive()}
    private_write(FIXTURE / "controls-and-closure.original.json",
                  (json.dumps(closure, indent=2) + "\n").encode("utf-8"))
print(json.dumps({"controls": len(checks), "elapsed_seconds": closure["elapsed_seconds"],
                  "fixture": str(FIXTURE), "qualified": False}))
