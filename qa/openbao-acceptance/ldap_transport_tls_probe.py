"""One actual TLS peer with a trusted chain and deliberately mismatching SAN.

This peer never implements LDAP. Evidence includes handshake completion so a
later LDAP failure cannot be misreported as certificate-name verification.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import threading
import time

from core_isolation import ScenarioFailure
from official_openbao_launcher import private_text, oracle_environment


WRONG_DNS_NAME = "wrong-ldap.invalid"


def san_rejection_observed(evidence):
    return (set(evidence) == {"handshake_attempted", "handshake_completed", "application_bytes_seen"}
            and all(type(value) is bool for value in evidence.values())
            and evidence["handshake_attempted"]
            and not evidence["handshake_completed"]
            and not evidence["application_bytes_seen"])


class WrongSanProbe:
    def __init__(self, root: Path, ca_cert: Path, ca_key: Path, *, csr=None, tls_key=None):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        ca_cert, ca_key = Path(ca_cert), Path(ca_key)
        csr = Path(csr) if csr is not None else ca_cert.parent / "tls.csr"
        tls_key = Path(tls_key) if tls_key is not None else ca_cert.parent / "tls.key"
        private_text(self.root / "wrong-san.ext",
                     "basicConstraints=critical,CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment\n"
                     "extendedKeyUsage=serverAuth\n"
                     "subjectAltName=DNS:" + WRONG_DNS_NAME + "\n")
        # Reuse the fixture's CSR/key but do not mutate its CA serial file: the
        # oracle and candidate probes may be set up independently.
        try:
            subprocess.run([
                "openssl", "x509", "-req", "-in", str(csr),
                "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-set_serial", "0x" + secrets.token_hex(16),
                "-out", str(self.root / "wrong-san.crt"), "-days", "2", "-sha256",
                "-extfile", str(self.root / "wrong-san.ext"),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
               timeout=10, env=oracle_environment(self.root))
            (self.root / "wrong-san.crt").chmod(0o600)
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.load_cert_chain(str(self.root / "wrong-san.crt"), str(tls_key))
        except (OSError, subprocess.SubprocessError, ssl.SSLError):
            raise ScenarioFailure("ldap_native.transport.san_probe_setup_failed") from None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._done = threading.Event()
        self._connection = None
        self._attempted = self._completed = self._application = False
        self._failed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.1)
        self.origin = "ldaps://127.0.0.1:" + str(self._listener.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, name="ldap-wrong-san", daemon=True)
        try:
            self._thread.start()
        except RuntimeError:
            self._listener.close()
            raise ScenarioFailure("ldap_native.transport.san_probe_start_failed") from None

    def _serve(self):
        connection = None
        try:
            deadline = time.monotonic() + 10
            while not self._stop.is_set() and time.monotonic() < deadline:
                try:
                    connection, _ = self._listener.accept()
                    break
                except socket.timeout:
                    continue
            if connection is None:
                return
            with self._lock:
                self._connection = connection
            connection.settimeout(2)
            # Do not count a plain TCP connect or an HTTP request as a TLS
            # attempt. Peeking does not consume the TLS record from OpenSSL.
            if connection.recv(1, socket.MSG_PEEK) != b"\x16":
                return
            with self._lock:
                self._attempted = True
            connection = self.context.wrap_socket(connection, server_side=True,
                                                  do_handshake_on_connect=False)
            with self._lock:
                self._connection = connection
            connection.do_handshake()
            with self._lock:
                self._completed = True
            # Inspect at most one decrypted byte, never retain or reflect it.
            application = bool(connection.recv(1))
            with self._lock:
                self._application = application
        except (ssl.SSLError, socket.timeout, ConnectionError):
            # Expected for a client rejecting this leaf's SAN. The caller also
            # verifies its HTTP status and that the handshake did not complete.
            pass
        except OSError:
            if not self._stop.is_set():
                with self._lock:
                    self._failed = True
        except Exception:
            with self._lock:
                self._failed = True
        finally:
            if connection is not None:
                connection.close()
            with self._lock:
                self._connection = None
            self._done.set()

    def wait(self, timeout=3):
        if not self._done.wait(timeout):
            raise ScenarioFailure("ldap_native.transport.san_probe_timeout")
        with self._lock:
            if self._failed:
                raise ScenarioFailure("ldap_native.transport.san_probe_failed")
            return {"handshake_attempted": self._attempted,
                    "handshake_completed": self._completed,
                    "application_bytes_seen": self._application}

    def close(self):
        self._stop.set()
        self._listener.close()
        with self._lock:
            connection = self._connection
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self._thread.join(timeout=3)
        if self._thread.is_alive():
            raise ScenarioFailure("ldap_native.transport.san_probe_cleanup_failed")


@contextmanager
def wrong_san_probe(root: Path, ca_cert: Path, ca_key: Path, *, csr=None, tls_key=None):
    probe = WrongSanProbe(root, ca_cert, ca_key, csr=csr, tls_key=tls_key)
    try:
        yield probe
    finally:
        probe.close()
