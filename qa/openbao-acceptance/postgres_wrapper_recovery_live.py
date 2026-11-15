#!/usr/bin/env python3
"""Real TLS PostgreSQL + SDK Wrapper Recovery, including a lost COMMIT reply.

Inputs must belong to a fresh, explicitly owned fixture. The PostgreSQL
configuration is read from a pinned private file; credentials and Recovery
shares never enter the report or command line. The proxy forwards opaque TLS
bytes and never performs encryption, authentication, or storage itself.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from postgres_live import Instance, free_loopback_port


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)


class OwnedInstance(Instance):
    """Keep the actual server and its descendants in an owned process group."""

    def __init__(self, binary, root, captures):
        super().__init__(binary, root)
        self.captures = captures
        self.pgid = None

    def call(self, method, path, body=None, *, token=None, namespace="", extra_headers=None):
        # The actual server keeps its original 15s accept-to-response budget.
        # Wait slightly longer at the client to observe its bounded result;
        # the shared smoke client's 10s would discard a valid slow init reply.
        headers = {"Accept": "application/json", "Content-Type": "application/json",
                   "X-Vault-Token": self.token if token is None else token}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        headers.update(extra_headers or {})
        request = urllib.request.Request(self.address + "/v1/" + path,
            data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        try:
            response = self.client.open(request, timeout=17)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise RuntimeError("unbounded_owned_http_response")
            return response.status, json.loads(raw) if raw else {}

    def start(self):
        self.log = open(self.root / "server.log", "ab")
        self.process = subprocess.Popen([str(self.binary), "--config", str(self.root / "server.json")],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
                                        start_new_session=True)
        self.pgid = os.getpgid(self.process.pid)
        self.captures.append(dict(pid=self.process.pid, sid=os.getsid(self.process.pid), pgid=self.pgid,
                                  uid=os.getuid(), config_sha256=digest(self.root / "server.json")))
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("owned_server_exited_during_startup")
            try:
                status, _ = self.call("GET", "sys/health")
                if status in (200, 501, 503):
                    return
            except ssl.SSLCertVerificationError:
                raise RuntimeError("owned_server_tls_verification_failed") from None
            except urllib.error.URLError as error:
                if isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise RuntimeError("owned_server_tls_verification_failed") from None
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError("owned_server_tls_listener_not_ready")

    def stop(self):
        if self.process is None:
            return
        # The group is created by this exact Popen; never search for and kill
        # an unrelated listener or provider by its name or port.
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = self.process.wait(timeout=5)
        self.captures[-1].update(exit=code, terminal_wait=True, scoped_sigkill_requested=True)
        self.log.close()
        self.process = None
        self.pgid = None


class PostgreSQL:
    def __init__(self, config, root, bin_dir):
        self.config, self.root, self.bin = config, root, bin_dir
        target = urlsplit(config["connection_url"])
        address = config["endpoint"]["address"]
        host, port = address.rsplit(":", 1)
        self.target = (host, int(port))
        self.database = target.path.removeprefix("/")
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
        ca = root / "postgres-ca.pem"
        private(ca, config["endpoint"]["ca_pem"])
        passfile = root / "postgres-pgpass.private"
        # Fixture credentials have no pgpass separators. Reject rather than
        # write an ambiguously parsed private authentication file.
        if any(character in config["password"] for character in ":\\\n\r"):
            raise RuntimeError("unsupported_fixture_pgpass_password")
        private(passfile, f"{target.hostname}:{port}:{self.database}:{config['username']}:{config['password']}\n")
        self.environment.update(PGHOST=target.hostname, PGHOSTADDR=host, PGPORT=port,
                                PGUSER=config["username"], PGDATABASE=self.database, PGPASSFILE=str(passfile),
                                PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca), PGREQUIREAUTH="scram-sha-256",
                                PGGSSENCMODE="disable", PGCONNECT_TIMEOUT="3")
        self.args = [str(bin_dir / "psql"), "-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1"]

    def sql(self, statement):
        result = subprocess.run(self.args, env=self.environment, input=statement.encode(), capture_output=True,
                                timeout=10)
        if result.returncode:
            raise RuntimeError("real_postgresql_sql_failed")
        return result.stdout.decode().strip()

    def hold_gate(self, gate):
        process = subprocess.Popen(self.args, env=self.environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        process.stdin.write(f"SELECT pg_advisory_lock(hashtextextended('{gate}',0)); SELECT 'locked';\n".encode())
        process.stdin.flush()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 5
        output = b""
        try:
            while time.monotonic() < deadline:
                if not selector.select(0.1):
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output += chunk
                if b"locked" in output.splitlines():
                    return process
        finally:
            selector.close()
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("real_postgresql_commit_gate_not_ready")

    @staticmethod
    def release_gate(process, gate):
        if process.poll() is None:
            process.stdin.write(f"SELECT pg_advisory_unlock(hashtextextended('{gate}',0));\n".encode())
            process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class ReplyDropProxy:
    """Concurrent opaque TLS forwarding; drop only actual server replies."""

    def __init__(self, target, server_name, *, listen_port=0):
        self.target = target
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port or free_loopback_port()))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.origin = f"postgresql://{server_name}:{self.port}"
        self.stopped, self.drop = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.connections, self.workers = set(), []
        self.accepted_connections = self.dropped_bytes = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def drop_server_replies(self):
        self.drop.set()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.accepted_connections += 1
                self.connections.add(client)
                worker = threading.Thread(target=self._session, args=(client,), daemon=True)
                self.workers.append(worker)
            worker.start()

    def _session(self, client):
        server = None
        try:
            server = socket.create_connection(self.target, timeout=5)
            server.settimeout(None)
            with self.lock:
                self.connections.add(server)
            if self.stopped.is_set():
                return
            to_server = threading.Thread(target=self._copy, args=(client, server, False), daemon=True)
            to_client = threading.Thread(target=self._copy, args=(server, client, True), daemon=True)
            to_server.start()
            to_client.start()
            to_server.join()
            to_client.join()
        except OSError:
            pass
        finally:
            for connection in (client, server):
                if connection is not None:
                    connection.close()
                    with self.lock:
                        self.connections.discard(connection)

    def _copy(self, source, target, from_server):
        try:
            while not self.stopped.is_set():
                raw = source.recv(65536)
                if not raw:
                    break
                if from_server and self.drop.is_set():
                    with self.lock:
                        self.dropped_bytes += len(raw)
                else:
                    target.sendall(raw)
        except OSError:
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=2)
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for worker in workers:
            worker.join(timeout=6)
        if self.thread.is_alive() or any(worker.is_alive() for worker in workers):
            raise RuntimeError("owned_pg_proxy_workers_did_not_stop")


def run(args, report):
    pg_config = json.loads(args.postgres_config.read_bytes())
    wrapper = json.loads(args.wrapper_config.read_bytes())
    captures = report["owned_server_processes"]
    instance = OwnedInstance(args.binary, args.work_dir / "candidate", captures)
    pg = PostgreSQL(pg_config, args.work_dir, args.postgres_bin)
    proxy = ReplyDropProxy(pg.target, pg_config["endpoint"]["server_name"])
    proxy.start()
    contender = None
    gate_process = None
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    trigger_created = False
    scope = "pg-wrapper-recovery-" + args.work_dir.name[-20:]
    if not all(character.isalnum() or character == "-" for character in scope):
        raise RuntimeError("private_fixture_scope_invalid")
    report["postgres_scope"] = scope
    gate = "pg-wrapper-gate-" + hashlib.sha256(scope.encode()).hexdigest()[:16]
    function = "hb_wrapper_gate_" + hashlib.sha256(scope.encode()).hexdigest()[:16]
    trigger = function + "_trigger"

    def check(name, condition):
        report["checks"].append(dict(case=name, passed=condition is True))
        if condition is not True:
            raise RuntimeError(name)

    def check_http(name, status, body, condition):
        if condition is not True:
            # Keep actual failed replies confidential, including an unexpected
            # secret-bearing response. Only its navigation and digest enter the
            # receipt; no response value is printed or placed in secret argv.
            path = args.work_dir / "failed-http-response.private.json"
            private(path, json.dumps(dict(case=name, status=status, body=body), sort_keys=True, indent=2) + "\n")
            report["private_response_diagnostics"].append(dict(path=str(path), sha256=digest(path)))
        check(name, condition)

    def manifest_revision():
        return int(pg.sql("SELECT revision FROM heptabao_durable_v1.manifest_v1 WHERE scope='" + scope + "'"))

    def manifest_shape():
        raw = pg.sql("SELECT revision,snapshot_len,ledger_len,journal_len FROM "
                     "heptabao_durable_v1.manifest_v1 WHERE scope='" + scope + "'")
        values = [int(value) for value in raw.split("|")]
        if len(values) != 4:
            raise RuntimeError("actual_pg_manifest_shape_not_unique")
        return dict(zip(("revision", "snapshot_len", "ledger_len", "journal_len"), values))

    def record_pg_boundary(name, shape):
        path = args.work_dir / (name + ".private.json")
        private(path, json.dumps(shape, sort_keys=True, indent=2) + "\n")
        report["private_pg_boundaries"].append(dict(case=name, path=str(path), sha256=digest(path)))

    def chunks():
        return pg.sql("SELECT artifact,chunk_no,revision,encode(bytes,'hex') FROM heptabao_durable_v1.chunks_v1 "
                      "WHERE scope='" + scope + "' ORDER BY artifact,chunk_no")

    try:
        check("real_postgresql_17_tls_scram", pg.sql("SELECT current_setting('server_version_num')::int >= 170000 "
              "AND current_setting('server_version_num')::int < 180000; "
              "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid();") == "t\nt")
        own = json.loads((instance.root / "server.json").read_text())
        storage = copy.deepcopy(pg_config)
        storage.update(scope=scope, connection_url=proxy.origin + "/" + pg.database)
        storage["endpoint"].update(origin=proxy.origin, address=f"127.0.0.1:{proxy.port}")
        own.update(postgres_durable=storage, openbao_wrapper=wrapper, lifecycle_interval_seconds=0, timeout_seconds=15)
        (instance.root / "server.json").write_text(json.dumps(own))
        (instance.root / "server.json").chmod(0o600)
        check("initialization_target_absent", not (instance.root / "data").exists())
        instance.start()
        parameters = dict(secret_shares=0, secret_threshold=0, recovery_shares=5, recovery_threshold=3,
                          recovery_nonce=os.urandom(32).hex())
        request = args.work_dir / "initialization-request.private.json"
        private(request, json.dumps(parameters, sort_keys=True, indent=2) + "\n")
        report["private_initialization_request"] = dict(path=str(request), sha256=digest(request))
        status, initialized = instance.call("POST", "sys/init", parameters)
        check_http("real_pg_wrapper_initialization_once", status, initialized,
                   status == 200 and bool(initialized.get("root_token")))
        instance.token = initialized["root_token"]
        old_keys = initialized.get("recovery_keys", [])
        check("real_pg_recovery_quorum_delivered", len(old_keys) == 5)
        status, retrieved = instance.call("PUT", "sys/init", parameters)
        check_http("same_pg_nonce_retrieves_exact_committed_candidate", status, retrieved,
                   status == 200 and retrieved == initialized)
        check("real_pg_initialization_ack", instance.call("POST", "sys/init/ack", {})[0] == 204)
        check("wrapper_unsealed_actual_service", instance.call("GET", "sys/health")[0] == 200)
        check("postgres_has_one_atomic_manifest", pg.sql("SELECT count(*) FROM heptabao_durable_v1.manifest_v1 "
              "WHERE scope='" + scope + "'") == "1")
        check("filesystem_contains_no_sealed_artifact_fallback", all(not (instance.root / "data" / leaf).exists()
              for leaf in ("state.hbs", "ledger.hbl", "journal.hbj")))
        status, rotation = instance.call("POST", "sys/rotate/recovery/init",
                                        dict(secret_shares=3, secret_threshold=2, require_verification=True))
        check_http("pg_recovery_ceremony_admitted", status, rotation,
                   status == 200 and bool(rotation.get("nonce")))
        for key in old_keys[:3]:
            status, delivered = instance.call("POST", "sys/rotate/recovery/update",
                                              dict(nonce=rotation["nonce"], key=key))
            check_http("pg_recovery_real_old_share_accepted", status, delivered, status == 200)
        new_keys = delivered.get("keys", [])
        verify_nonce = delivered.get("verification_nonce", "")
        check("pg_recovery_actual_new_quorum", len(new_keys) == 3 and bool(verify_nonce))
        status, partial = instance.call("POST", "sys/rotate/recovery/verify",
                                        dict(nonce=verify_nonce, key=new_keys[0]))
        check_http("pg_recovery_first_new_share_durable", status, partial,
                   status == 200 and partial.get("complete") is not True)
        # A second real TLS process must fail to steal the lifetime writer
        # fence even though it can authenticate to the same real database.
        contender = OwnedInstance(args.binary, args.work_dir / "contender", report["contender_processes"])
        competing = json.loads((contender.root / "server.json").read_text())
        competing.update(data_dir=own["data_dir"], postgres_durable=copy.deepcopy(storage),
                         openbao_wrapper=wrapper, lifecycle_interval_seconds=0, timeout_seconds=15)
        competing["postgres_durable"]["scope"] = scope
        (contender.root / "server.json").write_text(json.dumps(competing))
        (contender.root / "server.json").chmod(0o600)
        before_connections = proxy.accepted_connections
        before_contender_revision = manifest_revision()
        startup_rejected = False
        try:
            contender.start()
        except RuntimeError as error:
            if str(error) != "owned_server_exited_during_startup" or contender.process.poll() != 1:
                raise
            # Wrapper auto-activation intentionally aborts listener startup
            # when the already owned real store cannot be admitted.
            startup_rejected = True
        contender.token = instance.token
        check("same_profile_pg_contender_uses_actual_connection", proxy.accepted_connections > before_connections)
        check("same_profile_pg_lifetime_writer_fence_rejects_contender", startup_rejected or
              contender.call("GET", "sys/health")[0] == 503)
        lock_hash = "hashtextextended('heptabao-durable-backend-v1:" + scope + "',0)"
        check("real_pg_session_still_holds_exact_writer_lock", pg.sql("SELECT count(*) FROM pg_locks "
              "WHERE locktype='advisory' AND granted AND classid=((" + lock_hash +
              " >> 32)&4294967295)::oid AND objid=(" + lock_hash + "&4294967295)::oid") == "1")
        check("contender_cannot_publish_pg_owner", manifest_revision() == before_contender_revision)
        contender.stop()
        contender = None
        seal = instance.root / "data/seal.json"
        original_seal = seal.read_bytes()
        public_before = args.work_dir / "source-public-seal-before-fault.private.json"
        private(public_before, original_seal.decode())
        report["private_source_public_seal"] = dict(path=str(public_before), sha256=digest(public_before))
        baseline = manifest_shape()
        revision = baseline["revision"]
        apply_revision = revision + 2
        original_chunks = chunks()
        record_pg_boundary("before-owner-intent", dict(**baseline,
                           chunks_sha256=hashlib.sha256(original_chunks.encode()).hexdigest(),
                           expected_apply_revision=apply_revision))
        # The real durable owner batch physically appends Intent, Apply, then
        # bookkeeping Commit in three SQL transactions. A sole Intent must
        # preserve old authority; the authenticated Apply is the owner switch.
        # Admit only the actual second append after an observed first Intent,
        # with unchanged checkpoint shapes and a strictly growing journal.
        predicate = ("NEW.scope='" + scope + "' AND NEW.revision=" + str(apply_revision)
                     + " AND OLD.revision=" + str(revision + 1)
                     + " AND NEW.snapshot_len=" + str(baseline["snapshot_len"])
                     + " AND OLD.snapshot_len=" + str(baseline["snapshot_len"])
                     + " AND NEW.ledger_len=" + str(baseline["ledger_len"])
                     + " AND OLD.ledger_len=" + str(baseline["ledger_len"])
                     + " AND OLD.journal_len>" + str(baseline["journal_len"])
                     + " AND NEW.journal_len>OLD.journal_len")
        pg.sql("CREATE FUNCTION " + function + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
               "IF " + predicate + " THEN PERFORM pg_advisory_xact_lock(hashtextextended('" + gate +
               "',0)); END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER " + trigger +
               " AFTER UPDATE ON heptabao_durable_v1.manifest_v1 DEFERRABLE INITIALLY DEFERRED "
               "FOR EACH ROW EXECUTE FUNCTION " + function + "();")
        trigger_created = True
        gate_process = pg.hold_gate(gate)
        future = pool.submit(instance.call, "POST", "sys/rotate/recovery/verify",
                             dict(nonce=verify_nonce, key=new_keys[1]))
        deadline = time.monotonic() + 5
        waiting = False
        while time.monotonic() < deadline:
            waiting = pg.sql("SELECT count(*) FROM pg_stat_activity WHERE usename=current_user "
                             "AND query LIKE 'COMMIT%' AND wait_event_type='Lock'") == "1"
            if waiting or future.done():
                break
            time.sleep(0.02)
        check("final_recovery_apply_reaches_actual_pg_commit_gate", waiting)
        intent = manifest_shape()
        record_pg_boundary("first-intent-committed-apply-waiting", intent)
        check("actual_first_intent_durable_before_second_apply_commit",
              intent["revision"] == revision + 1
              and intent["snapshot_len"] == baseline["snapshot_len"]
              and intent["ledger_len"] == baseline["ledger_len"]
              and intent["journal_len"] > baseline["journal_len"])
        proxy.drop_server_replies()
        pg.release_gate(gate_process, gate)
        gate_process = None
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and proxy.dropped_bytes == 0:
            time.sleep(0.02)
        check("real_pg_commit_reply_actually_discarded", proxy.dropped_bytes > 0)
        proxy_port = proxy.port
        proxy.close()
        proxy = None
        status, unknown = future.result(timeout=10)
        check_http("unknown_pg_commit_fences_response_without_keys", status, unknown, status == 503 and not any(
              name in unknown for name in ("keys", "keys_base64", "root_token", "recovery_keys")))
        applied = manifest_shape()
        record_pg_boundary("actual-apply-committed-reply-unknown", applied)
        check("real_pg_second_apply_transaction_is_durable",
              applied["revision"] == apply_revision and applied["journal_len"] > intent["journal_len"]
              and applied["snapshot_len"] == baseline["snapshot_len"]
              and applied["ledger_len"] == baseline["ledger_len"] and chunks() != original_chunks)
        check("unknown_reply_keeps_old_public_index", seal.read_bytes() == original_seal)
        instance.stop()
        pg.sql("DROP TRIGGER " + trigger + " ON heptabao_durable_v1.manifest_v1; DROP FUNCTION " + function + "();")
        trigger_created = False
        proxy = ReplyDropProxy(pg.target, pg_config["endpoint"]["server_name"], listen_port=proxy_port)
        proxy.start()
        instance.start()
        status, restarted_health = instance.call("GET", "sys/health")
        check_http("same_store_pg_wrapper_restart_is_actually_unsealed", status, restarted_health, status == 200)
        check("same_store_pg_wrapper_restart_repairs_public_index", seal.read_bytes() != original_seal)
        record_pg_boundary("reopened-owner-after-apply-recovery", manifest_shape())
        source_metadata = json.loads(original_seal)
        target_metadata = json.loads(seal.read_bytes())
        source_envelope = json.loads(base64.b64decode(source_metadata["wrapped_barrier_key"], validate=True))
        target_envelope = json.loads(base64.b64decode(target_metadata["wrapped_barrier_key"], validate=True))
        source_recovery, target_recovery = source_envelope["recovery"], target_envelope["recovery"]
        check("repaired_public_recovery_has_actual_new_generation_and_quorum",
              source_recovery["generation"] == 1 and target_recovery["generation"] == 2
              and target_recovery["shares"] == 3 and target_recovery["threshold"] == 2)
        check("repaired_recovery_preserves_exact_provider_material",
              target_metadata["generation"] == source_metadata["generation"]
              and all(target_envelope.get(field) == source_envelope.get(field)
                      for field in ("schema", "seal_generation", "deployment_binding", "blobinfo")))
        report["repaired_public_recovery"] = dict(source_generation=1, target_generation=2,
                                                  shares=3, threshold=2, provider_material_unchanged=True)
        status, fresh_rotation = instance.call("POST", "sys/rotate/recovery/init",
                                              dict(secret_shares=3, secret_threshold=2, require_verification=True))
        check_http("reopened_pg_service_admits_new_recovery_ceremony", status, fresh_rotation,
                   status == 200 and bool(fresh_rotation.get("nonce")))
        # Indexed wire shares contain only an index and field value. The
        # credential can reject the old secret only after a complete current
        # threshold, so a single old fragment is real pending progress.
        check("actual_old_recovery_shares_are_distinct", len(set(old_keys[:2])) == 2)
        old_authority_replies = []
        for index, key in enumerate(old_keys[:2]):
            status, rejected = instance.call("POST", "sys/rotate/recovery/update",
                                            dict(nonce=fresh_rotation["nonce"], key=key))
            old_authority_replies.append(dict(status=status, body=rejected))
            without_keys = not any(name in rejected for name in
                                   ("keys", "keys_base64", "root_token", "recovery_keys"))
            if index == 0:
                check_http("old_fragment_is_only_real_pending_progress", status, rejected,
                           status == 200 and rejected.get("progress") == 1
                           and rejected.get("required") == 2 and without_keys)
            else:
                check_http("reopened_pg_owner_rejects_complete_old_recovery_authority",
                           status, rejected, status == 400 and without_keys)
        old_replies_path = args.work_dir / "actual-old-authority-responses.private.json"
        private(old_replies_path, json.dumps(old_authority_replies, sort_keys=True, indent=2) + "\n")
        report["private_response_diagnostics"].append(dict(path=str(old_replies_path),
                                                            sha256=digest(old_replies_path)))
        status, cleared = instance.call("GET", "sys/rotate/recovery/init")
        check_http("rejected_old_quorum_is_actually_erased", status, cleared,
                   status == 200 and cleared.get("progress") == 0
                   and cleared.get("required") == 2 and cleared.get("nonce") == fresh_rotation["nonce"]
                   and not any(name in cleared for name in
                               ("keys", "keys_base64", "root_token", "recovery_keys")))
        report["old_authority_rejection"] = dict(actual_distinct_shares=2,
                                                  pending_status=old_authority_replies[0]["status"],
                                                  final_status=old_authority_replies[1]["status"],
                                                  no_key_output=True, observed_cleared_progress=0)
        for key in new_keys[:2]:
            status, delivered = instance.call("POST", "sys/rotate/recovery/update",
                                              dict(nonce=fresh_rotation["nonce"], key=key))
            check_http("reopened_pg_owner_accepts_actual_new_authority", status, delivered, status == 200)
        check("new_pg_quorum_controls_recovery_generation", delivered.get("verification_required") is True
              and len(delivered.get("keys", [])) == 3)
    finally:
        if gate_process is not None:
            pg.release_gate(gate_process, gate)
        if contender is not None:
            contender.stop()
        if proxy is not None:
            proxy.close()
        instance.stop()
        pool.shutdown(wait=True, cancel_futures=True)
        if trigger_created:
            pg.sql("DROP TRIGGER IF EXISTS " + trigger + " ON heptabao_durable_v1.manifest_v1; "
                   "DROP FUNCTION IF EXISTS " + function + "();")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary-source-commit", help="Actual build origin when this child changes only QA")
    parser.add_argument("--postgres-config", type=Path, required=True)
    parser.add_argument("--postgres-config-sha256", required=True)
    parser.add_argument("--wrapper-config", type=Path, required=True)
    parser.add_argument("--wrapper-config-sha256", required=True)
    parser.add_argument("--postgres-bin", type=Path, default=Path("/usr/lib/postgresql/17/bin"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if os.environ.get("HEPTABAO_FIXTURE_PORT_RANGE") != "31000-31099":
        parser.error("closed fixture port range 31000-31099 must be explicit")
    for path in (args.binary, args.postgres_config, args.wrapper_config, args.work_dir, args.output):
        if not path.is_absolute():
            parser.error("all paths must be absolute")
    if digest(args.postgres_config) != args.postgres_config_sha256 or digest(args.wrapper_config) != args.wrapper_config_sha256:
        parser.error("fixture input digest mismatch")
    repo = Path(__file__).resolve().parents[2]
    if subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip() != args.source_commit:
        parser.error("source commit mismatch")
    if subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"]):
        parser.error("source checkout must be clean")
    binary_source = args.binary_source_commit or args.source_commit
    # An existing compiled producer may be reused only for a QA-only child.
    # Keep both source identities explicit; this does not qualify a new final
    # production release or borrow another source's whole-replacement verdict.
    if binary_source != args.source_commit and subprocess.check_output([
            "git", "-C", str(repo), "diff", binary_source, "HEAD", "--", ".", ":(exclude)qa"]):
        parser.error("binary producer differs in a non-QA source file")
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema="heptabao.real-pg-wrapper-recovery.v1", source_commit=args.source_commit,
                  binary_sha256=digest(args.binary), binary_producer_source_commit=binary_source,
                  production_equal_binary_producer=True, postgres_config_sha256=args.postgres_config_sha256,
                  wrapper_config_sha256=args.wrapper_config_sha256, checks=[], private_response_diagnostics=[], private_pg_boundaries=[], owned_server_processes=[],
                  contender_processes=[], passed=False, full_OpenBao270_replacement=False,
                  credentials_never_logged=True, server_request_budget_seconds=15, client_observation_timeout_seconds=17)
    try:
        run(args, report)
        report["passed"] = True
    except Exception as error:
        # Only fixed scenario names enter the receipt; actual responses and
        # PostgreSQL diagnostics remain confidential fixture material.
        report["error"] = type(error).__name__
        report["failed_case"] = next((item["case"] for item in report["checks"] if not item["passed"]), None)
        report["error_navigation"] = [dict(file=frame.filename, line=frame.lineno, function=frame.name)
                                      for frame in traceback.extract_tb(error.__traceback__)]
    private(args.output, json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(dict(passed=report["passed"], failed_case=report.get("failed_case"),
                         checks=len(report["checks"]), receipt_sha256=digest(args.output))))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
