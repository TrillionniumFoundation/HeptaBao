"""Bounded I/O for the separate launchd start/init step.

No module import starts a process, opens a credential, or touches a manager.
Long server ownership belongs to launchd; this module only waits its actual
short utility children. Raw utility and HTTP observations remain private.
"""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import time

import launch_guard as guard

need = guard.need
Refused = guard.Refused
file_identity = guard.file_identity
directory_identity = guard.directory_identity
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
UID, GID = 501, 20


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def parsed(raw):
    return json.loads(raw, object_pairs_hook=guard.unique_object,
                      parse_constant=lambda _x: (_ for _ in ()).throw(Refused("nonfinite_json")))


class Clock(guard.LaunchClock):
    def __init__(self, entry, custody=None):
        super().__init__(entry + 110)
        self.entry, self.total_end = entry, entry + 120
        self.request_end = None
        self.cleaning = False
        self.custody = custody

    def interrupted(self, signum, frame):
        if self.pending is None:
            self.pending = signum
        if self.depth or self.cleaning:
            return
        active = getattr(self.custody, "_ACTIVE", None)
        if active is not None:
            return active._interrupt(signum, frame)
        raise Refused("manager_signal_or_deadline")

    def check(self):
        if self.cleaning:
            need(time.monotonic() < self.total_end, "original_cleanup_deadline")
            return
        end = min(self.end, self.request_end) if self.request_end is not None else self.end
        need(self.pending is None and time.monotonic() < end, "original_manager_or_request_deadline")

    @contextlib.contextmanager
    def request(self, seconds):
        self.check()
        need(self.request_end is None and 0 < seconds <= 15, "one_bounded_request")
        self.request_end = min(self.end, time.monotonic() + seconds)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.request_end - time.monotonic()))
        try:
            yield
            self.check()
        finally:
            self.request_end = None
            if self.timer_owned:
                signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.end - time.monotonic()))


class PrivateIO(guard.Admission):
    """Reuse the reviewed original-FD registry, adding only create-only writes."""
    def __init__(self, clock):
        super().__init__(clock.end, clock)
        self.open_count = self.close_count = 0
        self.transitions = []

    def open_fd(self, *args, **kwargs):
        with self.clock.critical():
            before = set(self.handles)
            try:
                fd = super().open_fd(*args, **kwargs)
            finally:
                self.open_count += len(set(self.handles) - before)
        self.check()
        return fd

    def release_fd(self, fd):
        original = fd in self.handles
        prior = len(self.cleanup_errors)
        super().release_fd(fd)
        if original and len(self.cleanup_errors) == prior:
            self.close_count += 1

    def hold(self, path, expected=None, private=True):
        path = Path(path)
        pin = directory_identity(path, path.lstat())
        need(expected is None or pin == expected, "original_parent_identity_changed")
        for row in self.directories:
            if row["path"] == path:
                need(row["pin"] == pin == directory_identity(path, os.fstat(row["fd"])),
                     "original_retained_directory_changed")
                return row
        return self.hold_directory(pin, private=private)

    def absent(self, parent, name):
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) and name not in (".", ".."), "fixed_leaf_name")
        self.recheck()
        try:
            os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
        except FileNotFoundError:
            return
        raise Refused("create_only_target_exists")

    def mkdir(self, parent, name):
        self.absent(parent, name)
        with self.clock.critical():
            os.mkdir(name, 0o700, dir_fd=parent["fd"])
            os.fsync(parent["fd"])
        return self.hold(parent["path"] / name)

    def put(self, parent, name, raw, *, mode=0o600, remember=True, closeout_evidence=False):
        need(type(raw) is bytes and len(raw) <= 2 * 1024 * 1024 and mode in (0o600, 0o700), "bounded_private_write")
        if closeout_evidence:
            need(self.clock.cleaning and name in ("manager-init.private.json", "result.public.json"),
                 "closeout_evidence_only")
            need(directory_identity(parent["path"], parent["path"].lstat()) == parent["pin"]
                 == directory_identity(parent["path"], os.fstat(parent["fd"])), "original_evidence_parent")
            try:
                os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("create_only_evidence_exists")
        else:
            self.absent(parent, name)
        fd = self.open_fd(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode, dir_fd=parent["fd"])
        try:
            offset = 0
            while offset < len(raw):
                self.check()
                n = os.write(fd, memoryview(raw)[offset:offset + 65536])
                need(n > 0, "private_short_write")
                offset += n
            os.fsync(fd)
            pin = file_identity(os.fstat(fd))
            need(pin["uid"] == UID and pin["gid"] == GID and pin["mode"] == mode
                 and pin["file_type"] == stat.S_IFREG and pin["nlink"] == 1
                 and pin["bytes"] == len(raw), "private_created_file_identity")
            os.fsync(parent["fd"])
        finally:
            self.release_fd(fd)
        item = {"path": str(parent["path"] / name), "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(), "identity": pin}
        if remember:
            need(self.read_file(item, maximum=2 * 1024 * 1024) == raw, "private_write_readback")
        else:
            need(file_identity(Path(item["path"]).lstat()) == pin, "private_write_path_identity")
        return item

    def current_file(self, path, *, maximum, materialize=True, remember=True):
        """Current observation only; caller must tie it to a successful action."""
        path = guard.canonical_path(str(path))
        first = file_identity(path.lstat())
        need(first["file_type"] == stat.S_IFREG and first["uid"] == UID
             and first["nlink"] == 1 and first["mode"] in (0o600, 0o700)
             and 0 <= first["bytes"] <= maximum, "bounded_current_private_file")
        fd = self.open_fd(path, os.O_RDONLY)
        try:
            need(file_identity(os.fstat(fd)) == first, "current_file_original_fd")
            chunks, n, digest = [], 0, hashlib.sha256()
            while True:
                self.check()
                block = os.read(fd, min(65536, maximum + 1 - n))
                if not block:
                    break
                n += len(block)
                need(n <= maximum, "current_file_read_cap")
                digest.update(block)
                if materialize:
                    chunks.append(block)
            need(n == first["bytes"] and first == file_identity(os.fstat(fd)) == file_identity(path.lstat()),
                 "current_file_stable_read")
            item = {"path": str(path), "bytes": n, "sha256": digest.hexdigest(), "identity": first}
            if remember:
                self.files.append({"path": path, "pin": first, "fd": fd, "byte_hash_checked": True})
                fd = None
            return b"".join(chunks), item
        finally:
            if fd is not None:
                self.release_fd(fd)

    def initialized_directory_transition(self, original, *, actual_init_status, actual_response_validated):
        need(actual_init_status == 200 and actual_response_validated is True, "actual_init_response_required_for_rebinding")
        self.check()
        before = original["pin"]
        old_fd_identity = directory_identity(original["path"], os.fstat(original["fd"]))
        need(old_fd_identity == before and os.fstat(original["fd"]).st_nlink == 0,
             "original_empty_directory_not_retired_by_init")
        after = directory_identity(original["path"], original["path"].lstat())
        need(after["dev"] == before["dev"] and after["inode"] != before["inode"]
             and after["uid"] == UID and after["gid"] == GID and after["mode"] == 0o700,
             "actual_initialized_directory_transition")
        # Keep the original unlinked FD in handles for its one final close.
        # Only its path expectation is retired after the explicit API proof.
        self.directories.remove(original)
        current = self.hold_directory(after)
        self.transitions.append({"operation": "successful_sys_init_atomic_directory_publish",
                                 "before": before, "after": after,
                                 "original_fd_identity_retained": old_fd_identity,
                                 "original_fd_nlink": 0, "original_fd_held_until_closeout": True})
        return current

    def publish_initialized_binding(self, parent, initial_item, updated):
        """One named initial→initialized replacement; never a generic overwrite."""
        need(parsed(self.read_file(initial_item, maximum=131072))["state"] == "initial_empty"
             and updated["state"] == "initialized", "only_initialization_binding_transition")
        draft = self.put(parent, "launch-binding.initialized.pending.private.json", encoded(updated), remember=False)
        old_path, new_path = Path(initial_item["path"]), Path(draft["path"])
        self.recheck()
        need(file_identity(old_path.lstat()) == initial_item["identity"]
             and file_identity(new_path.lstat()) == draft["identity"], "binding_prepublication_identity")
        with self.clock.critical():
            os.replace(new_path.name, old_path.name, src_dir_fd=parent["fd"], dst_dir_fd=parent["fd"])
            os.fsync(parent["fd"])
            # ctime may change during rename; bind the actual post-publication
            # file without accepting another inode or modified bytes.
            after = file_identity(old_path.lstat())
            need(all(after[k] == draft["identity"][k] for k in guard.FILE_KEYS - {"ctime_ns"}),
                 "binding_published_original_inode")
            for row in self.files:
                if row["path"] == old_path:
                    need(row["pin"] == initial_item["identity"]
                         and os.fstat(row["fd"]).st_nlink == 0, "old_binding_original_fd_retired")
            self.files = [row for row in self.files if row["path"] != old_path]
        result = {**draft, "path": str(old_path), "identity": after}
        need(self.read_file(result, maximum=131072) == encoded(updated), "binding_published_readback")
        return result


def parse_label(raw, domain, label):
    need(type(raw) is bytes and 0 < len(raw) <= 131072, "bounded_label_output")
    text = raw.decode("utf-8", "strict")
    need(text.splitlines()[0] == domain + "/" + label + " = {", "exact_label_header")
    fields = {}
    for line in text.splitlines()[1:]:
        match = re.fullmatch(r"\t([a-z][a-z0-9 ]*) = ([^\r\n]*)", line)
        if not match:
            continue
        key, value = match.groups()
        if key not in ("path", "program", "pid", "state", "runs", "last exit code"):
            continue
        need(key not in fields, "duplicate_top_level_manager_field")
        if key in ("pid", "runs", "last exit code"):
            if key == "last exit code" and value == "(never exited)":
                value = None
            elif key == "last exit code" and value == "78: EX_CONFIG":
                value = 78
            else:
                need(re.fullmatch(r"-?[0-9]{1,10}", value), "typed_launchctl_integer")
                value = int(value)
        fields[key] = value
    need(type(fields.get("pid")) is int and fields["pid"] > 0
         and fields.get("state") == "running", "actual_running_manager_pid_required")
    return fields


def exact_absence(returncode, stdout, stderr, domain, label):
    suffixes = {"gui/501": "user gui: 501", "user/501": "uid: 501", "system": "system"}
    if domain not in suffixes or label != "org.heptabao.kv2":
        return False
    expected = ('Bad request.\nCould not find service "' + label + '" in domain for '
                + suffixes[domain] + '\n').encode('ascii')
    return returncode == 113 and stdout == b"" and stderr == expected


def safe_custody(receipt):
    children = []
    for original in receipt["children"]:
        row = {k: original.get(k) for k in ("pid", "exec_admitted", "returncode", "original_wait_completed",
                                           "original_wait_count", "no_live_members_before_reap")}
        row["gaps"] = list(original.get("gaps", []))
        row["birth"] = {k: original.get("birth", {}).get(k) for k in ("pid", "ppid", "pgid", "sid", "uid", "state")}
        for key in ("members_at_leader_exit", "members_before_original_reap"):
            row[key] = [{k: member.get(k) for k in ("pid", "ppid", "pgid", "sid", "uid", "state")}
                        for member in original.get(key, [])]
        children.append(row)
    return {"schema": "heptabao.safe-original-manager-command-custody.v1",
            "original_count": receipt["original_count"], "finished": receipt["finished"],
            "passed_process_custody": receipt["passed_process_custody"], "failed": receipt["failed"],
            "interrupted": receipt["interrupted"], "children": children,
            "long_server_is_launchd_owned_not_an_original_child": True}


class ManagedWire:
    def __init__(self, io, output, owner, ca, leaf_pem, service_root, plist_path):
        self.io, self.output, self.owner = io, output, owner
        self.ca, self.service_root, self.plist_path = Path(ca), Path(service_root), Path(plist_path)
        self.leaf_sha256 = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf_pem.decode("ascii"))).hexdigest()
        self.commands, self.http_rows, self.ordinal = [], [], 0
        self.negative_tls_rows = []
        self.command_cleanup_errors = []
        self.http_connections_created = self.http_connections_closed = 0

    def command(self, operation, argv, expected=None):
        need(argv[0] in ("/bin/launchctl", "/bin/ps"), "bounded_manager_utility_only")
        self.io.check()
        self.ordinal += 1
        base = "command-%02d" % self.ordinal
        pins = [self.io.put(self.output, base + suffix, b"", remember=False) for suffix in (".stdout.private", ".stderr.private")]
        fds = []
        process = None
        primary = None
        cleanup = []
        try:
            for pin in pins:
                fd = self.io.open_fd(pin["path"], os.O_WRONLY)
                fds.append(fd)
                need(file_identity(os.fstat(fd)) == pin["identity"], "utility_output_original_fd")
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fds[0], stderr=fds[1],
                                       cwd=self.service_root, env=ENV, start_new_session=True)
            process.wait(timeout=min(5, max(0.001, self.io.clock.end - time.monotonic())))
        except BaseException as error:
            primary = error
        finally:
            try:
                if process is not None and process.returncode is None:
                    process.kill()
                    process.wait(timeout=min(5, max(0.001, self.io.clock.total_end - time.monotonic())))
            except BaseException:
                cleanup.append("original_utility_child_retirement_failed")
            finally:
                for fd in reversed(fds):
                    with self.io.clock.critical():
                        try:
                            # The child modified these original files after
                            # their create-only empty-file fsync.
                            os.fsync(fd)
                        except BaseException:
                            cleanup.append("original_utility_output_sync_failed")
                        self.io.release_fd(fd)
        self.command_cleanup_errors.extend(cleanup)
        row = {"operation": operation, "argv": argv, "returncode": process.returncode if process is not None else None,
               "stdout_private_ref": pins[0]["path"], "stderr_private_ref": pins[1]["path"],
               "child": dict(process.custody) if process is not None else None,
               "cleanup_failure_codes": cleanup,
               "primary_error_type": type(primary).__name__ if primary is not None else None}
        self.commands.append(row)
        if primary is not None:
            raise primary
        need(not cleanup, "utility_output_or_child_cleanup_failed")
        raw = [self.io.current_file(pin["path"], maximum=131072)[0] for pin in pins]
        need(expected is None or process.returncode == expected, "manager_utility_status")
        self.io.check()
        return process.returncode, raw[0], raw[1]

    def http(self, method, path, body=None, *, mutation=False, readiness=False):
        need(method in ("GET", "POST") and path in ("sys/init", "sys/seal-status"), "initialization_http_scope")
        need(not mutation or method == "POST" and path == "sys/init", "single_init_mutation_scope")
        payload = encoded(body) if body is not None else None
        context = ssl.create_default_context(cafile=str(self.ca))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        connection = http.client.HTTPSConnection("127.0.0.1", 18240, context=context, timeout=15)
        self.http_connections_created += 1
        row = {"method": method, "path": path, "mutation": mutation, "request_attempted": False,
               "response_complete": False, "outcome_unknown": mutation}
        self.http_rows.append(row)
        try:
            with self.io.clock.request(15):
                connection.connect()
                peer = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
                need(peer == self.leaf_sha256, "exact_owned_tls_leaf")
                tls = {"schema": "heptabao.actual-managed-tls-observation.v1", "origin": "https://127.0.0.1:18240",
                       "verify_mode": "CERT_REQUIRED", "check_hostname": True,
                       "peer_leaf_sha256": peer, "protocol": connection.sock.version()}
                need(tls["protocol"] in ("TLSv1.2", "TLSv1.3"), "actual_tls_protocol")
                row["tls"] = tls
                row["request_attempted"] = True
                connection.request(method, "/v1/" + path, body=payload,
                                   headers={"Content-Type": "application/json", "Connection": "close"})
                response = connection.getresponse()
                raw = response.read(65537)
                need(len(raw) <= 65536, "bounded_init_http_response")
                row.update(http_status=response.status, response_complete=True,
                           outcome_unknown=mutation and response.status != 200)
                if not mutation:
                    row["body"] = parsed(raw)
                # The full combined secret response is deliberately never
                # attached to a row or persisted by the wire layer.
                return response.status, raw, row
        except ConnectionRefusedError:
            need(readiness and not mutation and not row["request_attempted"], "owned_endpoint_not_ready")
            return None, b"", row
        finally:
            connection.close()
            self.http_connections_closed += 1

    def negative_tls(self):
        """Two single-shot handshakes, before any nonce or init request."""
        for test in ("system_trust_without_new_ca", "correct_ca_wrong_hostname"):
            context = (ssl.create_default_context() if test == "system_trust_without_new_ca"
                       else ssl.create_default_context(cafile=str(self.ca)))
            context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            hostname = "127.0.0.1" if test == "system_trust_without_new_ca" else "invalid.heptabao.invalid"
            raw_socket = tls_socket = None
            row = {"case": test, "application_bytes_sent": 0, "certificate_verification_rejected": False,
                   "socket_closed": False}
            self.negative_tls_rows.append(row)
            try:
                with self.io.clock.request(15):
                    raw_socket = socket.create_connection(("127.0.0.1", 18240), timeout=15)
                    try:
                        tls_socket = context.wrap_socket(raw_socket, server_hostname=hostname)
                    except ssl.SSLCertVerificationError as error:
                        row.update(certificate_verification_rejected=True,
                                   error_type="SSLCertVerificationError", verify_code=error.verify_code)
                    need(row["certificate_verification_rejected"] is True, "negative_tls_verification_not_rejected")
            finally:
                if tls_socket is not None:
                    tls_socket.close()
                if raw_socket is not None:
                    raw_socket.close()
                row["socket_closed"] = ((tls_socket is None or tls_socket.fileno() == -1)
                                        and (raw_socket is None or raw_socket.fileno() == -1))
            self.io.check()
            need(row["socket_closed"], "negative_tls_socket_not_retired")

    def running(self, *, server_pin, plist_pin, data_pin):
        target = "gui/501/org.heptabao.kv2"
        _, raw, err = self.command("observe_owned_launchd_label", ["/bin/launchctl", "print", target], 0)
        need(not err, "manager_query_stderr")
        first = parse_label(raw, "gui/501", "org.heptabao.kv2")
        need(first.get("path") == str(self.plist_path) and first.get("program") == "/opt/homebrew/bin/python3",
             "registered_exact_original_plist_and_launcher")
        pid = first["pid"]
        _, numeric, err = self.command("observe_owned_manager_numeric_process", [
            "/bin/ps", "-p", str(pid), "-o", "pid=,ppid=,pgid=,uid=,gid=,state=,lstart="], 0)
        need(not err, "numeric_process_stderr")
        lines = numeric.decode("ascii", "strict").splitlines()
        need(len(lines) == 1, "one_actual_manager_process")
        columns = lines[0].split()
        need(len(columns) == 11 and all(x.isdecimal() for x in columns[:5]), "manager_numeric_shape")
        n_pid, ppid, pgid, uid, gid = map(int, columns[:5])
        need(n_pid == pid == pgid and ppid == 1 and uid == 501 and gid == 20
             and columns[5][0] in "RSIT", "actual_owned_launchd_process_topology")
        sid = os.getsid(pid)
        need(sid > 0 and os.getpgid(pid) == pgid, "actual_owned_process_session")
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        count = library.proc_pidpath(pid, buffer, len(buffer))
        need(0 < count < len(buffer) and buffer.value.decode("utf-8", "strict") == server_pin["path"],
             "actual_process_executable_path")
        need(file_identity(Path(server_pin["path"]).lstat()) == server_pin["identity"]
             and file_identity(self.plist_path.lstat()) == plist_pin["identity"], "manager_files_still_original")
        _, second_raw, second_err = self.command("reobserve_same_owned_launchd_label", ["/bin/launchctl", "print", target], 0)
        second = parse_label(second_raw, "gui/501", "org.heptabao.kv2")
        need(not second_err and first == second and os.getpgid(pid) == pgid and os.getsid(pid) == sid,
             "same_live_manager_through_observation")
        return {"domain": "gui/501", "label": "org.heptabao.kv2", "pid": pid, "ppid": ppid,
                "uid": uid, "gid": gid, "pgid": pgid, "session": sid,
                "executable_identity": server_pin, "plist_file_identity": plist_pin,
                "data_directory_identity": data_pin,
                "process_birth_observation": {"kind": "ps_lstart_diagnostic", "value": " ".join(columns[6:]),
                                               "sole_authority": False},
                "registered_fields": first, "controller_waitpid_parent": False}
