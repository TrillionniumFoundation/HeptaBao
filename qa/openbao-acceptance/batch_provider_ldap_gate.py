"""Real slapd Add/readback response gate; does not synthesize provider success."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import ssl
import time

from ldap_native_renewal_ha import GatedLdap, exact, MAX_FRAME, GATE_BUDGET_SECONDS
from openldap_secret_live import BASE, CREATION, DELETION, entry_marker, read_entry


def definite_length(first, encoded):
    if not first & 0x80:
        return first
    count = first & 0x7f
    if not 1 <= count <= 3 or len(encoded) != count:
        raise ValueError("invalid_ldap_length")
    length = int.from_bytes(encoded, "big")
    # outbound::ber_length uses two octets for every 128..65535 value.
    # Its 0x82 0x00 0x80 form is BER, although not minimal DER. Preserve
    # these real request bytes; this relay must not require a different codec.
    if length < 128 or length > MAX_FRAME:
        raise ValueError("invalid_ldap_length_bound")
    return length


def read_frame(stream):
    header = exact(stream, 2)
    if header[0] != 0x30:
        raise ValueError("invalid_ldap_envelope")
    first = header[1]
    encoded = b""
    if first & 0x80:
        count = first & 0x7f
        if not 1 <= count <= 3:
            raise ValueError("invalid_ldap_length")
        encoded = exact(stream, count)
    length = definite_length(first, encoded)
    return header + encoded + exact(stream, length)


def tlv(data, offset=0):
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated_ldap_tlv")
    tag, first = data[offset:offset + 2]
    cursor = offset + 2
    count = first & 0x7f if first & 0x80 else 0
    if (first & 0x80 and not 1 <= count <= 3) or cursor + count > len(data):
        raise ValueError("invalid_ldap_tlv_length")
    length = definite_length(first, data[cursor:cursor + count])
    cursor += count
    end = cursor + length
    if end > len(data):
        raise ValueError("invalid_ldap_tlv_bound")
    return tag, data[cursor:end], end


def fields(frame):
    tag, message, end = tlv(frame)
    if tag != 0x30 or end != len(frame):
        raise ValueError("invalid_message")
    tag, identifier, offset = tlv(message)
    if tag != 2 or not 1 <= len(identifier) <= 4 or identifier[0] & 0x80:
        raise ValueError("invalid_message_id")
    operation, payload, _ = tlv(message, offset)
    # Request assertion controls are forwarded verbatim, never interpreted or
    # removed. Only envelope/id/operation determine the relay response loop.
    return int.from_bytes(identifier, "big"), operation, payload


def success_result(payload):
    tag, code, offset = tlv(payload)
    a, _, offset = tlv(payload, offset)
    b, _, end = tlv(payload, offset)
    return tag == 0x0a and code == b"\0" and a == b == 4 and end == len(payload)


def is_issue_readback(message, operation, payload, *, added, entries):
    return (message == 4 and operation == 0x65 and added is True and entries == 1
            and success_result(payload))



def failure_category(error):
    # Exception messages may contain hostnames, paths or credential material.
    # The report contains only a fixed class, never str(error).
    if isinstance(error, ssl.SSLError):
        return "tls_error"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, EOFError):
        return "eof"
    if isinstance(error, OSError):
        return "socket_error"
    return "protocol_error"

class DynamicGate(GatedLdap):
    def __init__(self, *args):
        self.diagnostics = {}
        super().__init__(*args)

    def arm(self):
        self.observed_dn = None
        self.real_add_seen = False
        self.diagnostics = dict(stage="armed", failure=None, request_id=None, request_op=None,
            response_id=None, response_op=None, search_entries=0, normal_client_close=False)
        super().arm()

    def exchange(self, raw):
        client = upstream = None
        added = gated = False
        try:
            self.diagnostics["stage"] = "accept_tls"
            raw.settimeout(5)
            client = self.server_context.wrap_socket(raw, server_side=True)
            self.diagnostics["stage"] = "connect_provider"
            upstream = self.client_context.wrap_socket(socket.create_connection(
                ("127.0.0.1", self.directory.port), timeout=5), server_hostname="127.0.0.1")
            with self.lock:
                self.active.update((client, upstream))
            for _ in range(12):
                try:
                    self.diagnostics["stage"] = "read_client"
                    request = read_frame(client)
                except EOFError:
                    self.diagnostics["normal_client_close"] = True
                    return  # Normal client close after its verified final result.
                self.diagnostics["stage"] = "parse_client"
                identifier, op, _ = fields(request)
                self.diagnostics.update(request_id=identifier, request_op=op)
                if op == 0x42:
                    upstream.sendall(request)
                    return
                terminal = {0x60: 0x61, 0x63: 0x65, 0x68: 0x69, 0x66: 0x67}.get(op)
                if terminal is None:
                    raise ValueError("unexpected_dynamic_operation")
                self.diagnostics["stage"] = "write_provider"
                upstream.sendall(request)
                entries = 0
                observed_dn = None
                while True:
                    self.diagnostics["stage"] = "read_provider"
                    response = read_frame(upstream)
                    self.diagnostics["stage"] = "parse_provider"
                    message, operation, payload = fields(response)
                    self.diagnostics.update(response_id=message, response_op=operation)
                    if message != identifier or operation not in ((0x64, terminal) if op == 0x63 else (terminal,)):
                        raise ValueError("unexpected_dynamic_response")
                    if operation == 0x64:
                        entries += 1
                        self.diagnostics["search_entries"] = entries
                        tag, dn, _ = tlv(payload)
                        if tag != 4 or len(dn) > 1024:
                            raise ValueError("invalid_readback_dn")
                        observed_dn = dn.decode("utf-8")
                    if identifier == 3 and operation == 0x69:
                        added = success_result(payload)
                    if is_issue_readback(message, operation, payload, added=added, entries=entries):
                        with self.lock:
                            self.requests += 1
                            gated, self.armed = self.armed, False
                        if gated:
                            self.observed_dn, self.real_add_seen = observed_dn, True
                            started = time.monotonic()
                            self.diagnostics["stage"] = "gate_wait"
                            self.received.set()
                            if not self.release.wait(GATE_BUDGET_SECONDS):
                                raise ValueError("provider_gate_timeout")
                            self.gate_elapsed = time.monotonic() - started
                            if self.gate_elapsed >= GATE_BUDGET_SECONDS:
                                raise ValueError("provider_gate_deadline")
                    self.diagnostics["stage"] = "write_client"
                    client.sendall(response)
                    if gated:
                        self.replied.set()
                    if operation == terminal:
                        break
            raise ValueError("too_many_ldap_messages")
        except (EOFError, OSError, ValueError) as error:
            if not self.stopped.is_set():
                self.diagnostics["failure"] = failure_category(error)
                self.failed = True
                self.received.set()
        finally:
            with self.lock:
                self.active.difference_update((client, upstream))
            for stream in (client, upstream, raw):
                if stream is not None:
                    stream.close()
            self.slots.release()


def ldap_completion(instance, provider, trace, key):
    from batch_provider_lease_live import mint, no_secret_failure, restart, wait_read
    cert, private_key, ca = (instance.root / name for name in ("tls.crt", "tls.key", "ca.crt"))
    gate = provider.relay = DynamicGate(provider.directory, cert, private_key, ca)
    provider.additional_endpoints = [dict(origin=provider.origin,
        address=f"127.0.0.1:{provider.port}", server_name=provider.server_name,
        path_prefix="/", ca_pem=ca.read_text())]
    provider.origin, provider.port = gate.origin, gate.port
    restart(instance, provider, key, trace, "completion_worker_paused", lifecycle=60)
    trace.check("gate_mount", instance.call("POST", "sys/mounts/ldap-gate", {"type": "ldap"})[0] == 204)
    trace.check("gate_config", instance.call("POST", "ldap-gate/config", dict(url=gate.origin,
        binddn=provider.directory.admin_dn, bindpass=provider.directory.admin_password,
        userdn=BASE, schema="openldap"))[0] == 204)
    trace.check("gate_role", instance.call("POST", "ldap-gate/role/reader", dict(
        creation_ldif=CREATION, deletion_ldif=DELETION, default_ttl=120, max_ttl=600))[0] == 204)
    policy = ('path "ldap-gate/creds/*" { capabilities=["read"] }\n'
              'path "auth/token/create" { capabilities=["update"] }')
    trace.check("gate_policy", instance.call("POST", "sys/policies/acl/lease-owner", {"policy": policy})[0] == 204)
    parent = mint(instance, trace, "completion_service_parent", 300, batch=False)
    child = mint(instance, trace, "completion_child_batch", 180, parent=parent)
    gate.arm()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(instance.call, "GET", "ldap-gate/creds/reader", token=child)
            ready = gate.received.wait(1.5)
            trace.diagnostics["ldap_completion_gate"] = dict(gate.diagnostics)
            trace.check("completion_real_provider_observed", ready and gate.real_add_seen and not gate.failed
                        and isinstance(gate.observed_dn, str))
            dn = gate.observed_dn
            entry = read_entry(provider.directory, dn)
            marker = entry_marker(entry)
            trace.check("completion_real_add_readback", marker is not None and marker.startswith("hb-request:")
                        and len(entry.get("entryuuid", [])) == 1)
            trace.check("completion_parent_revoked_while_response_held", instance.call(
                "POST", "auth/token/revoke", {"token": parent})[0] == 204)
            gate.release.set()
            status, response = future.result(timeout=6)
    finally:
        gate.release.set()
    trace.check("completion_real_response_delivered", gate.replied.is_set() and not gate.failed
                and gate.gate_elapsed is not None and gate.gate_elapsed < GATE_BUDGET_SECONDS)
    trace.check("completion_no_secret", no_secret_failure(status, response))
    # Worker interval 60s leaves the successful Add visible; the finalizer itself
    # only persists cleanup. No LDAP success or disk plaintext is fabricated.
    trace.check("completion_remote_effect_retained_before_restart", entry_marker(read_entry(provider.directory, dn)) == marker)
    restart(instance, provider, key, trace, "completion_restart")
    expected = marker.replace("hb-request:", "hb-tombstone:", 1)
    trace.check("completion_cleanup_after_restart", wait_read(
        lambda: entry_marker(read_entry(provider.directory, dn)) == expected, 15))
