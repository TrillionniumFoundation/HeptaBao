"""Pure, private-only decoder for one retained 3-share init response.

No HTTP, disk, key generation, transfer, acknowledgement or retry occurs here.
The caller must first durably save its nonce in separate private custody and
must bind the actual init request, TLS peer and manager instance. Decoding is
not evidence of a real Shamir threshold or successful off-host custody.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

MAX_INIT_RESPONSE_BYTES = 65536


class RejectedInitDelivery(ValueError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise RejectedInitDelivery(code)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        need(key not in result, "duplicate_init_response_field")
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class PrivateInitDelivery:
    root_token: bytes
    shares_base64: tuple[bytes, bytes, bytes]
    # Do not serialize this object into any public report or combined disk file.


def decode_exact_three_share_response(raw: bytes) -> PrivateInitDelivery:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_INIT_RESPONSE_BYTES, "bounded_init_response_required")
    try:
        obj = json.loads(raw, object_pairs_hook=unique_object)
    except RejectedInitDelivery:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise RejectedInitDelivery("init_response_json_rejected") from None
    need(type(obj) is dict and set(obj) == {
        "keys", "keys_base64", "root_token", "recovery_keys", "recovery_keys_base64", "init_ack_required",
    }, "exact_init_response_fields_required")
    need(obj["init_ack_required"] is True, "recoverable_initialization_required")
    need(obj["recovery_keys"] == [] and obj["recovery_keys_base64"] == [], "shamir_not_external_recovery_profile")
    token = obj["root_token"]
    need(type(token) is str and 1 <= len(token) <= 4096, "bounded_root_token_required")
    need(all(33 <= ord(c) <= 126 for c in token), "root_token_opaque_ascii_required")
    encoded = obj["keys_base64"]
    hex_encoded = obj["keys"]
    need(type(encoded) is list and len(encoded) == 3, "exact_three_base64_shares_required")
    need(type(hex_encoded) is list and len(hex_encoded) == 3, "exact_three_hex_shares_required")
    decoded: list[bytes] = []
    preserved: list[bytes] = []
    for b64, hexadecimal in zip(encoded, hex_encoded):
        need(type(b64) is str and 1 <= len(b64) <= 4096, "bounded_share_required")
        need(type(hexadecimal) is str and 1 <= len(hexadecimal) <= 8192, "bounded_hex_share_required")
        try:
            wire = b64.encode("ascii")
            share = base64.b64decode(wire, validate=True)
        except (ValueError, UnicodeError, binascii.Error):
            raise RejectedInitDelivery("share_base64_rejected") from None
        need(0 < len(share) <= 3072 and base64.b64encode(share) == wire, "share_base64_not_canonical")
        need(share.hex() == hexadecimal, "duplicate_encoding_mismatch")
        need(share not in decoded, "duplicate_shamir_share")
        decoded.append(share)
        preserved.append(wire)
    # The decoder preserves the exact returned secret text. It makes no claim
    # that immutable Python objects or the JSON parser's copies are zeroized.
    return PrivateInitDelivery(token.encode("ascii"), tuple(preserved))
