"""Closed fixture labels for the derived transit HTTP requests.

Only source-defined labels cross the diagnostic boundary. Routes, bodies,
credentials and arbitrary caller labels never become pending-request metadata.
"""
from dataclasses import dataclass

_KINDS = ("aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305")
_MODES = ("ordinary", "derived", "convergent")


def _labels():
    names = {"mount"}
    fixed = ("create", "read", "export_master", "nonce_baseline", "wrong_context",
             "hmac_baseline", "batch_encrypt", "batch_decrypt", "batch_missing_context",
             "batch_partial", "rotate", "v2_encrypt", "rewrap_v1", "rewrapped_decrypt",
             "restart_read", "minimum_versions", "retired_decrypt", "retired_encrypt",
             "retired_rewrap", "retired_export", "current_export", "minimum_read",
             "current_decrypt", "restart_decrypt.old", "restart_decrypt.current")
    for kind in _KINDS:
        for mode in _MODES:
            prefix = kind + "." + mode + "."
            names.update(prefix + value for value in fixed)
            for n in range(3):
                for a in range(2):
                    names.update(prefix + f"message.{n}.aad.{a}." + tail
                                 for tail in ("encrypt", "repeat", "decrypt", "wrong_aad"))
            for family, count, tails in (
                    ("typed_context", 16, ("encrypt", "decrypt")),
                    ("typed_aad", 9, ("encrypt", "decrypt")),
                    ("nonce_ignored", 8, ("",)),
                    ("request_mode", 8, ("",)),
                    ("hmac_context", 8, ("",)),
                    ("hmac_verify_context", 8, ("",)),
                    ("typed_key_version", 9, ("",))):
                for index in range(count):
                    names.update(prefix + family + "." + str(index) + ("." + tail if tail else "")
                                 for tail in tails)
            for form in ("plaintext", "wrapped"):
                for bits in (128, 256, 512):
                    names.update(prefix + f"datakey.{form}.{bits}." + tail
                                 for tail in ("generate", "decrypt"))
    for index in range(5):
        names.update(f"upsert{index}." + tail for tail in ("encrypt", "read"))
    for index in range(10):
        names.update(f"weakflag{index}." + tail for tail in ("create", "read"))
    return frozenset("derived270." + name for name in names)


_ALLOWED = _labels()


@dataclass(frozen=True, repr=False)
class _PendingCase:
    label: str


def begin_case(client, name):
    label = "derived270." + name if type(name) is str else None
    client._heptabao_derived_pending_case = _PendingCase(label) if label in _ALLOWED else None


def complete_case(client):
    client._heptabao_derived_pending_case = None


def pending_case(client):
    if client is None:
        return None
    pending = vars(client).get("_heptabao_derived_pending_case")
    if type(pending) is _PendingCase and type(pending.label) is str and pending.label in _ALLOWED:
        return pending.label
    return None
