"""Explicit OpenBao 2.7 prerequisites. No credentials, implicit cache, or retries.

The index envelope is untrusted replication metadata, never authentication or a
proof of read authority. Preserve bytes and ordered repeated policy headers.
"""
from __future__ import annotations
import base64
import binascii
from dataclasses import dataclass
from functools import partial
import http.client
import json
import urllib.request

MAX_INDEX = 12 * 1024
BEHAVIORS = ((), ('fail',), ('forward-active-node',), ('await-state',),
             ('await-state', 'fail'), ('await-state', 'forward-active-node'))

class InvalidConsistency(ValueError):
    """Fixed diagnostic code only; never include an index or decoder exception."""

class _ObjectPairs(list):
    pass

def _invalid_constant(_):
    raise ValueError('invalid_constant')

def validate_index(index):
    if index is None or index == '':
        return
    if not isinstance(index, str) or len(index) > MAX_INDEX or not index.isascii():
        raise InvalidConsistency('invalid_consistency_index')
    try:
        raw = base64.b64decode(index, validate=True)
        value = json.loads(raw, object_pairs_hook=_ObjectPairs, parse_constant=_invalid_constant)
        if value is not None and not isinstance(value, _ObjectPairs):
            raise ValueError('index_object_required')
        for key, field in value or ():
            if key.lower() in ('cluster', 'value') and field is not None and not isinstance(field, str):
                raise ValueError('index_field_type')
    except (ValueError, TypeError, UnicodeError, RecursionError, binascii.Error):
        raise InvalidConsistency('invalid_consistency_index') from None

@dataclass(frozen=True, repr=False)
class Metadata:
    index: str | None = None
    behavior: tuple[str, ...] = ()

    def __post_init__(self):
        validate_index(self.index)
        behavior = self.behavior
        if behavior is None:
            behavior = ()
        elif isinstance(behavior, str):
            behavior = (behavior,)
        elif isinstance(behavior, (tuple, list)):
            behavior = tuple(behavior)
        else:
            raise InvalidConsistency('invalid_consistency_behavior')
        if behavior not in BEHAVIORS:
            raise InvalidConsistency('invalid_consistency_behavior')
        object.__setattr__(self, 'behavior', behavior)

    def headers(self):
        result = () if self.index is None else (('X-Vault-Index', self.index),)
        return result + tuple(('X-Vault-Inconsistent', value) for value in self.behavior)

def response_index(headers):
    """Bad optional metadata cannot turn an acknowledged mutation into a retry.

    Return no usable index and a false validity flag, leaving status/body intact.
    Callers requiring a prerequisite must fail the dependent request, not replay
    the original operation. Absence is valid but conveys no prerequisite.
    """
    if headers is None:
        return None, True
    values = headers.get_all('X-Vault-Index', [])
    if not values:
        return None, True
    if len(values) != 1:
        return None, False
    try:
        validate_index(values[0])
    except InvalidConsistency:
        return None, False
    return values[0], True

def retry_after(headers):
    if headers is None:
        return None
    values = headers.get_all('Retry-After', [])
    if len(values) != 1:
        return None
    value = values[0]
    if not isinstance(value, str) or not 1 <= len(value) <= 5 or not value.isascii() or not value.isdigit():
        return None
    seconds = int(value)
    return seconds if seconds <= 86400 else None

class _Connection(http.client.HTTPSConnection):
    def __init__(self, *args, consistency, **kwargs):
        super().__init__(*args, **kwargs)
        self._consistency = consistency

    def endheaders(self, message_body=None, *, encode_chunked=False):
        # One call per value is essential: comma joining and obs-fold change the
        # OpenBao policy. Nothing is appended to credentials or arbitrary names.
        for name, value in self._consistency.headers():
            self.putheader(name, value)
        return super().endheaders(message_body, encode_chunked=encode_chunked)

class HTTPSHandler(urllib.request.HTTPSHandler):
    def do_open(self, http_class, req, **http_conn_args):
        metadata = getattr(req, 'heptabao_consistency', None)
        if metadata is not None:
            if not isinstance(metadata, Metadata):
                raise InvalidConsistency('invalid_consistency_metadata')
            # Keep urllib's checked TLS context and request lifecycle unchanged.
            # The context is not shared with mutable request metadata.
            http_class = partial(_Connection, consistency=metadata)
        return super().do_open(http_class, req, **http_conn_args)
