"""Strict verification-only Ed25519 primitive for HeptaBao V2.5 evidence.

This module implements the RFC 8032 verification equation with canonical point
and scalar checks.  It does not provide signing, key generation, key custody or
an admission CLI.
"""
from __future__ import annotations

import hashlib

FIELD = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, FIELD - 2, FIELD)) % FIELD
SQRT_M1 = pow(2, (FIELD - 1) // 4, FIELD)
IDENTITY = (0, 1, 1, 0)

Point = tuple[int, int, int, int]


class Ed25519Error(ValueError):
    """The key, point or signature is not a strict Ed25519 value."""


def inverse(value: int) -> int:
    return pow(value, FIELD - 2, FIELD)


def recover_x(y: int, sign: int) -> int:
    xx = ((y * y - 1) * inverse(D * y * y + 1)) % FIELD
    x = pow(xx, (FIELD + 3) // 8, FIELD)
    if (x * x - xx) % FIELD:
        x = (x * SQRT_M1) % FIELD
    if (x * x - xx) % FIELD:
        raise Ed25519Error("Ed25519 point is not on the curve")
    if (x & 1) != sign:
        x = FIELD - x
    if x == 0 and sign:
        raise Ed25519Error("Ed25519 point encoding is non-canonical")
    return x


def _base_point() -> Point:
    y = (4 * inverse(5)) % FIELD
    x = recover_x(y, 0)
    return x, y, 1, (x * y) % FIELD


BASE = _base_point()


def point_add(left: Point, right: Point) -> Point:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % FIELD
    b = ((y1 + x1) * (y2 + x2)) % FIELD
    c = (2 * D * t1 * t2) % FIELD
    d = (2 * z1 * z2) % FIELD
    e = (b - a) % FIELD
    f = (d - c) % FIELD
    g = (d + c) % FIELD
    h = (b + a) % FIELD
    return (
        (e * f) % FIELD,
        (g * h) % FIELD,
        (f * g) % FIELD,
        (e * h) % FIELD,
    )


def scalar_mult(point: Point, scalar: int) -> Point:
    if scalar < 0:
        raise Ed25519Error("negative Ed25519 scalar")
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def point_equal(left: Point, right: Point) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % FIELD == 0
        and (left[1] * right[2] - right[1] * left[2]) % FIELD == 0
    )


def decode_point(encoded: bytes) -> Point:
    if len(encoded) != 32:
        raise Ed25519Error("Ed25519 public key/point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= FIELD:
        raise Ed25519Error("Ed25519 point encoding is non-canonical")
    x = recover_x(y, sign)
    point = (x, y, 1, (x * y) % FIELD)
    if point_equal(point, IDENTITY) or not point_equal(
        scalar_mult(point, ORDER), IDENTITY
    ):
        raise Ed25519Error("Ed25519 point is not in the prime-order subgroup")
    return point


def encode_point(point: Point) -> bytes:
    inverse_z = inverse(point[2])
    x = (point[0] * inverse_z) % FIELD
    y = (point[1] * inverse_z) % FIELD
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise Ed25519Error("Ed25519 key or signature length is invalid")
    public_point = decode_point(public_key)
    encoded_r = signature[:32]
    r_point = decode_point(encoded_r)
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= ORDER:
        raise Ed25519Error("Ed25519 signature scalar is non-canonical")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ORDER
    left = scalar_mult(BASE, scalar_s)
    right = point_add(r_point, scalar_mult(public_point, challenge))
    if not point_equal(left, right):
        raise Ed25519Error("Ed25519 signature verification failed")
