"""Operasi aritmetika pada GF(2^8) untuk konstruksi S-box."""

from __future__ import annotations
from .constants import SBOX_POLY

_MASK: int = 0xFF

def gf_mul(a: int, b: int, poly: int = SBOX_POLY) -> int:
    """Kalikan dua nilai dalam GF(2^8) dengan polinomial yang diberikan."""
    a &= _MASK
    b &= _MASK
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & _MASK
        if carry:
            a ^= poly & _MASK
        b >>= 1
    return product & _MASK


def gf_pow(a: int, exponent: int, poly: int = SBOX_POLY) -> int:
    """Pangkatkan nilai dalam GF(2^8) dengan eksponen bilangan bulat."""
    result = 1
    base = a & _MASK
    while exponent > 0:
        if exponent & 1:
            result = gf_mul(result, base, poly)
        base = gf_mul(base, base, poly)
        exponent >>= 1
    return result


def gf_inv(a: int, poly: int = SBOX_POLY) -> int:
    """Cari invers perkalian nilai dalam GF(2^8)."""
    a &= _MASK
    if a == 0:
        return 0
    return gf_pow(a, 254, poly)


__all__ = ["gf_mul", "gf_pow", "gf_inv"] # supaya membantu generator API Docs
