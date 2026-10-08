# Aritmetika medan berhingga GF(2^8)

from __future__ import annotations
from .constants import SBOX_POLY

_MASK: int = 0xFF

def gf_mul(a: int, b: int, poly: int = SBOX_POLY) -> int:
    # Perkalian di GF(2^8)
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
    # Eksponensial
    result = 1
    base = a & _MASK
    while exponent > 0:
        if exponent & 1:
            result = gf_mul(result, base, poly)
        base = gf_mul(base, base, poly)
        exponent >>= 1
    return result


def gf_inv(a: int, poly: int = SBOX_POLY) -> int:
    # Invers
    a &= _MASK
    if a == 0:
        return 0
    return gf_pow(a, 254, poly)


__all__ = ["gf_mul", "gf_pow", "gf_inv"] # supaya membantu generator API Docs
