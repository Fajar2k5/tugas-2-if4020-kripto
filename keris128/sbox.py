from __future__ import annotations

from .constants import SBOX_AFFINE_CONST
from .gf import gf_inv

__all__ = [
    "SBOX",
    "INV_SBOX",
    "sbox_sub",
    "inv_sbox_sub",
    "sbox_sub_bytes",
    "inv_sbox_sub_bytes",
] # generator API Docs


def _rotl8(value: int, shift: int) -> int:
    # Rotasi kiri 8-bit
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _affine(value: int) -> int:
    # Transformasi affine bit
    return (
        value
        ^ _rotl8(value, 1)
        ^ _rotl8(value, 2)
        ^ _rotl8(value, 5)
        ^ _rotl8(value, 7)
        ^ SBOX_AFFINE_CONST
    ) & 0xFF


def _build_sbox() -> tuple[int, ...]:
    # Bangun tabel S-box
    table = tuple(_affine(gf_inv(x)) for x in range(256))
    if len(set(table)) != 256:
        raise RuntimeError("Konstruksi S-box gagal: keluaran tidak bijektif.")
    if any(table[x] == x for x in range(256)):
        raise RuntimeError("Konstruksi S-box gagal: masih ada titik tetap.")
    return table


# Tabel substitusi
SBOX: tuple[int, ...] = _build_sbox()

# Tabel substitusi invers, dengan membalik permutasi sbox
_inv = [0] * 256
for _x, _sx in enumerate(SBOX):
    _inv[_sx] = _x
INV_SBOX: tuple[int, ...] = tuple(_inv)
del _inv, _x, _sx


def _check_byte(value: int, name: str = "x") -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} harus bertipe int, dapat {type(value).__name__}")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} harus berada pada rentang 0..255, dapat {value}")
    return value


def sbox_sub(x: int) -> int:
    # Substitusi melalui lookup S-box 
    return SBOX[_check_byte(x)]


def inv_sbox_sub(x: int) -> int:
    # Inverse substitusi melalui lookup S-box invserse
    return INV_SBOX[_check_byte(x)]


def _apply(table: tuple[int, ...], data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data harus bertipe bytes")
    return bytes(table[b] for b in data)


def sbox_sub_bytes(data: bytes) -> bytes:
    return _apply(SBOX, data)


def inv_sbox_sub_bytes(data: bytes) -> bytes:
    return _apply(INV_SBOX, data)
