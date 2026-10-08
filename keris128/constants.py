# Parameter global cipher

from __future__ import annotations

BLOCK_SIZE: int = 16          # ukuran blok dalam byte (128 bit)
KEY_SIZE: int = 16            # ukuran minimum master key dalam byte (128 bit)
NUM_ROUNDS: int = 16

ALGORITHM_NAME: str = "TUNG-128"
ALGORITHM_FULLNAME: str = "Tung Block Cahur"

# Polinomial tak-tereduksi GF(2^8): x^8 + x^6 + x^5 + x^2 + 1
SBOX_POLY: int = 0x165

SBOX_AFFINE_CONST: int = 0x1F


__all__ = [
    "BLOCK_SIZE",
    "KEY_SIZE",
    "NUM_ROUNDS",
    "ALGORITHM_NAME",
    "ALGORITHM_FULLNAME",
    "SBOX_POLY",
    "SBOX_AFFINE_CONST",
] # supaya membantu generator API Docs
