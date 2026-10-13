from __future__ import annotations

from .constants import BLOCK_SIZE, NUM_ROUNDS
from .sbox import SBOX

__all__ = ["encrypt_block", "decrypt_block"] # API Docs

_HALF: int = BLOCK_SIZE // 2

_SBOX: list[int] = list(SBOX)
assert len(_SBOX) == 256, "S-box harus berisi 256 nilai"


def _build_perm(n: int) -> list[int]:
    # From mid outwards X pattern: m, m+1, m-1, m+2, m-2, ...
    m = (n - 1) // 2
    order = [m]

    for k in range(1, n):
        if m + k < n:
            order.append(m + k)
        if m - k >= 0:
            order.append(m - k)
    source = [0] * n

    for i, src in enumerate(order):
        source[order[(i + 1) % n]] = src

    return source

# _PERM_SRC[j] = indeks asal byte yang menempati posisi j setelah permutasi
_PERM_SRC: list[int] = _build_perm(_HALF)

# Jumlah rotasi bit tiap ronde: 16 bilangan prima pertama
_ROT_PRIMES: list[int] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
assert len(_ROT_PRIMES) == NUM_ROUNDS, "Jumlah rotasi harus sama dengan NUM_ROUNDS"

_HALF_BITS: int = _HALF * 8
_HALF_MASK: int = (1 << _HALF_BITS) - 1

def _check_block(block: object) -> bytes:
    if not isinstance(block, bytes):
        raise TypeError(f"block harus bertipe bytes, dapat {type(block).__name__}")
    
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block harus {BLOCK_SIZE} byte, diberikan {len(block)} byte.")
    
    return block


def _check_round_keys(round_keys: object) -> list[bytes]:
    if not isinstance(round_keys, (list, tuple)):
        raise TypeError(f"round_keys harus bertipe list, dapat {type(round_keys).__name__}")
    
    if len(round_keys) != NUM_ROUNDS:
        raise ValueError(f"round_keys harus berisi {NUM_ROUNDS} kunci, diberikan {len(round_keys)}.")
    
    for i, rk in enumerate(round_keys):
        if not isinstance(rk, bytes):
            raise TypeError(f"round_keys[{i}] harus bertipe bytes, dapat {type(rk).__name__}")
        if len(rk) != BLOCK_SIZE:
            raise ValueError(f"round_keys[{i}] harus {BLOCK_SIZE} byte, diberikan {len(rk)} byte.")
        
    return list(round_keys)


def _rotl_half(data: bytes, shift: int) -> bytes:
    # Rotasi kiri setengah blok sebagai satu bilangan 64 bit
    value = int.from_bytes(data, "big")
    value = ((value << shift) | (value >> (_HALF_BITS - shift))) & _HALF_MASK

    return value.to_bytes(_HALF, "big")


def _mul_half(data: bytes) -> bytes:
    # Perkalian x * (2x + 1) mod 2^64, setengah blok sebagai satu bilangan 64 bit
    value = int.from_bytes(data, "big")
    value = (value * (2 * value + 1)) & _HALF_MASK

    return value.to_bytes(_HALF, "big")


def _round_function(half: bytes, round_key: bytes, round_index: int) -> bytes:
    # Function order
    # 1. XOR round key (8 byte pertama)
    # 2. substitution S-box
    # 3. permutasi
    # 4. perkalian x * (2x + 1) mod 2^64
    # 5. rotasi bit sebesar bilangan prima ronde (ronde 1 = 2, ronde 2 = 3, ...)
    # 6. XOR round key (8 byte terakhir)
    sub = bytes(_SBOX[a ^ k] for a, k in zip(half, round_key))
    perm = bytes(sub[i] for i in _PERM_SRC)
    mixed = _mul_half(perm)
    rotated = _rotl_half(mixed, _ROT_PRIMES[round_index])
    
    return _byte_xor(rotated, round_key[_HALF:])


def _byte_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    # input : block = bytes 16 byte, round_keys = list 16 bytes @ 16 byte
    # output: bytes 16 byte
    # Feistel terbalik: kanan yang dihitung, kiri diteruskan apa adanya ke kanan
    state = _check_block(block)
    left, right = state[:_HALF], state[_HALF:]
    for r, rk in enumerate(_check_round_keys(round_keys)):
        round_res = _round_function(left, rk, r)
        left, right = _byte_xor(right, round_res), left
    return left + right

def decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    # input : block = bytes 16 byte, round_keys = list 16 bytes @ 16 byte
    # output: bytes 16 byte
    state = _check_block(block)
    left, right = state[:_HALF], state[_HALF:]
    keys = _check_round_keys(round_keys)
    for r in reversed(range(NUM_ROUNDS)):
        round_res = _round_function(right, keys[r], r)
        left, right = right, _byte_xor(left, round_res)
    return left + right
