from __future__ import annotations

from .constants import BLOCK_SIZE, KEY_SIZE, NUM_ROUNDS
from .gf import gf_mul
from .sbox import SBOX

__all__ = ["validate_key", "generate_round_keys"] # API Docs

# _permute = transpose grid 4x4, hanya bisa untuk BLOCK_SIZE = 16.
assert BLOCK_SIZE == 16, f"_permute butuh BLOCK_SIZE=16, sekarang {BLOCK_SIZE}."

# dipakai untuk key whitening sebelum ronde pertama.
_KERNEL: bytes = b"TUNG-128-KERNEL!"
assert len(_KERNEL) == BLOCK_SIZE, "Panjang kernel harus sama dengan BLOCK_SIZE"


def _check_type(master_key: object) -> bytes:
    if not isinstance(master_key, bytes):
        raise TypeError(f"master_key harus bertipe bytes, dapat {type(master_key).__name__}")
    return master_key


def validate_key(master_key: bytes) -> bytes:
    raw = _check_type(master_key)
    if len(raw) < KEY_SIZE:
        raise ValueError(
            f"Master key minimal {KEY_SIZE} byte ({KEY_SIZE * 8} bit), "
            f"diberikan {len(raw)} byte ({len(raw) * 8} bit)."
        )
    return raw


def _permute(data: bytes) -> bytes:
    # permutasi byte
    n = len(data)
    order = [(i % 4) * 4 + (i // 4) for i in range(n)]
    return bytes(data[i] for i in order)


def _rotl_bytes(data: bytes, shift: int) -> bytes:
    # rotate ke kiri urutan byte
    n = len(data)
    shift %= n
    return data[shift:] + data[:shift]


def _rotl_byte(value: int, shift: int) -> int:
    # rotate kiri satu byte (8 bit)
    shift %= 8
    if shift == 0:
        return value & 0xFF
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _diffuse(state: bytes) -> bytes:
    return bytes(
        a ^ b ^ c ^ d ^ e
        for a, b, c, d, e in zip(
            state,
            _rotl_bytes(state, 11),  # Tung
            _rotl_bytes(state, 13),  # Tung
            _rotl_bytes(state, 14),  # Tung
            _rotl_bytes(state, 15),  # Sahur
        )
    )


def _round_constant(round_index: int) -> bytes:
    # constant generator yang deterministik
    out = bytearray(BLOCK_SIZE)
    x = (0x9E * (round_index + 1)) & 0xFF
    for j in range(BLOCK_SIZE):
        x = gf_mul(x, 0x02) ^ (j + round_index)
        out[j] = SBOX[x & 0xFF]
    return bytes(out)


def _fold_key(raw: bytes) -> bytes:
    # Kunci > 16 byte dipadatkan jadi 16 byte dengan
    # mempertimbangkan urutan byte agar dua kunci yang isinya sama
    # tapi urutannya beda tidak menghasilkan round key yang sama
    if len(raw) == KEY_SIZE:
        return raw
    folded = bytearray(KEY_SIZE)
    for i, byte in enumerate(raw):
        slot = i % KEY_SIZE
        order_marker = (i % 7) + 1  # besarnya putaran
        folded[slot] ^= _rotl_byte(byte, order_marker) ^ ((i // KEY_SIZE) * 0x1D & 0xFF)
    mixed = _diffuse(bytes(SBOX[b] for b in folded))
    return mixed


def generate_round_keys(master_key: bytes) -> list[bytes]:
    # Bangkitkan daftar round key dari master key
    key = _fold_key(validate_key(master_key))

    # key whitening
    state = bytes(a ^ b for a, b in zip(key, _KERNEL))
    master_word = _permute(key)

    round_keys: list[bytes] = []
    for r in range(NUM_ROUNDS):
        sub = bytes(SBOX[b] for b in state)          # 1. confusion
        perm = _permute(sub)                         # 2. transposition
        diff = _diffuse(perm)                        # 3. diffusion
        rc = _round_constant(r)                      # 4. round constant
        mk = _rotl_bytes(master_word, (5 * r) % BLOCK_SIZE)  # 5. master binding
        state = bytes(a ^ b ^ c for a, b, c in zip(diff, rc, mk))
        round_keys.append(state)

    return round_keys
