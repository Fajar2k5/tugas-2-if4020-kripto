from __future__ import annotations

from .constants import BLOCK_SIZE, NUM_ROUNDS

__all__ = ["encrypt_block", "decrypt_block"] # API Docs


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


def encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    # MOCK, belum cipher asli
    # input : block = bytes 16 byte, round_keys = list 16 bytes @ 16 byte
    # output: bytes 16 byte
    state = _check_block(block)
    for rk in _check_round_keys(round_keys):
        state = bytes((a + b) & 0xFF for a, b in zip(state, rk))
        state = state[1:] + state[:1]
    return state


def decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    # MOCK, belum cipher asli
    # input : block = bytes 16 byte, round_keys = list 16 bytes @ 16 byte
    # output: bytes 16 byte
    state = _check_block(block)
    for rk in reversed(_check_round_keys(round_keys)):
        state = state[-1:] + state[:-1]
        state = bytes((a - b) & 0xFF for a, b in zip(state, rk))
    return state
