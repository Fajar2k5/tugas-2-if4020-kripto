"""API utama TUNG-128 untuk enkripsi, dekripsi, dan berkas berintegritas."""

from __future__ import annotations

import hashlib
import hmac

from .block import decrypt_block, encrypt_block
from .constants import BLOCK_SIZE, KEY_SIZE, NUM_ROUNDS
from .iv import generate_iv
from .key_schedule import generate_round_keys, validate_key
from .sbox import (
    INV_SBOX,
    SBOX,
    inv_sbox_sub,
    inv_sbox_sub_bytes,
    sbox_sub,
    sbox_sub_bytes,
)
from .tung import decrypt, encrypt

MAGIC = b"TUNG-D\x01"
TAG_SIZE = hashlib.sha256().digest_size
MODE_TO_ID = {"ECB": 0, "CBC": 1, "CFB": 2, "OFB": 3, "CTR": 4}
ID_TO_MODE = {value: key for key, value in MODE_TO_ID.items()}


def _authentication_key(key: bytes) -> bytes:
    return hmac.new(validate_key(key), b"TUNG-D file authentication key v1", hashlib.sha256).digest()


def seal(data: bytes, key: bytes, mode: str, iv: bytes | None = None) -> tuple[bytes, bytes | None]:
    """Enkripsi data dan wrap ciphertext dengan informasi mode, IV, serta tag."""
    key = validate_key(key)
    mode = mode.upper()
    if mode not in MODE_TO_ID:
        raise ValueError(f"Mode '{mode}' tidak didukung.")
    if mode == "ECB":
        iv = None
    elif iv is None:
        iv = generate_iv()
    ciphertext = encrypt(data, key, mode, iv)
    header = MAGIC + bytes((MODE_TO_ID[mode], len(iv) if iv is not None else 0)) + (iv or b"")
    body = header + ciphertext
    tag = hmac.new(_authentication_key(key), body, hashlib.sha256).digest()
    return body + tag, iv


def open_sealed(envelope: bytes, key: bytes) -> tuple[bytes, str, bytes | None]:
    """Verifikasi tag envelope lalu kembalikan plaintext, mode, dan IV."""
    key = validate_key(key)
    prefix_size = len(MAGIC) + 2
    if len(envelope) < prefix_size + BLOCK_SIZE + TAG_SIZE or not envelope.startswith(MAGIC):
        raise ValueError("Berkas bukan envelope TUNG-D yang valid atau terlalu pendek.")
    mode_id, iv_size = envelope[len(MAGIC):prefix_size]
    mode = ID_TO_MODE.get(mode_id)
    if mode is None:
        raise ValueError("Mode pada header tidak dikenal.")
    expected_iv_size = 0 if mode == "ECB" else BLOCK_SIZE
    if iv_size != expected_iv_size:
        raise ValueError("Panjang IV/counter pada header tidak valid.")
    header_size = prefix_size + iv_size
    body, tag = envelope[:-TAG_SIZE], envelope[-TAG_SIZE:]
    expected_tag = hmac.new(_authentication_key(key), body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Verifikasi integritas gagal: key salah atau berkas telah dimodifikasi.")
    ciphertext = envelope[header_size:-TAG_SIZE]
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Panjang ciphertext pada envelope tidak valid.")
    iv = envelope[prefix_size:header_size] or None
    return decrypt(ciphertext, key, mode, iv), mode, iv

