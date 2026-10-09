from __future__ import annotations

from .constants import BLOCK_SIZE
from .iv import generate_iv
from .key_schedule import generate_round_keys
from .tung import compute_cbc_mac, decrypt, encrypt


def combine(iv: bytes | None, ciphertext: bytes, mac: bytes | None = None) -> bytes:
    out = bytearray()
    if iv is not None:
        out.extend(iv)
    out.extend(ciphertext)
    if mac is not None:
        out.extend(mac)
    return bytes(out)


def separate(
    data: bytes, has_iv: bool = True, has_mac: bool = False
) -> tuple[bytes | None, bytes, bytes | None]:
    iv = None
    mac = None
    start = 0
    end = len(data)

    if has_iv:
        if len(data) < BLOCK_SIZE:
            raise ValueError("Data terlalu pendek untuk memuat IV.")
        iv = data[:BLOCK_SIZE]
        start = BLOCK_SIZE

    if has_mac:
        if end - start < BLOCK_SIZE:
            raise ValueError("Data terlalu pendek untuk memuat MAC.")
        mac = data[-BLOCK_SIZE:]
        end -= BLOCK_SIZE

    ciphertext = data[start:end]
    return iv, ciphertext, mac


def write_encrypted(
    filepath: str,
    data: bytes,
    key: bytes,
    mode: str,
    iv: bytes | None = None,
    use_mac: bool = True,
) -> None:
    mode_upper = mode.upper()
    if mode_upper != "ECB" and iv is None:
        iv = generate_iv()

    ciphertext = encrypt(data, key, mode_upper, iv)

    mac = None
    if use_mac:
        round_keys = generate_round_keys(key)
        mac = compute_cbc_mac(ciphertext, round_keys)

    combined = combine(iv if mode_upper != "ECB" else None, ciphertext, mac)

    with open(filepath, "wb") as f:
        f.write(combined)


def read_encrypted(
    filepath: str,
    key: bytes,
    mode: str,
    has_mac: bool = True,
) -> bytes:
    mode_upper = mode.upper()
    with open(filepath, "rb") as f:
        raw = f.read()

    has_iv = mode_upper != "ECB"
    iv, ciphertext, mac = separate(raw, has_iv=has_iv, has_mac=has_mac)

    if has_mac:
        round_keys = generate_round_keys(key)
        expected_mac = compute_cbc_mac(ciphertext, round_keys)
        if mac != expected_mac:
            raise ValueError("Verifikasi integritas gagal: MAC tidak cocok / ciphertext telah dimanipulasi.")

    return decrypt(ciphertext, key, mode_upper, iv)
