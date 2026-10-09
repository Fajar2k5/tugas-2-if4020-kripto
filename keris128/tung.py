from __future__ import annotations

from .block import decrypt_block, encrypt_block
from .constants import BLOCK_SIZE, KEY_SIZE
from .key_schedule import generate_round_keys


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    ciphertext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        plaintext_block = data[i:i + BLOCK_SIZE]
        ciphertext.extend(encrypt_block(plaintext_block, round_keys))
    return bytes(ciphertext)


def encrypt_cbc(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        plaintext_block = data[i:i + BLOCK_SIZE]
        xored = _xor_bytes(plaintext_block, prev)
        ciphertext_block = encrypt_block(xored, round_keys)
        ciphertext.extend(ciphertext_block)
        prev = ciphertext_block
    return bytes(ciphertext)


def encrypt_cfb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        plaintext_block = data[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, round_keys)
        cipher_block = _xor_bytes(plaintext_block, keystream)
        ciphertext.extend(cipher_block)
        prev = cipher_block
    return bytes(ciphertext)


def encrypt_ofb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        plaintext_block = data[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, round_keys)
        cipher_block = _xor_bytes(plaintext_block, keystream)
        ciphertext.extend(cipher_block)
        prev = keystream
    return bytes(ciphertext)


def encrypt_ctr(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    counter_int = int.from_bytes(iv, byteorder="big")
    modulus = 1 << (BLOCK_SIZE * 8)
    ciphertext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        plaintext_block = data[i:i + BLOCK_SIZE]
        counter_bytes = counter_int.to_bytes(BLOCK_SIZE, byteorder="big")
        keystream = encrypt_block(counter_bytes, round_keys)
        ciphertext.extend(_xor_bytes(plaintext_block, keystream))
        counter_int = (counter_int + 1) % modulus
    return bytes(ciphertext)


def decrypt_ecb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    plaintext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[i:i + BLOCK_SIZE]
        plaintext.extend(decrypt_block(ciphertext_block, round_keys))
    return bytes(plaintext)


def decrypt_cbc(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(ciphertext_block, round_keys)
        plaintext.extend(_xor_bytes(decrypted_block, prev))
        prev = ciphertext_block
    return bytes(plaintext)


def decrypt_cfb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, round_keys)
        plaintext.extend(_xor_bytes(ciphertext_block, keystream))
        prev = ciphertext_block
    return bytes(plaintext)


def decrypt_ofb(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, round_keys)
        plaintext.extend(_xor_bytes(ciphertext_block, keystream))
        prev = keystream
    return bytes(plaintext)


def decrypt_ctr(data: bytes, round_keys: list[bytes], iv: bytes | None = None) -> bytes:
    counter_int = int.from_bytes(iv, byteorder="big")
    modulus = 1 << (BLOCK_SIZE * 8)
    plaintext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[i:i + BLOCK_SIZE]
        counter_bytes = counter_int.to_bytes(BLOCK_SIZE, byteorder="big")
        keystream = encrypt_block(counter_bytes, round_keys)
        plaintext.extend(_xor_bytes(ciphertext_block, keystream))
        counter_int = (counter_int + 1) % modulus
    return bytes(plaintext)


ENCRYPT_MODES = {
    "ECB": encrypt_ecb,
    "CBC": encrypt_cbc,
    "CFB": encrypt_cfb,
    "OFB": encrypt_ofb,
    "CTR": encrypt_ctr,
}

DECRYPT_MODES = {
    "ECB": decrypt_ecb,
    "CBC": decrypt_cbc,
    "CFB": decrypt_cfb,
    "OFB": decrypt_ofb,
    "CTR": decrypt_ctr,
}


def pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Panjang data bukan kelipatan block size.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Padding PKCS#7 tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Byte padding PKCS#7 rusak.")
    return data[:-pad_len]


def encrypt(data: bytes, key: bytes, mode: str, iv: bytes | None = None) -> bytes:
    if mode not in ENCRYPT_MODES:
        raise ValueError(f"Mode '{mode}' tidak didukung.")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Panjang key harus {KEY_SIZE} byte, diberikan {len(key)} byte.")
    if mode != "ECB":
        if iv is None:
            raise ValueError(f"Mode '{mode}' membutuhkan IV.")
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"Panjang IV harus {BLOCK_SIZE} byte, diberikan {len(iv)} byte.")

    round_keys = generate_round_keys(key)
    padded_data = pad(data)
    return ENCRYPT_MODES[mode](padded_data, round_keys, iv)


def decrypt(data: bytes, key: bytes, mode: str, iv: bytes | None = None) -> bytes:
    if mode not in DECRYPT_MODES:
        raise ValueError(f"Mode '{mode}' tidak didukung.")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Panjang key harus {KEY_SIZE} byte, diberikan {len(key)} byte.")
    if mode != "ECB":
        if iv is None:
            raise ValueError(f"Mode '{mode}' membutuhkan IV.")
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"Panjang IV harus {BLOCK_SIZE} byte, diberikan {len(iv)} byte.")

    round_keys = generate_round_keys(key)
    decrypted_data = DECRYPT_MODES[mode](data, round_keys, iv)
    return unpad(decrypted_data)
