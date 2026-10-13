from __future__ import annotations

import math
from collections import Counter

from ..tung import encrypt

__all__ = [
    "byte_entropy",
    "byte_histogram",
    "avalanche_bits",
    "analyze_modes",
    "avalanche_modes",
]


def byte_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (range 0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def byte_histogram(data: bytes) -> list[int]:
    """Return counts for byte values 0 through 255."""
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def avalanche_bits(left: bytes, right: bytes) -> tuple[int, int, float]:
    """Return changed bits, compared bits, and changed-bit percentage."""
    if len(left) != len(right):
        raise ValueError("Data harus memiliki panjang yang sama untuk uji avalanche.")
    changed = sum((a ^ b).bit_count() for a, b in zip(left, right))
    total = len(left) * 8
    return changed, total, (100.0 * changed / total if total else 0.0)


def analyze_modes(data: bytes, key: bytes, iv: bytes) -> dict[str, dict[str, float]]:
    """Measure ciphertext entropy and plaintext/ciphertext entropy per mode."""
    results = {}
    for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
        ciphertext = encrypt(data, key, mode, None if mode == "ECB" else iv)
        results[mode] = {
            "plaintext_bits_per_byte": byte_entropy(data),
            "ciphertext_bits_per_byte": byte_entropy(ciphertext),
            "plaintext_bytes": float(len(data)),
            "ciphertext_bytes": float(len(ciphertext)),
        }
    return results


def avalanche_modes(data: bytes, key: bytes, iv: bytes) -> dict[str, dict[str, float]]:
    """Measure output change for one plaintext-bit and one key-bit flip per mode."""
    sample = data if data else b"\x00"
    changed_plaintext = bytearray(sample)
    changed_plaintext[0] ^= 1
    changed_key = bytearray(key)
    if not changed_key:
        raise ValueError("Key tidak boleh kosong.")
    changed_key[0] ^= 1

    results = {}
    for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
        mode_iv = None if mode == "ECB" else iv
        baseline = encrypt(sample, key, mode, mode_iv)
        plain_result = encrypt(bytes(changed_plaintext), key, mode, mode_iv)
        key_result = encrypt(sample, bytes(changed_key), mode, mode_iv)
        plain_changed, _, plain_percent = avalanche_bits(baseline, plain_result)
        key_changed, _, key_percent = avalanche_bits(baseline, key_result)
        results[mode] = {
            "plaintext_changed_bits": float(plain_changed),
            "plaintext_percent": plain_percent,
            "key_changed_bits": float(key_changed),
            "key_percent": key_percent,
        }
    return results
