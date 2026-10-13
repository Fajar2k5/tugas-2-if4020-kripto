"""Fungsi untuk mengukur perubahan ciphertext saat satu bit input dibalik."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

EncryptFn = Callable[[bytes, bytes], bytes]

__all__ = [
    "flip_bit",
    "hamming_distance",
    "bit_change_percentage",
    "avalanche_key_effect",
    "avalanche_plaintext_effect",
    "avalanche_key_by_mode",
    "avalanche_plaintext_by_mode",
    "make_mode_encryptor",
    "summarize",
] # supaya membantu generator API Docs


def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Balik satu bit pada data dengan indeks MSB-first."""
    buf = bytearray(data)
    total_bits = len(buf) * 8
    if not 0 <= bit_index < total_bits:
        raise IndexError(f"bit_index {bit_index} di luar rentang 0..{total_bits - 1}")
    byte_index = bit_index // 8
    bit_in_byte = 7 - (bit_index % 8)
    buf[byte_index] ^= 1 << bit_in_byte
    return bytes(buf)


def hamming_distance(a: bytes, b: bytes) -> int:
    """Hitung jumlah bit berbeda pada dua data dengan panjang sama."""
    if len(a) != len(b):
        raise ValueError("hamming_distance memerlukan dua data berukuran sama")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def bit_change_percentage(a: bytes, b: bytes) -> float:
    """Hitung persentase bit berbeda antara dua data."""
    distance = hamming_distance(a, b)
    total_bits = len(a) * 8
    if total_bits == 0:
        return 0.0
    return 100.0 * distance / total_bits


def _run(
    encrypt: EncryptFn,
    data: bytes,
    key: bytes,
    changed: str,
    bit_count: int,
    bit_positions: Sequence[int] | None,
) -> dict:
    positions = list(bit_positions) if bit_positions is not None else list(range(bit_count))
    base = encrypt(data, key)
    if len(base) == 0:
        raise ValueError("Ciphertext kosong; tidak bisa mengukur avalanche effect")

    samples: list[dict] = []
    for pos in positions:
        if changed == "key":
            mutated = (data, flip_bit(key, pos))
        else:
            mutated = (flip_bit(data, pos), key)
        ciphertext = encrypt(*mutated)
        if len(ciphertext) != len(base):
            raise ValueError("Panjang ciphertext berubah antar enkripsi")
        dist = hamming_distance(base, ciphertext)
        samples.append(
            {
                "bit": pos,
                "hamming": dist,
                "percentage": 100.0 * dist / (len(base) * 8),
            }
        )

    average = sum(s["percentage"] for s in samples) / len(samples) if samples else 0.0
    distances = [s["hamming"] for s in samples]
    return {
        "changed": changed,
        "count": len(samples),
        "bits_compared": len(base) * 8,
        "average_percentage": average,
        "min_percentage": min((s["percentage"] for s in samples), default=0.0),
        "max_percentage": max((s["percentage"] for s in samples), default=0.0),
        "average_hamming": sum(distances) / len(distances) if distances else 0.0,
        "samples": samples,
    }


def avalanche_key_effect(
    encrypt: EncryptFn,
    data: bytes,
    key: bytes,
    bit_positions: Sequence[int] | None = None,
) -> dict:
    """Ukur perubahan ciphertext saat satu bit master key dibalik."""
    return _run(encrypt, bytes(data), bytes(key), "key", len(key) * 8, bit_positions)


def avalanche_plaintext_effect(
    encrypt: EncryptFn,
    data: bytes,
    key: bytes,
    bit_positions: Sequence[int] | None = None,
) -> dict:
    """Ukur perubahan ciphertext saat satu bit plaintext dibalik."""

    return _run(encrypt, bytes(data), bytes(key), "plaintext", len(data) * 8, bit_positions)


def make_mode_encryptor(
    encrypt_mode_fn: Callable[..., bytes],
    mode: str,
    iv: bytes | None = None,
) -> EncryptFn:

    def _encrypt(data: bytes, key: bytes) -> bytes:
        if iv is None:
            return encrypt_mode_fn(data, key, mode)
        return encrypt_mode_fn(data, key, mode, iv)

    return _encrypt


def summarize(results: dict[str, dict]) -> str:
    """Format ringkasan persentase avalanche untuk tiap mode."""
    lines = ["mode      avg%    min%    max%    sampel"]
    lines.append("-" * 45)
    for mode, res in results.items():
        lines.append(
            f"{mode:<8}  {res['average_percentage']:6.2f}  "
            f"{res['min_percentage']:6.2f}  {res['max_percentage']:6.2f}  {res['count']:>6}"
        )
    return "\n".join(lines)


def avalanche_key_by_mode(
    encrypt_mode_fn: Callable[..., bytes],
    data: bytes,
    key: bytes,
    modes: Iterable[str],
    iv: bytes | None = None,
    bit_positions: Sequence[int] | None = None,
) -> dict[str, dict]:
    """Ukur efek perubahan satu bit key pada beberapa mode."""
    results: dict[str, dict] = {}
    for mode in modes:
        enc = make_mode_encryptor(encrypt_mode_fn, mode, iv)
        results[mode] = avalanche_key_effect(enc, data, key, bit_positions)
    return results


def avalanche_plaintext_by_mode(
    encrypt_mode_fn: Callable[..., bytes],
    data: bytes,
    key: bytes,
    modes: Iterable[str],
    iv: bytes | None = None,
    bit_positions: Sequence[int] | None = None,
) -> dict[str, dict]:
    """Ukur efek perubahan satu bit plaintext pada beberapa mode."""
    results: dict[str, dict] = {}
    for mode in modes:
        enc = make_mode_encryptor(encrypt_mode_fn, mode, iv)
        results[mode] = avalanche_plaintext_effect(enc, data, key, bit_positions)
    return results
