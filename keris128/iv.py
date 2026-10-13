"""Pembuatan IV acak untuk mode cipher."""

from __future__ import annotations

import os

from .constants import BLOCK_SIZE


def generate_iv(size: int = BLOCK_SIZE) -> bytes:
    """Buat IV acak dengan panjang yang diminta."""
    return os.urandom(size)
