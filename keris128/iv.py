from __future__ import annotations

import os

from .constants import BLOCK_SIZE


def generate_iv(size: int = BLOCK_SIZE) -> bytes:
    return os.urandom(size)
