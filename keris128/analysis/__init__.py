from __future__ import annotations

from .statistics import (
    analyze_modes,
    avalanche_bits,
    avalanche_modes,
    byte_entropy,
    byte_histogram,
)
from .avalanche import (
    avalanche_key_by_mode,
    avalanche_key_effect,
    avalanche_plaintext_effect,
    avalanche_plaintext_by_mode,
    bit_change_percentage,
    flip_bit,
    hamming_distance,
    make_mode_encryptor,
    summarize,
)
