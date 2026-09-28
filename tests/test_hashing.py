"""Unit tests for the mask generation function (MGF1)."""

import hashlib
import pytest

from src.exceptions import MaskGenerationError
from src.hashing import mask_generation_function


def test_mask_generation_function_raises_error_on_negative_length() -> None:
    """MaskGenerationError must be raised when mask_length is negative."""
    with pytest.raises(MaskGenerationError, match="negative"):
        mask_generation_function(b"valid_seed", -1)


def test_mask_generation_function_raises_error_on_excessive_length() -> None:
    """MaskGenerationError must be raised when mask_length exceeds maximum allowed limit."""
    max_length = (2**32) * 32
    excessive_length = max_length + 1

    with pytest.raises(MaskGenerationError, match="exceeds maximum"):
        mask_generation_function(b"valid_seed", excessive_length)


@pytest.mark.parametrize(
    "requested_length",
    [
        0,
        1,
        16,
        31,
        32,
        33,
        64,
        70,
        128,
    ],
)
def test_mask_generation_function_output_length(requested_length: int) -> None:
    """The output must contain exactly mask_length bytes for various sizes."""
    seed = b"test_seed_for_length"
    result = mask_generation_function(seed, requested_length)

    assert isinstance(result, bytes)
    assert len(result) == requested_length


def test_mask_generation_function_first_bytes_match_counter_zero_digest() -> None:
    """The first 32 bytes must match SHA3-256(seed || 0x00000000)."""
    seed = b"interoperability_seed"
    mask_length = 64
    result = mask_generation_function(seed, mask_length)

    counter_zero = (0).to_bytes(4, byteorder="big")
    expected_first_digest = hashlib.sha3_256(seed + counter_zero).digest()

    assert result[:32] == expected_first_digest


def test_mask_generation_function_different_seeds_produce_different_masks() -> None:
    """Different seeds must produce different masks of the same length."""
    seed_a = b"seed_variant_a"
    seed_b = b"seed_variant_b"
    mask_length = 48

    mask_a = mask_generation_function(seed_a, mask_length)
    mask_b = mask_generation_function(seed_b, mask_length)

    assert mask_a != mask_b


def test_mask_generation_function_is_deterministic() -> None:
    """The same seed and mask_length must always produce the exact same mask."""
    seed = b"deterministic_seed_value"
    mask_length = 50

    run_1 = mask_generation_function(seed, mask_length)
    run_2 = mask_generation_function(seed, mask_length)

    assert run_1 == run_2
