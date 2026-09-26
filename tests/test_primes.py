import pytest
from unittest.mock import patch
from src.exceptions import PrimeGenerationError
from src.primes import is_probable_prime, generate_prime_number


def test_is_probable_prime_with_invalid_parameters():
    with pytest.raises(PrimeGenerationError):
        is_probable_prime(0, -1)


@pytest.mark.parametrize(
    "number, is_prime", [
        (1, False),
        (2, True),
        (1000000000, False),
        (1000000001, False),
        (1000000007, True)
    ]
)
def test_is_probable_prime(number: int, is_prime: bool):
    assert is_probable_prime(number) == is_prime


def test_generate_prime_number_with_invalid_parameter():
    with pytest.raises(PrimeGenerationError):
        generate_prime_number(127, 100)


def test_generate_prime_number_with_max_attempts_exceeded():
    with patch("src.primes.is_probable_prime", return_value=False):
        with pytest.raises(PrimeGenerationError):
            generate_prime_number(128, 1)


def test_generate_prime_number_outputs_correct_bit_length():
    bit_length = 128
    assert generate_prime_number(bit_length, 1000).bit_length() == bit_length
