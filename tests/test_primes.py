import pytest
from unittest.mock import patch
from src.exceptions import PrimeGenerationError
from src.primes import is_probable_prime, generate_prime_number


def test_is_probable_prime_with_invalid_parameters():
    with pytest.raises(PrimeGenerationError):
        is_probable_prime(1, 3)


@pytest.mark.parametrize(
    "number", (
        1000000000,
        1000000010,
        1000000020,
        1000000030,
        1000000080,
        1000000001,
        1000000003,
        1000000005,
        1000000011,
        1000000013
    )
)
def test_is_probable_prime_with_even_and_non_prime_odd_numbers(number: int):
    assert is_probable_prime(number) == False


@pytest.mark.parametrize(
    "number", (
        1000000007,
        1000000009,
        1000000021,
        1000000033,
        1000000087
    )
)
def test_is_probabale_prime_with_known_primes(number: int):
    assert is_probable_prime(number)


def test_generate_prime_number_with_invalid_parameter():
    with pytest.raises(PrimeGenerationError):
        generate_prime_number(127, 100)


def test_generate_prime_number_with_max_attempts_exceeded():
    with patch("src.primes.is_probable_prime", return_value=False):
        with pytest.raises(PrimeGenerationError):
            generate_prime_number(128, 1)


def test_generate_prime_number_correct_bit_length():
    number = generate_prime_number(128, 1000)
    bit_number = 0
    while number % 2 != 0:
        bit_number += 1
    assert 128 != bit_number
