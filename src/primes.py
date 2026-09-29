"""
Probabilistic Prime Number Generation and Primality Testing.

This module provides cryptographic-grade prime generation utilities using
secure random numbers and the Miller-Rabin probabilistic primality test.
It is primarily designed to support asymmetric cryptography algorithms
such as RSA by generating large probable primes.

Functions:
    generate_prime_number: Generates a probable prime of a specified bit length.
    is_probable_prime: Tests a candidate integer for primality using Miller-Rabin.
"""

import secrets
from src.exceptions import PrimeGenerationError


def generate_prime_number(bit_length: int, max_attempts: int = 100) -> int:
    """
    Generate a probable prime with the given bit length using the Miller-Rabin test.

    This function continuously generates random numbers of the specified bit length 
    and validates them using Miller-Rabin probabilistic primality testing until a 
    valid prime is found.

    Args:
        bit_length (int): The bit length of the prime number to be generated 
            (must be at least 128 bits for security and proper test execution).
        max_attempts (int, optional): The maximum number of random generation 
            attempts before giving up. Defaults to 100.

    Returns:
        int: An integer representing a probable prime of the specified bit length.

    Raises:
        PrimeGenerationError: If `bit_length` is less than 128, or if no prime 
            is found within the maximum number of attempts (`max_attempts`).
    """

    if bit_length < 128:
        error_message = f"Unable to generate prime number with bit length under 128"
        raise PrimeGenerationError(error_message)

    for _ in range(max_attempts):
        random_odd = _generate_random_odd_number(bit_length)

        if is_probable_prime(random_odd):
            return random_odd

    error_message = f"Unable to generate prime number within {max_attempts} attempts"
    raise PrimeGenerationError(error_message)


def is_probable_prime(candidate: int, rounds: int = 50) -> bool:
    """
    Return True if the candidate is a probable prime using the Miller-Rabin primality test.
    The Miller-Rabin test is a probabilistic algorithm that determines whether
    an integer is composite or a probable prime. By increasing the number of
    rounds, the probability of a composite number passing the test (false positive)
    decreases exponentially.

    Args:
        candidate (int): The integer candidate to test for primality.
        rounds (int, optional): The number of testing rounds to perform. More rounds increase statistical confidence.

    Returns:
        bool: True if the candidate is a probable prime, False if it is composite.

    Raises:
        PrimeGenerationError: If `rounds` is less than 1.
    """

    trivial_result = _resolve_trivial_probable_primes(candidate, rounds)
    if trivial_result is not None:
        return trivial_result

    odd_component, factors_of_two = _get_odd_component(candidate)

    for _ in range(rounds):

        witness = secrets.randbelow(candidate - 3) + 2
        initial_residue = pow(witness, odd_component, candidate)

        if initial_residue in (1, candidate-1):
            continue

        if not _has_non_trivial_sqrt_of_one(candidate, initial_residue, factors_of_two):
            return False

    return True

# ========================== *
# PRIVATE AUXILIAR FUNCTIONS *
# ========================== *


def _resolve_trivial_probable_primes(candidate: int, rounds: int) -> bool | None:
    if rounds < 1:
        error_message = "rounds must be greater than or equal to 1."
        raise PrimeGenerationError(error_message)
    elif candidate < 2:
        return False
    elif candidate == 2:
        return True
    elif candidate % 2 == 0:
        return False


def _get_odd_component(candidate: int) -> tuple[int, int]:
    odd_component = candidate - 1
    factors_of_two = 0

    while odd_component % 2 == 0:
        odd_component //= 2
        factors_of_two += 1

    return (odd_component, factors_of_two)


def _has_non_trivial_sqrt_of_one(candidate: int, initial_residue: int, factors_of_two: int) -> bool:
    for _ in range(factors_of_two - 1):
        initial_residue = pow(initial_residue, 2, candidate)
        if initial_residue == candidate - 1:
            return True
    return False


def _generate_random_odd_number(bit_length: int) -> int:
    lower_bound = 1 << (bit_length - 1)
    candidate_range = 1 << (bit_length - 1)
    return lower_bound + (secrets.randbelow(candidate_range) | 1)
